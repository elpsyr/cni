package net

import (
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/coreos/go-iptables/iptables"
	"github.com/elpsyr/cni/pkg/utils"
	"github.com/elpsyr/ipam"
	"github.com/vishvananda/netlink"
	"net"
	"os"
)

// CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster
// 1. 在主机ns下创建网桥
// 2. pod ns 下创建 VethPair ，一端添加到主机ns，一端留在内部给上pod ip
// 3. pod ns 下创建路由规则，让所有流量走Veth
// 4. 在 host ns 下将veth 接入网桥
func CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster(
	brName, gw, ifName, podIP string, mtu int, netns ns.NetNS,
) error {
	// 先创建网桥
	br, err := CreateBridge(brName, gw, mtu)
	if err != nil {
		utils.WriteLog("创建网桥失败, err: ", err.Error())
		return err
	}

	// netns.Do() 函数的作用是在新的 network namespace 环境中执行给定的函数，执行完毕后自动切回原来的ns
	// 在这里：hostNs 是一个表示主机的 namespace 的对象，而 netns 则是一个表示容器的 namespace 的对象。
	err = netns.Do(func(hostNs ns.NetNS) error {
		// 创建一对儿 veth 设备
		containerVeth, hostVeth, err := CreateVethPair(ifName, mtu)
		if err != nil {
			utils.WriteLog("创建 veth 失败, err: ", err.Error())
			return err
		}

		// 把随机起名的 veth 那头放在主机上
		err = SetVethNsFd(hostVeth, hostNs)
		if err != nil {
			utils.WriteLog("把 veth 设置到 ns 下失败: ", err.Error())
			return err
		}

		// 然后把要被放到 pod 中的那头 veth 塞上 podIP
		err = SetIpForVeth(containerVeth.Name, podIP)
		if err != nil {
			utils.WriteLog("给 veth 设置 ip 失败, err: ", err.Error())
			return err
		}

		// 然后启动它
		err = SetUpVeth(containerVeth)
		if err != nil {
			utils.WriteLog("启动 veth pair 失败, err: ", err.Error())
			return err
		}

		// 启动之后给这个 netns 设置默认路由 以便让其他网段的包也能从 veth 走到网桥
		gwNetIP, _, err := net.ParseCIDR(gw)
		if err != nil {
			utils.WriteLog("转换 gwip 失败, err:", err.Error())
			return err
		}

		// 给 pod(net ns) 中加一个默认路由规则, 该规则让匹配了 0.0.0.0 的都走上边创建的那个 container veth
		err = SetDefaultRouteToVeth(gwNetIP, containerVeth)
		if err != nil {
			utils.WriteLog("SetDefaultRouteToVeth 时出错, err: ", err.Error())
			return err
		}

		hostNs.Do(func(_ ns.NetNS) error {
			// 重新获取一次 host 上的 veth, 因为 hostVeth 发生了改变
			_hostVeth, err := netlink.LinkByName(hostVeth.Attrs().Name)
			hostVeth = _hostVeth.(*netlink.Veth)
			if err != nil {
				utils.WriteLog("重新获取 hostVeth 失败, err: ", err.Error())
				return err
			}
			// 启动它
			err = SetUpVeth(hostVeth)
			if err != nil {
				utils.WriteLog("启动 veth pair 失败, err: ", err.Error())
				return err
			}

			// 把它塞到网桥上
			err = SetVethMaster(hostVeth, br)
			if err != nil {
				utils.WriteLog("挂载 veth 到网桥失败, err: ", err.Error())
				return err
			}

			// 都完事儿之后理论上同一台主机下的俩 netns(pod) 就能通信了
			// 如果无法通信, 有可能是 iptables 被设置了 forward drop
			// 需要用 iptables 允许网桥做转发
			err = SetIptablesForToForwardAccept(br)
			if err != nil {
				return err
			}

			return nil
		})

		return nil
	})

	if err != nil {
		return err
	}
	return nil
}

func SetOtherHostRouteToCurrentHost(networks []*ipam.Network, currentNetwork *ipam.Network) error {

	link, err := netlink.LinkByName(currentNetwork.Name)

	list, _ := netlink.RouteList(link, netlink.FAMILY_V4)

	if err != nil {
		return err
	}

	for _, network := range networks {
		if !network.IsCurrentHost {
			// 对于其他主机, 需要获取到其他主机的对外网卡 ip, 以及它的 pods 们所占用的网段的 cidr
			// 然后用这个 cidr 和这个 ip 做一个路由表的映射
			if link == nil {
				return err
			}

			_, cidr, err := net.ParseCIDR(network.CIDR)
			if err != nil {
				return err
			}

			// 检查当前网络是否已经存在于当前主机的路由表中，以免重复添加
			isSkip := false
			for _, l := range list {
				if l.Dst != nil && l.Dst.String() == network.CIDR {
					isSkip = true
					break
				}
			}

			if isSkip {
				// fmt.Println(network.CIDR, " 已存在路由表中, 直接跳过")
				continue
			}

			ip := net.ParseIP(network.IP)

			// 发往cidr的流量会通过link发往ip这个地址
			err = AddHostRoute(cidr, ip, link)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// AddHostRoute 向当前主机的路由表中添加一条主机路由规则
// 发往ipn的流量会从dev设备发往gw
// forked from plugins/pkg/ip/route_linux.go
func AddHostRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link) error {
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		// Scope:     netlink.SCOPE_HOST,
		Dst: ipn,
		Gw:  gw,
	})
}

// SetIptablesForDeviceToFarwordAccept 允许经过指定的网络接口（device）的数据包被转发到其他 IP 地址
func SetIptablesForDeviceToFarwordAccept(device *netlink.Device) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		utils.WriteLog("这里 NewWithProtocol 失败, err: ", err.Error())
		return err
	}
	err = ipt.Append("filter", "FORWARD", "-i", device.Attrs().Name, "-j", "ACCEPT")
	if err != nil {
		utils.WriteLog("这里 ipt.Append 失败, err: ", err.Error())
		return err
	}
	return nil
}

// SetIptablesForToForwardAccept 将iptables规则设置为允许通过指定网络接口(在这里是link)的转发流量
func SetIptablesForToForwardAccept(link netlink.Link) error {
	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		utils.WriteLog("这里 NewWithProtocol 失败, err: ", err.Error())
		return err
	}
	err = ipt.Append("filter", "FORWARD", "-i", link.Attrs().Name, "-j", "ACCEPT")
	if err != nil {
		utils.WriteLog("这里 ipt.Append 失败, err: ", err.Error())
		return err
	}
	return nil
}

// SetVethMaster 将一个 Veth 对象（*netlink.Veth 类型）添加到指定的 Bridge 对象（*netlink.Bridge 类型）中
// 实现两个不同的网络命名空间之间的通信
func SetVethMaster(veth *netlink.Veth, br *netlink.Bridge) error {
	err := netlink.LinkSetMaster(veth, br)
	if err != nil {
		utils.WriteLog(fmt.Sprintf("把 veth %q 干到 master 上失败: %v", veth.Attrs().Name, err))
		return fmt.Errorf("add veth %q to master error: %v", veth.Attrs().Name, err)
	}
	return nil
}

func SetDefaultRouteToVeth(gwIP net.IP, veth netlink.Link) error {
	return AddDefaultRoute(gwIP, veth)
}

// forked from plugins/pkg/ip/route_linux.go
func AddDefaultRoute(gw net.IP, dev netlink.Link) error {
	_, defNet, _ := net.ParseCIDR("0.0.0.0/0")
	return AddRoute(defNet, gw, dev)
}

// forked from plugins/pkg/ip/route_linux.go
func AddRoute(ipn *net.IPNet, gw net.IP, dev netlink.Link, scope ...netlink.Scope) error {
	defaultScope := netlink.SCOPE_UNIVERSE
	if len(scope) > 0 {
		defaultScope = scope[0]
	}
	return netlink.RouteAdd(&netlink.Route{
		LinkIndex: dev.Attrs().Index,
		Scope:     defaultScope,
		Dst:       ipn,
		Gw:        gw,
	})
}

func SetUpVeth(veth ...*netlink.Veth) error {
	for _, v := range veth {
		// 启动 veth 设备
		err := netlink.LinkSetUp(v)
		if err != nil {
			utils.WriteLog("启动 veth1 失败, err: ", err.Error())
			return err
		}
	}
	return nil
}

// CreateBridge 创建一个网桥设备，并将其绑定到指定的IP地址上，让它作为一个网关。
// 网桥的名称（brName）、IP地址（gw）以及 MTU 大小。
// "MTU"（Maximum Transmission Unit）是网络数据包中传输的最大数据长度。
// NOTE: 网关作为网络中的出入口，起到了重要的作用。
// 当一台计算机需要连接到另一个网络时，它需要知道目标网络的地址和子网掩码，并将数据包发送到目标网络的网关。
// 网关收到数据包后，会根据目标网络的地址将数据包转发给正确的下一跳路由器或目标主机。
// 因此，网关可以将不同的物理网络连接在一起，并使得它们能够互相通信。
func CreateBridge(brName, gw string, mtu int) (*netlink.Bridge, error) {
	// 首先尝试通过网桥的名称获取网桥设备的链接，如果找到了就返回该设备的指针，否则会创建一个新的网桥设备
	l, err := netlink.LinkByName(brName)
	if err != nil {
		return nil, err
	}

	br, ok := l.(*netlink.Bridge)
	if ok && br != nil {
		return br, nil
	}

	br = &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name:   brName,
			MTU:    mtu,
			TxQLen: -1,
		},
	}

	err = netlink.LinkAdd(br)
	if err != nil {
		utils.WriteLog("无法创建网桥: ", brName, "err: ", err.Error())
		return nil, err
	}

	// 这里需要通过 netlink 重新获取网桥
	// 否则光创建的话无法从上头拿到其他属性
	l, err = netlink.LinkByName(brName)
	if err != nil {
		return nil, err
	}

	br, ok = l.(*netlink.Bridge)
	if !ok {
		utils.WriteLog("找到了设备, 但是该设备不是网桥")
		return nil, fmt.Errorf("found the device %q but it's not a bridge device", brName)
	}

	// 给网桥绑定 ip 地址, 让网桥作为网关
	ipaddr, ipnet, err := net.ParseCIDR(gw)
	if err != nil {
		utils.WriteLog("无法 parse gw 为 ipnet, err: ", err.Error())
		return nil, fmt.Errorf("transform the gatewayIP error %q: %v", gw, err)
	}
	ipnet.IP = ipaddr
	addr := &netlink.Addr{IPNet: ipnet}
	if err = netlink.AddrAdd(br, addr); err != nil {
		utils.WriteLog("将 gw 添加到 bridge 失败, err: ", err.Error())
		return nil, fmt.Errorf("can not add the gw %q to bridge %q, err: %v", addr, brName, err)
	}

	// 然后还要把这个网桥给 up 起来
	if err = netlink.LinkSetUp(br); err != nil {
		utils.WriteLog("启动网桥失败, err: ", err.Error())
		return nil, fmt.Errorf("set up bridge %q error, err: %v", brName, err)
	}
	return br, nil
}

func CreateVethPair(ifName string, mtu int, hostName ...string) (*netlink.Veth, *netlink.Veth, error) {
	vethPairName := ""
	if len(hostName) > 0 && hostName[0] != "" {
		vethPairName = hostName[0]
	} else {
		for {
			_vname, err := RandomVethName()
			vethPairName = _vname
			if err != nil {
				utils.WriteLog("生成随机 veth pair 名字失败, err: ", err.Error())
				return nil, nil, err
			}

			_, err = netlink.LinkByName(vethPairName)
			if err != nil && !os.IsExist(err) {
				// 上面生成随机名字可能会重名, 所以这里先尝试按照这个名字获取一下
				// 如果没有这个名字的设备, 那就可以 break 了
				break
			}
		}
	}

	if vethPairName == "" {
		return nil, nil, errors.New("create veth pair's name error")
	}

	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName,
			// Flags:     net.FlagUp,
			MTU: mtu,
			// Namespace: netlink.NsFd(int(ns.Fd())), // 先不设置 ns, 要不一会儿下头 LinkByName 时候找不到
		},
		PeerName: vethPairName,
		// PeerNamespace: netlink.NsFd(int(ns.Fd())),
	}

	// 创建 veth pair
	err := netlink.LinkAdd(veth)

	if err != nil {
		utils.WriteLog("创建 veth 设备失败, err: ", err.Error())
		return nil, nil, err
	}

	// 尝试重新获取 veth 设备看是否能成功
	veth1, err := netlink.LinkByName(ifName) // veth1 一会儿要在 pod(net ns) 里
	if err != nil {
		// 如果获取失败就尝试删掉
		netlink.LinkDel(veth1)
		utils.WriteLog("创建完 veth 但是获取失败, err: ", err.Error())
		return nil, nil, err
	}

	// 尝试重新获取 veth 设备看是否能成功
	veth2, err := netlink.LinkByName(vethPairName) // veth2 在主机上
	if err != nil {
		// 如果获取失败就尝试删掉
		netlink.LinkDel(veth2)
		utils.WriteLog("创建完 veth 但是获取失败, err: ", err.Error())
		return nil, nil, err
	}

	return veth1.(*netlink.Veth), veth2.(*netlink.Veth), nil
}

// RandomVethName returns string "veth" with random prefix (hashed from entropy)
// forked from /plugins/pkg/ip/link_linux.go
func RandomVethName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (recent versions) will ignore veth devices that start with "veth"
	return fmt.Sprintf("veth%x", entropy), nil
}

func SetVethNsFd(veth *netlink.Veth, ns ns.NetNS) error {
	return SetDeviceToNS(veth, ns)
}

// SetDeviceToNS 将一个网络设备（network device）添加到指定的网络命名空间（network namespace）
// 其中 fd 是文件描述符（file descriptor）的缩写。
func SetDeviceToNS(device netlink.Link, ns ns.NetNS) error {
	err := netlink.LinkSetNsFd(device, int(ns.Fd()))
	if err != nil {
		return fmt.Errorf("failed to add the device %q to ns: %v", device.Attrs().Name, err)
	}
	return nil
}

func SetIpForVeth(name string, podIP string) error {
	return setIpForDevice(name, podIP, "veth")
}

// setIpForDevice 给指定的网络设备设置 IP 地址
func setIpForDevice(name string, ip string, mode ...string) error {
	deviceType := ""
	if len(mode) != 0 {
		deviceType = mode[0]
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to get %s device by name %q, error: %v", deviceType, name, err)
	}

	ipaddr, ipnet, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("failed to transform the ip %q, error : %v", ip, err)
	}
	ipnet.IP = ipaddr
	err = netlink.AddrAdd(link, &netlink.Addr{IPNet: ipnet})
	if err != nil {
		return fmt.Errorf("can not add the ip %q to %s device %q, error: %v", ip, deviceType, name, err)
	}
	return nil
}
