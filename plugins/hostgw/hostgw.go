package hostgw

import (
	types "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/elpsyr/cni/pkg/cni"
	"github.com/elpsyr/cni/pkg/consts"
	cninet "github.com/elpsyr/cni/pkg/net"
	"github.com/elpsyr/cni/pkg/skel"
	"github.com/elpsyr/cni/pkg/utils"
	"github.com/elpsyr/ipam"
	"github.com/vishvananda/netlink"
	"net"
	"os"
)

const MODE = consts.MODE_HOST_GW

type HostGatewayCNI struct{}

func (h HostGatewayCNI) Bootstrap(args *skel.CmdArgs, pluginConfig *cni.PluginConf) (*types.Result, error) {
	//TODO implement me
	ipamClient, err := ipam.New(ipam.Config{
		Subnet: pluginConfig.Subnet,
	})
	if err != nil {
		utils.WriteLog("创建 ipam 客户端出错, err: ", err.Error())
	}
	gatewayWithMaskSegment, err := ipamClient.GatewayWithMaskSegment()
	if err != nil {
		utils.WriteLog("获取 gatewayWithMaskSegment 出错, err: ", err.Error())
		return nil, err
	}

	bridgeName := pluginConfig.Bridge
	if bridgeName == "" {
		bridgeName = "testcni0"
	}

	mtu := 1500

	// 获取 containerd 传过来的网卡名, 这个网卡名要被插到 net ns 中
	ifName := args.IfName
	// 根据 containerd 传过来的 netns 的地址获取 ns
	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		utils.WriteLog("获取 ns 失败: ", err.Error())
		return nil, err
	}

	// 从 ipam 中拿到一个未使用的 ip 地址
	podIP, err := ipamClient.GetUnusedIP()
	if err != nil {
		utils.WriteLog("获取 podIP 出错, err: ", err.Error())
		return nil, err
	}

	// 这里拼接 pod 的 cidr
	// podIP = podIP + "/" + ipamClient.MaskSegment
	podIP = podIP + "/" + "24"

	err = cninet.CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster(bridgeName, gatewayWithMaskSegment, ifName, podIP, mtu, netns)
	if err != nil {
		utils.WriteLog("执行创建网桥, 创建 veth 设备, 添加默认路由等操作失败, err: ", err.Error())
		// Todo : release  ip if failed
		//err = ipamClient.Release().IPs(podIP)

		if err != nil {
			utils.WriteLog("释放 podIP", podIP, " 失败: ", err.Error())
		}
	}

	// Todo 跨节点通讯

	gateway, err := ipamClient.Gateway()
	if err != nil {
		utils.WriteLog("获取当前节点网关出错, err: ", err.Error())
	}

	networks, err := ipamClient.AllHostNetwork()
	if err != nil {
		utils.WriteLog("这里的获取所有节点的网络信息失败, err: ", err.Error())
		return nil, err
	}
	// 然后获取一下本机的网卡信息
	hostname, err := os.Hostname()
	if err != nil {
		utils.WriteLog("这里的获取本机hostname信息失败, err: ", err.Error())
	}
	currentNetwork, err := ipamClient.HostNetwork(hostname)
	if err != nil {
		utils.WriteLog("获取本机网卡信息失败, err: ", err.Error())
		return nil, err
	}

	// 这里面要做的就是把其他节点上的 pods 的 cidr 和其主机的网卡 ip 作为一条路由规则创建到当前主机上
	err = cninet.SetOtherHostRouteToCurrentHost(networks, currentNetwork)
	if err != nil {
		utils.WriteLog("给主机添加其他节点网络信息失败, err: ", err.Error())
		return nil, err
	}

	link, err := netlink.LinkByName(currentNetwork.Name)
	if err != nil {
		utils.WriteLog("获取本机网卡失败, err: ", err.Error())
		return nil, err
	}
	err = cninet.SetIptablesForDeviceToFarwordAccept(link.(*netlink.Device))
	if err != nil {
		utils.WriteLog("设置本机网卡转发规则失败")
		return nil, err
	}

	_gw := net.ParseIP(gateway)

	_, _podIP, _ := net.ParseCIDR(podIP)

	result := &types.Result{
		CNIVersion: pluginConfig.CNIVersion,
		IPs: []*types.IPConfig{
			{
				Address: *_podIP,
				Gateway: _gw,
			},
		},
	}
	return result, nil

}

func (h HostGatewayCNI) Unmount(args *skel.CmdArgs, pluginConfig *cni.PluginConf) error {
	//TODO implement me
	panic("implement me")
}

func (h HostGatewayCNI) Check(args *skel.CmdArgs, pluginConfig *cni.PluginConf) error {
	//TODO implement me
	panic("implement me")
}

func (h HostGatewayCNI) GetMode() string {
	//TODO implement me
	panic("implement me")
}
