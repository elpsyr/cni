package hostgw

import (
	types "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/elpsyr/cni/pkg/cni"
	"github.com/elpsyr/cni/pkg/consts"
	"github.com/elpsyr/cni/pkg/net"
	"github.com/elpsyr/cni/pkg/skel"
	"github.com/elpsyr/cni/pkg/utils"
	"github.com/elpsyr/ipam"
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

	err = net.CreateBridgeAndCreateVethAndSetNetworkDeviceStatusAndSetVethMaster(bridgeName, gatewayWithMaskSegment, ifName, podIP, mtu, netns)
	if err != nil {
		utils.WriteLog("执行创建网桥, 创建 veth 设备, 添加默认路由等操作失败, err: ", err.Error())
		// Todo : release  ip if failed
		//err = ipamClient.Release().IPs(podIP)

		if err != nil {
			utils.WriteLog("释放 podIP", podIP, " 失败: ", err.Error())
		}
	}

	// Todo 跨节点通讯

	//gateway, err := ipamClient.Gateway()
	//if err != nil {
	//	utils.WriteLog("获取当前节点网关出错, err: ", err.Error())
	//}
	panic("implement me")

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
