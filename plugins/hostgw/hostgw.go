package hostgw

import (
	types "github.com/containernetworking/cni/pkg/types/100"
	"github.com/elpsyr/cni/pkg/cni"
	"github.com/elpsyr/cni/pkg/consts"
	"github.com/elpsyr/cni/pkg/skel"
)

const MODE = consts.MODE_HOST_GW

type HostGatewayCNI struct{}

func (h HostGatewayCNI) Bootstrap(args *skel.CmdArgs, pluginConfig *cni.PluginConf) (*types.Result, error) {
	//TODO implement me
	//ipamClient, err := ipam.New(ipam.Config{
	//	Subnet: pluginConfig.Subnet,
	//})
	//if err != nil {
	//	utils.WriteLog("创建 ipam 客户端出错, err: ", err.Error())
	//}
	//gateway, err := ipamClient.Gateway()
	//if err != nil {
	//	utils.WriteLog("创建 ipam 客户端出错, err: ", err.Error())
	//}
	//gatewayWithMaskSegment, err := ipamClient.GatewayWithMaskSegment()
	//if err != nil {
	//	utils.WriteLog("获取 gatewayWithMaskSegment 出错, err: ", err.Error())
	//	return nil, err
	//}
	//
	//bridgeName := pluginConfig.Bridge
	//if bridgeName == "" {
	//	bridgeName = "testcni0"
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
