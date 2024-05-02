package rpc

import (
	"context"

	"github.com/starkzarn/glod/protobuf/commonpb"
	"github.com/starkzarn/glod/server/configs"
	"github.com/starkzarn/glod/server/watchtower"
)

func (rpc *Server) MonitorStart(ctx context.Context, _ *commonpb.Empty) (*commonpb.Response, error) {
	resp := &commonpb.Response{}
	config := configs.GetServerConfig()
	err := watchtower.StartWatchTower(config)
	if err != nil {
		resp.Err = err.Error()
	}
	return resp, err
}

func (rpc *Server) MonitorStop(ctx context.Context, _ *commonpb.Empty) (*commonpb.Empty, error) {
	resp := &commonpb.Empty{}
	watchtower.StopWatchTower()
	return resp, nil
}
