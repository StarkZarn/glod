package rpc

import (
	"context"

	"github.com/starkzarn/glod/protobuf/commonpb"
	"github.com/starkzarn/glod/protobuf/glodpb"
)

// StartService creates and starts a Windows service on a remote host
func (rpc *Server) StartService(ctx context.Context, req *glodpb.StartServiceReq) (*glodpb.ServiceInfo, error) {
	resp := &glodpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// StopService stops a remote service
func (rpc *Server) StopService(ctx context.Context, req *glodpb.StopServiceReq) (*glodpb.ServiceInfo, error) {
	resp := &glodpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// RemoveService deletes a service from the remote system
func (rpc *Server) RemoveService(ctx context.Context, req *glodpb.RemoveServiceReq) (*glodpb.ServiceInfo, error) {
	resp := &glodpb.ServiceInfo{Response: &commonpb.Response{}}
	err := rpc.GenericHandler(req, resp)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
