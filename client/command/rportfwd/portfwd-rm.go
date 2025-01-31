package rportfwd

/*
	Sliver Implant Framework
	Copyright (C) 2019  Bishop Fox

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import (
	"context"

	"github.com/starkzarn/glod/client/console"
	"github.com/starkzarn/glod/protobuf/glodpb"

	"github.com/desertbit/grumble"
)

// StartRportFwdListenerCmd - Start listener for reverse port forwarding on implant
func StopRportFwdListenerCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}

	listenerID := ctx.Flags.Int("id")
	rportfwdListener, err := con.Rpc.StopRportFwdListener(context.Background(), &glodpb.RportFwdStopListenerReq{
		Request: con.ActiveTarget.Request(ctx),
		ID:      uint32(listenerID),
	})
	if err != nil {
		con.PrintWarnf("%s\n", err)
		return
	}
	printStoppedRportFwdListener(rportfwdListener, con)
}

func printStoppedRportFwdListener(rportfwdListener *glodpb.RportFwdListener, con *console.SliverConsoleClient) {
	if rportfwdListener.Response != nil && rportfwdListener.Response.Err != "" {
		con.PrintErrorf("%s", rportfwdListener.Response.Err)
		return
	}
	con.PrintInfof("Stopped reverse port forwarding %s <- %s\n", rportfwdListener.ForwardAddress, rportfwdListener.BindAddress)
}
