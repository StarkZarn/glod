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
	"fmt"
	"regexp"

	"github.com/starkzarn/glod/client/console"
	"github.com/starkzarn/glod/protobuf/glodpb"

	"github.com/desertbit/grumble"
)

var (
	portNumberOnlyRegexp = regexp.MustCompile("^[0-9]+$")
)

// StartRportFwdListenerCmd - Start listener for reverse port forwarding on implant
func StartRportFwdListenerCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	if session.GetActiveC2() == "dns" {
		con.PrintWarnf("The current C2 is DNS, this is going to be a very slow tunnel!\n")
	}

	bindAddress := ctx.Flags.String("bind")
	// Check if the bind address is just a port number, if no host is specified
	// we just bind to all interfaces implant-side
	if portNumberOnlyRegexp.MatchString(bindAddress) {
		bindAddress = fmt.Sprintf(":%s", bindAddress)
	}

	forwardAddress := ctx.Flags.String("remote")
	// Check if the forward address is just a port number, if no host is specified
	// we just forward to localhost client-side
	if portNumberOnlyRegexp.MatchString(forwardAddress) {
		forwardAddress = fmt.Sprintf("127.0.0.1:%s", forwardAddress)
	}
	rportfwdListener, err := con.Rpc.StartRportFwdListener(context.Background(), &glodpb.RportFwdStartListenerReq{
		Request:        con.ActiveTarget.Request(ctx),
		BindAddress:    bindAddress,
		ForwardAddress: forwardAddress,
	})
	if err != nil {
		con.PrintWarnf("%s\n", err)
		return
	}
	printStartedRportFwdListener(rportfwdListener, con)
}

func printStartedRportFwdListener(rportfwdListener *glodpb.RportFwdListener, con *console.SliverConsoleClient) {
	if rportfwdListener.Response != nil && rportfwdListener.Response.Err != "" {
		con.PrintErrorf("%s", rportfwdListener.Response.Err)
		return
	}
	con.PrintInfof("Reverse port forwarding %s <- %s\n", rportfwdListener.ForwardAddress, rportfwdListener.BindAddress)
}
