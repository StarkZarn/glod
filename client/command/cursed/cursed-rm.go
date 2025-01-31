package cursed

/*
	Sliver Implant Framework
	Copyright (C) 2022  Bishop Fox

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

	"github.com/AlecAivazis/survey/v2"
	"github.com/starkzarn/glod/client/console"
	"github.com/starkzarn/glod/client/core"
	"github.com/starkzarn/glod/protobuf/glodpb"
	"github.com/desertbit/grumble"
)

func CursedRmCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	kill := ctx.Flags.Bool("kill")
	bindPort := ctx.Args.Int("bind-port")
	core.CloseCursedProcessesByBindPort(session.ID, bindPort)
	if kill {
		confirm := false
		err := survey.AskOne(&survey.Confirm{Message: "Kill the cursed process?"}, &confirm)
		if err != nil {
			con.PrintErrorf("%s", err)
			return
		}
		if !confirm {
			con.PrintErrorf("User cancel\n")
			return
		}
		// Get cursed process
		var cursedProc *core.CursedProcess
		curses := core.CursedProcessBySessionID(session.ID)
		for _, curse := range curses {
			if curse.BindTCPPort == bindPort {
				cursedProc = curse
			}
		}
		if cursedProc == nil {
			con.PrintErrorf("Failed to find cursed process\n")
			return
		}
		terminateResp, err := con.Rpc.Terminate(context.Background(), &glodpb.TerminateReq{
			Request: con.ActiveTarget.Request(ctx),
			Pid:     int32(cursedProc.PID),
		})
		if err != nil {
			con.PrintErrorf("%s\n", err)
			return
		}
		if terminateResp.Response != nil && terminateResp.Response.Err != "" {
			con.PrintErrorf("could not terminate the existing process: %s\n", terminateResp.Response.Err)
			return
		}
	}
}
