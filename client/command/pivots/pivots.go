package pivots

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

	"github.com/starkzarn/glod/client/command/settings"
	"github.com/starkzarn/glod/client/console"
	"github.com/starkzarn/glod/protobuf/glodpb"
	"github.com/jedib0t/go-pretty/v6/table"

	"github.com/desertbit/grumble"
)

// PivotsCmd - Display pivots for all sessions
func PivotsCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}
	pivotListeners, err := con.Rpc.PivotSessionListeners(context.Background(), &glodpb.PivotListenersReq{
		Request: con.ActiveTarget.Request(ctx),
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
		return
	}
	if pivotListeners.Response != nil && pivotListeners.Response.Err != "" {
		con.PrintErrorf("%s\n", pivotListeners.Response.Err)
		return
	}

	if len(pivotListeners.Listeners) == 0 {
		con.PrintInfof("No pivot listeners running on this session\n")
	} else {
		PrintPivotListeners(pivotListeners.Listeners, con)
	}
}

// PrintPivotListeners - Print a table of pivot listeners
func PrintPivotListeners(pivotListeners []*glodpb.PivotListener, con *console.SliverConsoleClient) {
	tw := table.NewWriter()
	tw.SetStyle(settings.GetTableStyle(con))
	tw.AppendHeader(table.Row{
		"ID",
		"Protocol",
		"Bind Address",
		"Number of Pivots",
	})
	for _, listener := range pivotListeners {
		tw.AppendRow(table.Row{
			listener.ID,
			PivotTypeToString(listener.Type),
			listener.BindAddress,
			len(listener.Pivots),
		})
	}
	con.Printf("%s\n", tw.Render())
}

// PivotTypeToString - Convert a pivot type to a human string
func PivotTypeToString(pivotType glodpb.PivotType) string {
	switch pivotType {
	case glodpb.PivotType_TCP:
		return "TCP"
	case glodpb.PivotType_UDP:
		return "UDP"
	case glodpb.PivotType_NamedPipe:
		return "Named Pipe"
	}
	return "Unknown"
}
