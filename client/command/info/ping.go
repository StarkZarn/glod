package info

import (
	"context"
	insecureRand "math/rand"

	"github.com/starkzarn/glod/client/console"
	"github.com/starkzarn/glod/protobuf/glodpb"
	"github.com/desertbit/grumble"
)

// PingCmd - Send a round trip C2 message to an implant (does not use ICMP)
func PingCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	session := con.ActiveTarget.GetSessionInteractive()
	if session == nil {
		return
	}

	nonce := insecureRand.Intn(999999)
	con.PrintInfof("Ping %d\n", nonce)
	pong, err := con.Rpc.Ping(context.Background(), &glodpb.Ping{
		Nonce:   int32(nonce),
		Request: con.ActiveTarget.Request(ctx),
	})
	if err != nil {
		con.PrintErrorf("%s\n", err)
	} else {
		con.PrintInfof("Pong %d\n", pong.Nonce)
	}
}
