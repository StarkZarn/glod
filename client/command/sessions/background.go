package sessions

import (
	"github.com/starkzarn/glod/client/console"
	"github.com/desertbit/grumble"
)

// BackgroundCmd - Background the active session
func BackgroundCmd(ctx *grumble.Context, con *console.SliverConsoleClient) {
	con.ActiveTarget.Background()
	con.PrintInfof("Background ...\n")
}
