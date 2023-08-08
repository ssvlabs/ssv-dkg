package main

import (
	"github.com/bloxapp/ssv-dkg-tool/cli"
)

var (
	// AppName is the application name
	AppName = "SSV-DKG-Tool"

	// Version is the app version
	Version = "latest"
)

func main() {
	cli.Execute(AppName, Version)
}
