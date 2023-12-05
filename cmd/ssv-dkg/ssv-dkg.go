package main

import (
	"github.com/bloxapp/ssv-dkg/cli"
)

var (
	// AppName is the application name
	AppName = "ssv-dkg"

	// Version is the app version
	Version = "v1.0.3"
)

func main() {
	cli.Execute(AppName, Version)
}
