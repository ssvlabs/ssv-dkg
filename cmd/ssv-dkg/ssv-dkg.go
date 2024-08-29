package main

import (
	"github.com/ssvlabs/ssv-dkg/cli"
)

var (
	// AppName is the application name
	AppName = "ssv-dkg"

	// Version is the app version
	Version = "latest"
)

func main() {
	cli.Execute(AppName, Version)
}
