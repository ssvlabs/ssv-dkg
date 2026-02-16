package main

import "github.com/ssvlabs/ssv-dkg/cli"

// Version is the app version, set via -ldflags at build time.
var Version = "dev"

// BuildTime is the UTC timestamp of the build, set via -ldflags at build time.
var BuildTime = "unknown"

func main() {
	version := Version
	if BuildTime != "unknown" {
		version += " (built " + BuildTime + ")"
	}
	cli.Execute("ssv-dkg", version)
}
