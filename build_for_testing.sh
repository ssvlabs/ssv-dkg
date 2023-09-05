#!/bin/bash
go build cmd/dkgcli/dkgcli.go

cp dkgcli ./examples/server1/dkgcli
cp dkgcli ./examples/server2/dkgcli
cp dkgcli ./examples/server3/dkgcli
cp dkgcli ./examples/server4/dkgcli