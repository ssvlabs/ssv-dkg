package main

import (
	"flag"
	"fmt"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"log"
	"strconv"
	"strings"
)

// TODO: CLI
func main() {
	operatorFile := flag.String("operators", "", "Path to operators' public keys, IDs and IPs file")
	participants := flag.String("participants", "", "participants in dkg")
	withdrawAddr := flag.String("withdraw", "0x0", "address to withdraw to")

	flag.Parse()

	// Load operators TODO: add more sources.
	opmap, err := load.Operators(*operatorFile)
	if err != nil {
		log.Fatalf("Failed to load operators: %v", err)
	}

	parts, err := loadParticipants(*participants)

	if err != nil {
		log.Fatalf("failed: %v", err)
	}

	dkgclient := client.New(opmap)

	err = dkgclient.StartDKG([]byte(*withdrawAddr), parts)

	if err != nil {
		log.Fatalf("wtf %v")
	}
}

func loadParticipants(flagdata string) ([]uint64, error) {
	parts := strings.Split(flagdata, ",")

	partsarr := make([]uint64, 0, len(parts))

	for i := 0; i < len(parts); i++ {
		opid, err := strconv.ParseUint(parts[i], 10, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("cant load operator err: %v , data: %v, ", err, parts[i])
		}
		partsarr = append(partsarr, opid)
	}

	return partsarr, nil
}
