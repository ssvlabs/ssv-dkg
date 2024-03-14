package main

import (
	"context"
	"log"

	"github.com/bloxapp/ssv-dkg/e2e"
)

func main() {
	ctx := context.Background()
	err := e2e.Run(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("E2E tests passed")
}
