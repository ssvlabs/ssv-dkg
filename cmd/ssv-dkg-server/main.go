package main

import (
	"flag"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"
	"log"
)

func main() {
	// Parse command line arguments
	port := flag.Uint("port", 3030, "the port to start the server on")
	privateKeyFile := flag.String("private-key", "", "Path to RSA private key file")
	flag.Parse()

	if *privateKeyFile == "" {
		log.Fatal("Must provide a private key")
	}

	// Load and decode the private key
	privateKey, err := load.PrivateKey(*privateKeyFile)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	srv := server.New(privateKey)

	if err := srv.Start(uint16(*port)); err != nil {
		log.Fatalf("Error in server %v", err)
	}

}
