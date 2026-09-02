// Command unlock re-derives the hmac-secret for a credential created by
// the enroll example, given its credential ID (hex-encoded) as an
// argument, and prints the derived secret (hex-encoded).
//
// Run it with:
//
//	go run ./examples/unlock <credential-id-hex>
package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	hmacsecret "github.com/tpyle/gohmacsecret"
)

// rpID must match what the enroll example used.
const rpID = "gohmacsecret-example"

// salt would normally be generated once and stored alongside the
// credential ID - a fixed value here only for this example's sake.
var salt = []byte("gohmacsecret-example-salt")

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: unlock <credential-id-hex>")
		os.Exit(2)
	}
	credentialID, err := hex.DecodeString(os.Args[1])
	if err != nil {
		log.Fatalf("decoding credential ID: %v", err)
	}

	fmt.Println("Touch your security key when it starts flashing...")

	secret, err := hmacsecret.GetSecret(rpID, credentialID, salt)
	if err != nil {
		log.Fatalf("GetSecret: %v", err)
	}

	fmt.Println("Derived secret:")
	fmt.Println(hex.EncodeToString(secret))
}
