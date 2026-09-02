// Command enroll creates a new FIDO2 hmac-secret credential and prints
// its credential ID (hex-encoded, since it's binary) so it can be saved
// and later passed to the unlock example.
//
// Run it with:
//
//	go run ./examples/enroll
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	hmacsecret "github.com/tpyle/gohmacsecret"
)

// rpID identifies this application to the authenticator - any stable
// string works, but it must be byte-identical between Enroll and every
// later GetSecret call for the resulting credential.
const rpID = "gohmacsecret-example"

func main() {
	fmt.Println("Touch your security key when it starts flashing...")

	credentialID, err := hmacsecret.Enroll(rpID)
	if err != nil {
		log.Fatalf("Enroll: %v", err)
	}

	fmt.Println("Enrolled. Save this credential ID to use with the unlock example:")
	fmt.Println(hex.EncodeToString(credentialID))
}
