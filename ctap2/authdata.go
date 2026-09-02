package ctap2

import (
	"encoding/binary"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// authenticatorData flag bits - see the WebAuthn spec's "authenticator
// data" section. gokeys only ever inspects attestedCredData/extensionData.
const (
	flagAttestedCredData = 0x40
	flagExtensionData    = 0x80
)

// authData is the subset of a parsed CTAP2 authenticatorData structure
// gokeys needs. The full binary layout (common to both
// authenticatorMakeCredential's and authenticatorGetAssertion's
// responses) is:
//
//	[32 bytes] rpIdHash
//	[1 byte]   flags
//	[4 bytes]  signCount
//	[...]      attestedCredentialData, only if flags&flagAttestedCredData:
//	             [16 bytes] aaguid
//	             [2 bytes]  credentialId length (big-endian)
//	             [...]      credentialId
//	             [...]      credentialPublicKey (a CBOR-encoded COSE key)
//	[...]      extensions (a CBOR map), only if flags&flagExtensionData
type authData struct {
	flags        byte
	credentialID []byte                     // set only if flagAttestedCredData
	extensions   map[string]cbor.RawMessage // set only if flagExtensionData
}

func parseAuthData(data []byte) (*authData, error) {
	if len(data) < 37 {
		return nil, fmt.Errorf("ctap2: authData too short (%d bytes)", len(data))
	}
	ad := &authData{flags: data[32]}
	rest := data[37:]

	if ad.flags&flagAttestedCredData != 0 {
		if len(rest) < 18 {
			return nil, fmt.Errorf("ctap2: authData truncated in attested credential data")
		}
		credIDLen := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if len(rest) < credIDLen {
			return nil, fmt.Errorf("ctap2: authData truncated in credential ID")
		}
		ad.credentialID = append([]byte(nil), rest[:credIDLen]...)
		rest = rest[credIDLen:]

		// The credential's public key follows, CBOR-encoded - gokeys
		// never uses it (only the hmac-secret extension, never any
		// asymmetric operation on this credential), but it must still
		// be decoded to know where it ends, since nothing else records
		// its length.
		var pubKey cbor.RawMessage
		remaining, err := cbor.UnmarshalFirst(rest, &pubKey)
		if err != nil {
			return nil, fmt.Errorf("ctap2: decoding credential public key: %w", err)
		}
		rest = remaining
	}

	if ad.flags&flagExtensionData != 0 {
		if err := cbor.Unmarshal(rest, &ad.extensions); err != nil {
			return nil, fmt.Errorf("ctap2: decoding extensions: %w", err)
		}
	}

	return ad, nil
}
