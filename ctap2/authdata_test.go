package ctap2

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// authDataHeader builds the fixed 37-byte rpIdHash+flags+signCount
// prefix every authData structure starts with.
func authDataHeader(flags byte) []byte {
	header := make([]byte, 37)
	copy(header[:32], bytes.Repeat([]byte{0xAA}, 32))
	header[32] = flags
	binary.BigEndian.PutUint32(header[33:37], 1)
	return header
}

func TestParseAuthDataNoFlags(t *testing.T) {
	ad, err := parseAuthData(authDataHeader(0x00))
	if err != nil {
		t.Fatalf("parseAuthData: %v", err)
	}
	if ad.credentialID != nil {
		t.Errorf("credentialID = %x, want nil (no AT flag)", ad.credentialID)
	}
	if ad.extensions != nil {
		t.Errorf("extensions = %v, want nil (no ED flag)", ad.extensions)
	}
}

func TestParseAuthDataAttestedCredentialData(t *testing.T) {
	credID := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	pubKey, err := cbor.Marshal(coseKey{Kty: coseKeyTypeEC2, Alg: -7, Crv: coseCurveP256, X: bytes.Repeat([]byte{0x11}, 32), Y: bytes.Repeat([]byte{0x22}, 32)})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}

	data := authDataHeader(flagAttestedCredData)
	data = append(data, bytes.Repeat([]byte{0}, 16)...) // aaguid
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID))) //nolint:gosec // test fixture; credID literals here are always a handful of bytes
	data = append(data, credIDLen...)
	data = append(data, credID...)
	data = append(data, pubKey...)

	ad, err := parseAuthData(data)
	if err != nil {
		t.Fatalf("parseAuthData: %v", err)
	}
	if !bytes.Equal(ad.credentialID, credID) {
		t.Errorf("credentialID = %x, want %x", ad.credentialID, credID)
	}
	if ad.extensions != nil {
		t.Errorf("extensions = %v, want nil (no ED flag)", ad.extensions)
	}
}

func TestParseAuthDataExtensionsOnly(t *testing.T) {
	extBytes, err := cbor.Marshal(map[string][]byte{"hmac-secret": bytes.Repeat([]byte{0x33}, 48)})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	data := append(authDataHeader(flagExtensionData), extBytes...)

	ad, err := parseAuthData(data)
	if err != nil {
		t.Fatalf("parseAuthData: %v", err)
	}
	if ad.credentialID != nil {
		t.Errorf("credentialID = %x, want nil (no AT flag)", ad.credentialID)
	}
	raw, ok := ad.extensions["hmac-secret"]
	if !ok {
		t.Fatalf("extensions missing \"hmac-secret\" key: %v", ad.extensions)
	}
	var got []byte
	if err := cbor.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decoding hmac-secret extension value: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x33}, 48)) {
		t.Errorf("hmac-secret extension value = %x, want 48 bytes of 0x33", got)
	}
}

func TestParseAuthDataAttestedCredentialDataAndExtensions(t *testing.T) {
	credID := []byte{0xAB, 0xCD}
	pubKey, err := cbor.Marshal(coseKey{Kty: coseKeyTypeEC2, Crv: coseCurveP256, X: bytes.Repeat([]byte{0x01}, 32), Y: bytes.Repeat([]byte{0x02}, 32)})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}
	extBytes, err := cbor.Marshal(map[string]bool{"hmac-secret": true})
	if err != nil {
		t.Fatalf("cbor.Marshal: %v", err)
	}

	data := authDataHeader(flagAttestedCredData | flagExtensionData)
	data = append(data, bytes.Repeat([]byte{0}, 16)...)
	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credID))) //nolint:gosec // test fixture; credID literals here are always a handful of bytes
	data = append(data, credIDLen...)
	data = append(data, credID...)
	data = append(data, pubKey...)
	data = append(data, extBytes...)

	ad, err := parseAuthData(data)
	if err != nil {
		t.Fatalf("parseAuthData: %v", err)
	}
	if !bytes.Equal(ad.credentialID, credID) {
		t.Errorf("credentialID = %x, want %x", ad.credentialID, credID)
	}
	var enabled bool
	if err := cbor.Unmarshal(ad.extensions["hmac-secret"], &enabled); err != nil {
		t.Fatalf("decoding hmac-secret extension value: %v", err)
	}
	if !enabled {
		t.Error("hmac-secret extension value = false, want true")
	}
}

func TestParseAuthDataErrors(t *testing.T) {
	tests := map[string][]byte{
		"too short":                    make([]byte, 10),
		"AT flag but truncated aaguid": append(authDataHeader(flagAttestedCredData), make([]byte, 5)...),
		"AT flag but truncated credID": append(append(authDataHeader(flagAttestedCredData), make([]byte, 16)...), 0x00, 0xFF), // claims a 255-byte credential ID with nothing after
		"ED flag but invalid CBOR":     append(authDataHeader(flagExtensionData), 0xFF, 0xFF, 0xFF),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseAuthData(data); err == nil {
				t.Error("expected an error, got nil")
			}
		})
	}
}
