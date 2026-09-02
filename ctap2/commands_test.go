package ctap2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func newTestClient(t *testing.T, fa *fakeAuthenticator) *Client {
	t.Helper()
	c, err := NewClient(fa)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestGetInfoNoPIN(t *testing.T) {
	fa := newFakeAuthenticator()
	c := newTestClient(t, fa)

	info, err := c.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !info.SupportsHMACSecret() {
		t.Error("SupportsHMACSecret() = false, want true")
	}
	if !info.SupportsPINProtocolTwo() {
		t.Error("SupportsPINProtocolTwo() = false, want true")
	}
	if !info.ClientPIN {
		t.Error("ClientPIN = false, want true (the fake supports the ClientPIN feature)")
	}
	if info.PINSet {
		t.Error("PINSet = true, want false (no PIN configured on this fake)")
	}
}

func TestGetInfoNoHMACSecretSupport(t *testing.T) {
	fa := newFakeAuthenticator()
	fa.noHMACSecret = true
	c := newTestClient(t, fa)

	info, err := c.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.SupportsHMACSecret() {
		t.Error("SupportsHMACSecret() = true, want false")
	}
}

func TestGetInfoNoClientPINSupport(t *testing.T) {
	fa := newFakeAuthenticator()
	fa.pinOptionAbsent = true
	c := newTestClient(t, fa)

	info, err := c.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if info.ClientPIN {
		t.Error("ClientPIN = true, want false (the \"clientPin\" option key is absent)")
	}
	if info.PINSet {
		t.Error("PINSet = true, want false")
	}
}

func TestGetInfoPINSet(t *testing.T) {
	fa := newFakeAuthenticator().withPIN("1234")
	c := newTestClient(t, fa)

	info, err := c.GetInfo()
	if err != nil {
		t.Fatalf("GetInfo: %v", err)
	}
	if !info.PINSet {
		t.Error("PINSet = false, want true")
	}
}

func TestGetPINTokenSuccess(t *testing.T) {
	fa := newFakeAuthenticator().withPIN("1234")
	c := newTestClient(t, fa)

	token, err := c.GetPINToken("1234", PermissionGetAssertion, "gokeys")
	if err != nil {
		t.Fatalf("GetPINToken: %v", err)
	}
	if len(token) != 32 {
		t.Fatalf("token is %d bytes, want 32", len(token))
	}
	if !bytes.Equal(token, fa.pinToken) {
		t.Errorf("token = %x, want %x", token, fa.pinToken)
	}
}

func TestGetPINTokenWrongPIN(t *testing.T) {
	fa := newFakeAuthenticator().withPIN("1234")
	c := newTestClient(t, fa)

	_, err := c.GetPINToken("0000", PermissionGetAssertion, "gokeys")
	if err == nil {
		t.Fatal("expected an error for the wrong PIN, got nil")
	}
	var ctapErr *Error
	if !errors.As(err, &ctapErr) || ctapErr.Code != 0x31 {
		t.Errorf("error = %v, want a *ctap2.Error with code 0x31 (PIN invalid)", err)
	}
}

func TestMakeCredentialAndGetAssertionRoundTripNoPIN(t *testing.T) {
	fa := newFakeAuthenticator()
	c := newTestClient(t, fa)

	clientDataHash := sha256.Sum256([]byte("gokeys hmac-secret v1"))
	credID, err := c.MakeCredential("gokeys", clientDataHash[:], nil)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	if len(credID) == 0 {
		t.Fatal("MakeCredential returned an empty credential ID")
	}

	salt := bytes.Repeat([]byte{0x07}, hmacSecretSaltLen)
	secret1, err := c.GetAssertion("gokeys", clientDataHash[:], credID, salt, nil)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}
	if len(secret1) != 32 {
		t.Fatalf("secret is %d bytes, want 32", len(secret1))
	}

	// Deterministic: the same credential and salt must always derive the
	// same secret - this is the entire property gokeys relies on to
	// unwrap a "hardware" slot's DEK on every unlock.
	secret2, err := c.GetAssertion("gokeys", clientDataHash[:], credID, salt, nil)
	if err != nil {
		t.Fatalf("GetAssertion (second call): %v", err)
	}
	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("GetAssertion isn't deterministic: %x vs %x", secret1, secret2)
	}

	// A different salt against the same credential must derive a
	// different secret.
	otherSalt := bytes.Repeat([]byte{0x08}, hmacSecretSaltLen)
	secret3, err := c.GetAssertion("gokeys", clientDataHash[:], credID, otherSalt, nil)
	if err != nil {
		t.Fatalf("GetAssertion (different salt): %v", err)
	}
	if bytes.Equal(secret1, secret3) {
		t.Fatal("GetAssertion produced the same secret for two different salts")
	}
}

func TestMakeCredentialAndGetAssertionRoundTripWithPIN(t *testing.T) {
	fa := newFakeAuthenticator().withPIN("123456")
	c := newTestClient(t, fa)

	clientDataHash := sha256.Sum256([]byte("gokeys hmac-secret v1"))
	pinToken, err := c.GetPINToken("123456", PermissionMakeCredential, "gokeys")
	if err != nil {
		t.Fatalf("GetPINToken: %v", err)
	}
	credID, err := c.MakeCredential("gokeys", clientDataHash[:], pinToken)
	if err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}

	gaToken, err := c.GetPINToken("123456", PermissionGetAssertion, "gokeys")
	if err != nil {
		t.Fatalf("GetPINToken: %v", err)
	}
	salt := bytes.Repeat([]byte{0x09}, hmacSecretSaltLen)
	secret, err := c.GetAssertion("gokeys", clientDataHash[:], credID, salt, gaToken)
	if err != nil {
		t.Fatalf("GetAssertion: %v", err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret is %d bytes, want 32", len(secret))
	}
}

func TestMakeCredentialRejectsWrongPINToken(t *testing.T) {
	fa := newFakeAuthenticator().withPIN("123456")
	c := newTestClient(t, fa)

	clientDataHash := sha256.Sum256([]byte("gokeys hmac-secret v1"))
	_, err := c.MakeCredential("gokeys", clientDataHash[:], bytes.Repeat([]byte{0xFF}, 32))
	if err == nil {
		t.Fatal("expected an error for a bogus PIN token, got nil")
	}
}

func TestGetAssertionUnknownCredentialFailsFast(t *testing.T) {
	fa := newFakeAuthenticator()
	c := newTestClient(t, fa)

	clientDataHash := sha256.Sum256([]byte("gokeys hmac-secret v1"))
	salt := bytes.Repeat([]byte{0x01}, hmacSecretSaltLen)
	_, err := c.GetAssertion("gokeys", clientDataHash[:], []byte("not a real credential id"), salt, nil)
	if err == nil {
		t.Fatal("expected an error for an unrecognized credential ID, got nil")
	}
	var ctapErr *Error
	if !errors.As(err, &ctapErr) || ctapErr.Code != 0x2E {
		t.Errorf("error = %v, want a *ctap2.Error with code 0x2E (no credentials)", err)
	}
}

func TestGetAssertionRejectsWrongSaltLength(t *testing.T) {
	fa := newFakeAuthenticator()
	c := newTestClient(t, fa)
	clientDataHash := sha256.Sum256([]byte("x"))
	if _, err := c.GetAssertion("gokeys", clientDataHash[:], []byte("cred"), []byte("too short"), nil); err == nil {
		t.Fatal("expected an error for a non-32-byte salt, got nil")
	}
}

func TestKeepAliveDuringMakeCredentialInvokesOnKeepAlive(t *testing.T) {
	fa := newFakeAuthenticator()
	fa.keepAlivesBeforeResponse = 3
	c := newTestClient(t, fa)
	var calls int
	c.OnKeepAlive = func(_ byte) { calls++ }

	clientDataHash := sha256.Sum256([]byte("gokeys hmac-secret v1"))
	if _, err := c.MakeCredential("gokeys", clientDataHash[:], nil); err != nil {
		t.Fatalf("MakeCredential: %v", err)
	}
	// The fake emits the same status (0x02) for every keep-alive, so the
	// de-duplication in readResponse means exactly one call, however many
	// keep-alive frames were sent.
	if calls != 1 {
		t.Errorf("OnKeepAlive called %d times, want 1", calls)
	}
}

// TestWireFormatMapKeys guards the CBOR struct tags in commands.go/pin.go
// against a mistaken key number by decoding a real, fully-encoded
// GetAssertion request into a generic integer-keyed map and checking the
// exact keys and nested hmac-secret extension shape against the CTAP2
// spec - independent of fakeAuthenticator, which (being in the same
// package) decodes with the very same struct tags and so couldn't catch
// a shared mistake in them.
func TestWireFormatMapKeys(t *testing.T) {
	req := getAssertionRequest{
		RPID:           "gokeys",
		ClientDataHash: bytes.Repeat([]byte{0x01}, 32),
		AllowList:      []credentialDescriptor{{ID: []byte{0xAA}, Type: "public-key"}},
		Extensions: map[string]any{
			"hmac-secret": hmacSecretInput{
				KeyAgreement:      coseKey{Kty: 2, Alg: -25, Crv: 1, X: bytes.Repeat([]byte{0x02}, 32), Y: bytes.Repeat([]byte{0x03}, 32)},
				SaltEnc:           bytes.Repeat([]byte{0x04}, 48),
				SaltAuth:          bytes.Repeat([]byte{0x05}, 32),
				PINUvAuthProtocol: 2,
			},
		},
		PINUvAuthParam:    bytes.Repeat([]byte{0x06}, 32),
		PINUvAuthProtocol: 2,
	}
	enc, err := ctap2EncMode.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var generic map[int]cbor.RawMessage
	if err := cbor.Unmarshal(enc, &generic); err != nil {
		t.Fatalf("decoding into a generic map: %v", err)
	}
	for _, key := range []int{1, 2, 3, 4, 6, 7} {
		if _, ok := generic[key]; !ok {
			t.Errorf("encoded request is missing top-level key %d", key)
		}
	}

	var rpID string
	if err := cbor.Unmarshal(generic[1], &rpID); err != nil || rpID != "gokeys" {
		t.Errorf("key 1 (rpId) = %q, %v, want %q, nil", rpID, err, "gokeys")
	}

	var extensions map[string]cbor.RawMessage
	if err := cbor.Unmarshal(generic[4], &extensions); err != nil {
		t.Fatalf("decoding key 4 (extensions): %v", err)
	}
	var hmacExt map[int]cbor.RawMessage
	if err := cbor.Unmarshal(extensions["hmac-secret"], &hmacExt); err != nil {
		t.Fatalf("decoding hmac-secret extension: %v", err)
	}
	for _, key := range []int{1, 2, 3, 4} {
		if _, ok := hmacExt[key]; !ok {
			t.Errorf("hmac-secret extension is missing key %d", key)
		}
	}
}
