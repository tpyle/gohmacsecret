package ctap2

import (
	"bytes"
	"testing"
)

func mustKeyPair(t *testing.T) *ecdhKeyPair {
	t.Helper()
	kp, err := generateECDHKeyPair()
	if err != nil {
		t.Fatalf("generateECDHKeyPair: %v", err)
	}
	return kp
}

func TestSharedSecretAgreesBothWays(t *testing.T) {
	a := mustKeyPair(t)
	b := mustKeyPair(t)

	secretFromA, err := a.sharedSecret(b.publicCOSEKey())
	if err != nil {
		t.Fatalf("a.sharedSecret: %v", err)
	}
	secretFromB, err := b.sharedSecret(a.publicCOSEKey())
	if err != nil {
		t.Fatalf("b.sharedSecret: %v", err)
	}
	if !bytes.Equal(secretFromA, secretFromB) {
		t.Fatalf("shared secrets disagree: %x vs %x", secretFromA, secretFromB)
	}
	if len(secretFromA) != 64 {
		t.Fatalf("shared secret is %d bytes, want 64 (32 HMAC key + 32 AES key)", len(secretFromA))
	}
}

func TestSharedSecretRejectsWrongCurve(t *testing.T) {
	a := mustKeyPair(t)
	bad := a.publicCOSEKey()
	bad.Crv = 2 // not P-256
	if _, err := a.sharedSecret(bad); err == nil {
		t.Fatal("expected an error for a non-P-256 key-agreement key, got nil")
	}
}

func TestPinEncryptDecryptRoundTrip(t *testing.T) {
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}
	plaintext := bytes.Repeat([]byte{0x42}, 32)

	ciphertext, err := pinEncrypt(secret, plaintext)
	if err != nil {
		t.Fatalf("pinEncrypt: %v", err)
	}
	if len(ciphertext) != 16+len(plaintext) {
		t.Fatalf("ciphertext is %d bytes, want %d (16-byte IV + plaintext)", len(ciphertext), 16+len(plaintext))
	}

	decrypted, err := pinDecrypt(secret, ciphertext)
	if err != nil {
		t.Fatalf("pinDecrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted = %x, want %x", decrypted, plaintext)
	}
}

func TestPinEncryptTwoCallsDifferByIV(t *testing.T) {
	secret := make([]byte, 64)
	plaintext := bytes.Repeat([]byte{0x01}, 16)

	c1, err := pinEncrypt(secret, plaintext)
	if err != nil {
		t.Fatalf("pinEncrypt: %v", err)
	}
	c2, err := pinEncrypt(secret, plaintext)
	if err != nil {
		t.Fatalf("pinEncrypt: %v", err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("two encryptions of the same plaintext produced identical ciphertext - IV isn't being randomized")
	}
}

func TestPinEncryptRejectsBadLength(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := pinEncrypt(secret, []byte("not a multiple of 16")); err == nil {
		t.Fatal("expected an error for a non-block-aligned plaintext, got nil")
	}
	if _, err := pinEncrypt(secret, nil); err == nil {
		t.Fatal("expected an error for empty plaintext, got nil")
	}
}

func TestPinDecryptRejectsBadLength(t *testing.T) {
	secret := make([]byte, 64)
	if _, err := pinDecrypt(secret, make([]byte, 8)); err == nil {
		t.Fatal("expected an error for data shorter than one IV, got nil")
	}
	if _, err := pinDecrypt(secret, make([]byte, 16+5)); err == nil {
		t.Fatal("expected an error for a non-block-aligned ciphertext, got nil")
	}
}

func TestPinAuthenticateIsDeterministicAndKeyed(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x01}, 64)
	key2 := bytes.Repeat([]byte{0x02}, 64)
	msg := []byte("clientDataHash goes here, 32 bytes worth")

	mac1a := pinAuthenticate(key1, msg)
	mac1b := pinAuthenticate(key1, msg)
	if !bytes.Equal(mac1a, mac1b) {
		t.Fatal("pinAuthenticate isn't deterministic for the same key/message")
	}
	if len(mac1a) != 32 {
		t.Fatalf("pinAuthenticate produced %d bytes, want 32 (untruncated HMAC-SHA256)", len(mac1a))
	}

	mac2 := pinAuthenticate(key2, msg)
	if bytes.Equal(mac1a, mac2) {
		t.Fatal("pinAuthenticate produced the same MAC for two different keys")
	}

	// A bare 32-byte pinUvAuthToken must work directly as the key, since
	// GetPINToken/MakeCredential/GetAssertion all call pinAuthenticate
	// with one in place of a full 64-byte shared secret.
	token := bytes.Repeat([]byte{0x03}, 32)
	if mac := pinAuthenticate(token, msg); len(mac) != 32 {
		t.Fatalf("pinAuthenticate with a 32-byte token produced %d bytes, want 32", len(mac))
	}
}

func TestKDFProtocolTwoSplitsHMACAndAESKeys(t *testing.T) {
	z := bytes.Repeat([]byte{0xAB}, 32)
	secret, err := kdfProtocolTwo(z)
	if err != nil {
		t.Fatalf("kdfProtocolTwo: %v", err)
	}
	if len(secret) != 64 {
		t.Fatalf("kdfProtocolTwo produced %d bytes, want 64", len(secret))
	}
	if bytes.Equal(secret[:32], secret[32:]) {
		t.Fatal("HMAC key and AES key halves are identical - info-string domain separation isn't working")
	}

	// Deterministic: the same input always derives the same output.
	secret2, err := kdfProtocolTwo(z)
	if err != nil {
		t.Fatalf("kdfProtocolTwo: %v", err)
	}
	if !bytes.Equal(secret, secret2) {
		t.Fatal("kdfProtocolTwo isn't deterministic for the same input")
	}
}
