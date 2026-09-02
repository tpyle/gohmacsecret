package ctap2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// pinProtocol identifies which CTAP2 PIN/UV Auth Protocol gokeys speaks
// on the wire. Only Two is implemented - see AGENTS.md for why One,
// needed only by older authenticator firmware, is out of scope.
const pinProtocol = 2

// coseKey is the small subset of a COSE_Key map gokeys needs: an
// uncompressed NIST P-256 public key, as used for CTAP2's ECDH key
// agreement (see keyAgreement in the ClientPIN command and the
// hmac-secret extension). Field tags are COSE's standard integer labels.
type coseKey struct {
	Kty int    `cbor:"1,keyasint"`
	Alg int    `cbor:"3,keyasint,omitempty"`
	Crv int    `cbor:"-1,keyasint,omitempty"`
	X   []byte `cbor:"-2,keyasint,omitempty"`
	Y   []byte `cbor:"-3,keyasint,omitempty"`
}

// COSE registry values CTAP2 expects for an EC2/P-256 key-agreement key.
// The algorithm value is fixed at -25 (ECDH-ES + HKDF-256) regardless of
// which PIN/UV Auth Protocol is actually in use - the CTAP2 spec calls
// this out explicitly as a quirk ("although this is NOT the algorithm
// actually used"), and every reference implementation sends it
// unconditionally.
const (
	coseKeyTypeEC2         = 2
	coseCurveP256          = 1
	coseAlgECDHES256KDF256 = -25
)

// ecdhKeyPair is an ephemeral P-256 key pair generated fresh for each
// key-agreement round trip - CTAP2 never reuses one across requests.
type ecdhKeyPair struct {
	private *ecdh.PrivateKey
}

func generateECDHKeyPair() (*ecdhKeyPair, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdhKeyPair{private: priv}, nil
}

// publicCOSEKey encodes the key pair's public half as the COSE map CTAP2
// expects on the wire.
func (kp *ecdhKeyPair) publicCOSEKey() coseKey {
	raw := kp.private.PublicKey().Bytes() // uncompressed SEC1: 0x04 || X || Y
	return coseKey{
		Kty: coseKeyTypeEC2,
		Alg: coseAlgECDHES256KDF256,
		Crv: coseCurveP256,
		X:   append([]byte(nil), raw[1:33]...),
		Y:   append([]byte(nil), raw[33:65]...),
	}
}

// sharedSecret performs ECDH against peer (the authenticator's public
// key, as returned by ClientPIN's getKeyAgreement subcommand) and
// derives the PIN/UV Auth Protocol Two shared secret via kdfProtocolTwo.
func (kp *ecdhKeyPair) sharedSecret(peer coseKey) ([]byte, error) {
	if peer.Kty != coseKeyTypeEC2 || peer.Crv != coseCurveP256 || len(peer.X) != 32 || len(peer.Y) != 32 {
		return nil, fmt.Errorf("ctap2: unsupported or malformed key-agreement key")
	}
	peerBytes := make([]byte, 0, 65)
	peerBytes = append(peerBytes, 0x04)
	peerBytes = append(peerBytes, peer.X...)
	peerBytes = append(peerBytes, peer.Y...)
	peerKey, err := ecdh.P256().NewPublicKey(peerBytes)
	if err != nil {
		return nil, fmt.Errorf("ctap2: invalid authenticator key-agreement key: %w", err)
	}
	z, err := kp.private.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ctap2: ECDH key agreement failed: %w", err)
	}
	return kdfProtocolTwo(z)
}

// hkdfSalt, hkdfInfoHMAC and hkdfInfoAES are PIN/UV Auth Protocol Two's
// fixed HKDF-SHA256 parameters for deriving its two keys from a raw ECDH
// shared secret - see kdfProtocolTwo.
var (
	hkdfSalt     = make([]byte, 32) // 32 zero bytes, per the CTAP2 spec
	hkdfInfoHMAC = []byte("CTAP2 HMAC key")
	hkdfInfoAES  = []byte("CTAP2 AES key")
)

// kdfProtocolTwo derives PIN/UV Auth Protocol Two's 64-byte shared
// secret from a raw ECDH shared secret z: 32 bytes of HMAC key followed
// by 32 bytes of AES key, each independently derived via HKDF-SHA256
// with a 32-byte all-zero salt and a fixed, protocol-specific info
// string - see pinAuthenticate/pinEncrypt/pinDecrypt for how each half
// is used.
func kdfProtocolTwo(z []byte) ([]byte, error) {
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, z, hkdfSalt, hkdfInfoHMAC), hmacKey); err != nil {
		return nil, err
	}
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, z, hkdfSalt, hkdfInfoAES), aesKey); err != nil {
		return nil, err
	}
	return append(hmacKey, aesKey...), nil
}

// pinEncrypt implements PIN/UV Auth Protocol Two's encrypt(): AES-256-CBC
// under sharedSecret's AES half (its last 32 bytes), with a fresh random
// IV prepended to the ciphertext. plaintext's length must already be a
// multiple of the AES block size - every plaintext gokeys ever encrypts
// this way (a 16-byte PIN hash, a 32-byte hmac-secret salt) already is.
func pinEncrypt(sharedSecret, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ctap2: plaintext length %d isn't a positive multiple of the AES block size", len(plaintext))
	}
	block, err := aes.NewCipher(sharedSecret[32:])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return append(iv, ciphertext...), nil
}

// pinDecrypt reverses pinEncrypt.
func pinDecrypt(sharedSecret, data []byte) ([]byte, error) {
	if len(data) <= aes.BlockSize || (len(data)-aes.BlockSize)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ctap2: malformed encrypted data (%d bytes)", len(data))
	}
	block, err := aes.NewCipher(sharedSecret[32:])
	if err != nil {
		return nil, err
	}
	iv, ciphertext := data[:aes.BlockSize], data[aes.BlockSize:]
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext, nil
}

// pinAuthenticate implements PIN/UV Auth Protocol Two's authenticate():
// full, untruncated HMAC-SHA256 keyed by key's first 32 bytes (the HMAC
// half of a shared secret - or, when key is itself a 32-byte
// pinUvAuthToken rather than a full 64-byte shared secret, the whole of
// it, which is exactly what CTAP2's pinUvAuthParam computation needs).
func pinAuthenticate(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key[:32])
	mac.Write(message) //nolint:errcheck // hash.Hash.Write never returns an error
	return mac.Sum(nil)
}
