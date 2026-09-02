package ctap2

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// Permission bits for a pinUvAuthToken (see GetPINToken) - the CTAP2
// spec's "permissions" bitfield, restricting what the resulting token
// can authorize. Combine bits with | to request one token valid for
// more than one operation.
const (
	PermissionMakeCredential = 0x01
	PermissionGetAssertion   = 0x02
)

// hmacSecretSaltLen is the salt length the hmac-secret extension
// requires (see GetAssertion) - always exactly 32 bytes for a single
// salt (a second, optional 32-byte salt exists in the spec for rotating
// between two secrets; gokeys never uses it).
const hmacSecretSaltLen = 32

// clientPIN subcommand values (authenticatorClientPIN's subCommand
// parameter) - gokeys only ever needs these two.
const (
	clientPINSubCmdGetKeyAgreement = 0x02
	clientPINSubCmdGetPINToken     = 0x09
)

type clientPINRequest struct {
	PINProtocol    int      `cbor:"1,keyasint,omitempty"`
	SubCommand     int      `cbor:"2,keyasint"`
	KeyAgreement   *coseKey `cbor:"3,keyasint,omitempty"`
	PINUvAuthParam []byte   `cbor:"4,keyasint,omitempty"`
	PINHashEnc     []byte   `cbor:"6,keyasint,omitempty"`
	Permissions    int      `cbor:"9,keyasint,omitempty"`
	RPID           string   `cbor:"10,keyasint,omitempty"`
}

type clientPINResponse struct {
	KeyAgreement   *coseKey `cbor:"1,keyasint,omitempty"`
	PINUvAuthToken []byte   `cbor:"2,keyasint,omitempty"`
}

// getKeyAgreement fetches the authenticator's current ECDH public key
// (authenticatorClientPIN's getKeyAgreement subcommand) - the first step
// of every PIN/UV Auth Protocol Two operation.
func (c *Client) getKeyAgreement() (coseKey, error) {
	resp, err := c.sendCBOR(ctapClientPIN, clientPINRequest{
		PINProtocol: pinProtocol,
		SubCommand:  clientPINSubCmdGetKeyAgreement,
	})
	if err != nil {
		return coseKey{}, fmt.Errorf("getKeyAgreement: %w", err)
	}
	var r clientPINResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		return coseKey{}, fmt.Errorf("getKeyAgreement: decoding response: %w", err)
	}
	if r.KeyAgreement == nil {
		return coseKey{}, fmt.Errorf("getKeyAgreement: response didn't include a key")
	}
	return *r.KeyAgreement, nil
}

// keyAgreement performs one full PIN/UV Auth Protocol Two key-agreement
// round trip: fetch the authenticator's current public key, generate a
// fresh local ephemeral key pair, and derive the shared secret. This is
// the shared first step behind GetPINToken and the hmac-secret
// extension in GetAssertion - each needs its own independent shared
// secret, so this is called once per use, never cached.
func (c *Client) keyAgreement() (local coseKey, sharedSecret []byte, err error) {
	peer, err := c.getKeyAgreement()
	if err != nil {
		return coseKey{}, nil, err
	}
	kp, err := generateECDHKeyPair()
	if err != nil {
		return coseKey{}, nil, fmt.Errorf("generating an ephemeral key pair: %w", err)
	}
	secret, err := kp.sharedSecret(peer)
	if err != nil {
		return coseKey{}, nil, err
	}
	return kp.publicCOSEKey(), secret, nil
}

// GetPINToken exchanges pin for a pinUvAuthToken scoped to permission
// and, if rpID is non-empty, further scoped to that relying party - the
// token MakeCredential/GetAssertion then authenticate their request
// with (see pinAuthenticate). Callers must first confirm the
// authenticator actually has a PIN set (Info.PINSet) - calling this
// otherwise fails with a CTAP2 error asking for one to be set first.
func (c *Client) GetPINToken(pin string, permission int, rpID string) ([]byte, error) {
	local, sharedSecret, err := c.keyAgreement()
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetPINToken: %w", err)
	}
	pinHash := sha256.Sum256([]byte(pin))
	pinHashEnc, err := pinEncrypt(sharedSecret, pinHash[:16])
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetPINToken: encrypting PIN hash: %w", err)
	}

	resp, err := c.sendCBOR(ctapClientPIN, clientPINRequest{
		PINProtocol:  pinProtocol,
		SubCommand:   clientPINSubCmdGetPINToken,
		KeyAgreement: &local,
		PINHashEnc:   pinHashEnc,
		Permissions:  permission,
		RPID:         rpID,
	})
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetPINToken: %w", err)
	}
	var r clientPINResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("ctap2: GetPINToken: decoding response: %w", err)
	}
	token, err := pinDecrypt(sharedSecret, r.PINUvAuthToken)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetPINToken: decrypting token: %w", err)
	}
	if len(token) != 32 {
		return nil, fmt.Errorf("ctap2: GetPINToken: token is %d bytes, want 32", len(token))
	}
	return token, nil
}

// Info is the subset of authenticatorGetInfo's response gokeys acts on.
type Info struct {
	// Extensions lists the CTAP2 extension identifiers this
	// authenticator supports - gokeys requires "hmac-secret" (see
	// SupportsHMACSecret) before attempting anything else.
	Extensions []string
	// ClientPIN reports whether the authenticator has ClientPIN
	// functionality at all, regardless of whether a PIN is currently
	// set - see PINSet.
	ClientPIN bool
	// PINSet reports whether a PIN is currently configured. GetPINToken
	// must only be called when this is true.
	PINSet bool
	// PINProtocols lists the PIN/UV Auth Protocol version numbers this
	// authenticator supports - see SupportsPINProtocolTwo.
	PINProtocols []int
}

// SupportsHMACSecret reports whether info lists the hmac-secret
// extension.
func (info *Info) SupportsHMACSecret() bool {
	for _, e := range info.Extensions {
		if e == "hmac-secret" {
			return true
		}
	}
	return false
}

// SupportsPINProtocolTwo reports whether info lists PIN/UV Auth Protocol
// Two among its supported protocols.
func (info *Info) SupportsPINProtocolTwo() bool {
	for _, p := range info.PINProtocols {
		if p == pinProtocol {
			return true
		}
	}
	return false
}

type getInfoResponse struct {
	Extensions   []string        `cbor:"2,keyasint,omitempty"`
	Options      map[string]bool `cbor:"4,keyasint,omitempty"`
	PINProtocols []int           `cbor:"6,keyasint,omitempty"`
}

// GetInfo sends authenticatorGetInfo and returns the fields gokeys acts
// on.
func (c *Client) GetInfo() (*Info, error) {
	resp, err := c.sendCBOR(ctapGetInfo, nil)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetInfo: %w", err)
	}
	var r getInfoResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("ctap2: GetInfo: decoding response: %w", err)
	}
	// The "clientPin" option's mere PRESENCE (regardless of its value)
	// means ClientPIN is supported at all; its value then says whether a
	// PIN is actually set - a missing key means no ClientPIN support and
	// PINSet is meaningless.
	pinSet, hasClientPIN := r.Options["clientPin"]
	return &Info{
		Extensions:   r.Extensions,
		ClientPIN:    hasClientPIN,
		PINSet:       hasClientPIN && pinSet,
		PINProtocols: r.PINProtocols,
	}, nil
}

type rpEntity struct {
	ID string `cbor:"id"`
}

type userEntity struct {
	ID          []byte `cbor:"id"`
	Name        string `cbor:"name,omitempty"`
	DisplayName string `cbor:"displayName,omitempty"`
}

type pubKeyCredParam struct {
	Alg  int    `cbor:"alg"`
	Type string `cbor:"type"`
}

type credentialDescriptor struct {
	ID   []byte `cbor:"id"`
	Type string `cbor:"type"`
}

type makeCredentialRequest struct {
	ClientDataHash    []byte            `cbor:"1,keyasint"`
	RP                rpEntity          `cbor:"2,keyasint"`
	User              userEntity        `cbor:"3,keyasint"`
	PubKeyCredParams  []pubKeyCredParam `cbor:"4,keyasint"`
	Extensions        map[string]any    `cbor:"6,keyasint,omitempty"`
	Options           map[string]bool   `cbor:"7,keyasint,omitempty"`
	PINUvAuthParam    []byte            `cbor:"8,keyasint,omitempty"`
	PINUvAuthProtocol int               `cbor:"9,keyasint,omitempty"`
}

type makeCredentialResponse struct {
	AuthData []byte `cbor:"2,keyasint"`
}

// gokeysUserID is a fixed, non-secret placeholder user handle. CTAP2
// requires a non-empty user.id for authenticatorMakeCredential, but
// gokeys never creates a discoverable/resident credential (see the "rk"
// option in MakeCredential), so nothing ever reads this back to
// identify an account - there's no real "user" to name.
var gokeysUserID = []byte("gokeys")

// MakeCredential enrolls a new, non-discoverable, hmac-secret-capable
// credential scoped to rpID and returns its opaque credential ID for
// later use with GetAssertion. pinToken must be non-nil if and only if
// the authenticator has a PIN set (see Info.PINSet); it authenticates
// the request via pinUvAuthParam (see pinAuthenticate).
func (c *Client) MakeCredential(rpID string, clientDataHash []byte, pinToken []byte) ([]byte, error) {
	req := makeCredentialRequest{
		ClientDataHash:   clientDataHash,
		RP:               rpEntity{ID: rpID},
		User:             userEntity{ID: gokeysUserID, Name: "gokeys", DisplayName: "gokeys"},
		PubKeyCredParams: []pubKeyCredParam{{Alg: -7, Type: "public-key"}}, // ES256; the resulting key is never used to sign anything
		Extensions:       map[string]any{"hmac-secret": true},
		Options:          map[string]bool{"rk": false}, // explicitly non-discoverable/non-resident
	}
	if pinToken != nil {
		req.PINUvAuthParam = pinAuthenticate(pinToken, clientDataHash)
		req.PINUvAuthProtocol = pinProtocol
	}

	resp, err := c.sendCBOR(ctapMakeCredential, req)
	if err != nil {
		return nil, fmt.Errorf("ctap2: MakeCredential: %w", err)
	}
	var r makeCredentialResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("ctap2: MakeCredential: decoding response: %w", err)
	}
	ad, err := parseAuthData(r.AuthData)
	if err != nil {
		return nil, fmt.Errorf("ctap2: MakeCredential: %w", err)
	}
	if ad.credentialID == nil {
		return nil, fmt.Errorf("ctap2: MakeCredential: response didn't include a credential")
	}
	return ad.credentialID, nil
}

type hmacSecretInput struct {
	KeyAgreement      coseKey `cbor:"1,keyasint"`
	SaltEnc           []byte  `cbor:"2,keyasint"`
	SaltAuth          []byte  `cbor:"3,keyasint"`
	PINUvAuthProtocol int     `cbor:"4,keyasint"`
}

type getAssertionRequest struct {
	RPID              string                 `cbor:"1,keyasint"`
	ClientDataHash    []byte                 `cbor:"2,keyasint"`
	AllowList         []credentialDescriptor `cbor:"3,keyasint,omitempty"`
	Extensions        map[string]any         `cbor:"4,keyasint,omitempty"`
	PINUvAuthParam    []byte                 `cbor:"6,keyasint,omitempty"`
	PINUvAuthProtocol int                    `cbor:"7,keyasint,omitempty"`
}

type getAssertionResponse struct {
	AuthData []byte `cbor:"2,keyasint"`
}

// GetAssertion requests the hmac-secret extension's derived secret for
// credentialID (as returned by an earlier MakeCredential): it performs
// its own independent PIN/UV Auth Protocol Two key agreement to encrypt
// salt and decrypt the authenticator's response (this is entirely
// separate from pinToken/pinUvAuthParam, which merely authenticates
// *that a request may proceed at all* - the hmac-secret round trip has
// its own, unrelated confidentiality layer), and returns the resulting
// ~32-byte secret. salt must be exactly 32 bytes. pinToken must be
// non-nil if and only if the authenticator has a PIN set.
func (c *Client) GetAssertion(rpID string, clientDataHash, credentialID, salt, pinToken []byte) ([]byte, error) {
	if len(salt) != hmacSecretSaltLen {
		return nil, fmt.Errorf("ctap2: GetAssertion: salt must be %d bytes, got %d", hmacSecretSaltLen, len(salt))
	}
	local, sharedSecret, err := c.keyAgreement()
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: %w", err)
	}
	saltEnc, err := pinEncrypt(sharedSecret, salt)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: encrypting salt: %w", err)
	}
	saltAuth := pinAuthenticate(sharedSecret, saltEnc)

	req := getAssertionRequest{
		RPID:           rpID,
		ClientDataHash: clientDataHash,
		AllowList:      []credentialDescriptor{{ID: credentialID, Type: "public-key"}},
		Extensions: map[string]any{
			"hmac-secret": hmacSecretInput{
				KeyAgreement:      local,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PINUvAuthProtocol: pinProtocol,
			},
		},
	}
	if pinToken != nil {
		req.PINUvAuthParam = pinAuthenticate(pinToken, clientDataHash)
		req.PINUvAuthProtocol = pinProtocol
	}

	resp, err := c.sendCBOR(ctapGetAssertion, req)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: %w", err)
	}
	var r getAssertionResponse
	if err := cbor.Unmarshal(resp, &r); err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: decoding response: %w", err)
	}
	ad, err := parseAuthData(r.AuthData)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: %w", err)
	}
	rawOutput, ok := ad.extensions["hmac-secret"]
	if !ok {
		return nil, fmt.Errorf("ctap2: GetAssertion: response didn't include an hmac-secret output")
	}
	var encOutput []byte
	if err := cbor.Unmarshal(rawOutput, &encOutput); err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: decoding hmac-secret output: %w", err)
	}
	secret, err := pinDecrypt(sharedSecret, encOutput)
	if err != nil {
		return nil, fmt.Errorf("ctap2: GetAssertion: decrypting hmac-secret output: %w", err)
	}
	return secret, nil
}
