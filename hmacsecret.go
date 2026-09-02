// Package hmacsecret derives a symmetric secret from a FIDO2 security
// key's CTAP2 hmac-secret extension: enroll a new non-discoverable
// credential once (Enroll), then re-derive the same secret from it any
// number of times (GetSecret), given the credential ID, a salt, and (if
// the authenticator has a PIN set) the PIN. This is the same mechanism
// tools like age-plugin-fido2-hmac use for FIDO2-backed file encryption.
//
// It talks to the authenticator end to end: discovering it over package
// hid, negotiating a PIN via package ctap2 if the device requires one,
// and performing the CTAP2 hmac-secret extension round trip - no cgo, no
// external process, no third-party FIDO2/CTAP2 library.
package hmacsecret

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/tpyle/gohmacsecret/ctap2"
	"github.com/tpyle/gohmacsecret/hid"
)

// ErrUnsupportedPlatform is hid.ErrUnsupportedPlatform, re-exported so
// callers can errors.Is against it without importing package hid
// themselves.
var ErrUnsupportedPlatform = hid.ErrUnsupportedPlatform

// clientDataHash stands in for the "origin" a browser-based CTAP2 client
// would normally bind - meaningless for a native client talking raw
// CTAPHID, but CTAP2 still requires one. Versioned so a deliberate future
// protocol change can be distinguished from this one.
var clientDataHash = sha256.Sum256([]byte("gohmacsecret client data v1"))

// PINPrompt reads a FIDO2 PIN from the user, given the prompt text to
// show. The default implementation reads from the terminal without echo,
// or a plain line when stdin isn't a terminal. Override it to integrate
// with your own terminal/GUI/test harness.
var PINPrompt = defaultPINPrompt

// OnTouchRequired is called at most once per Enroll/GetSecret call, when
// the authenticator signals it's waiting for a physical touch. The
// default prints "Touch your security key now..." to stderr; override to
// suppress or redirect that narration.
var OnTouchRequired = defaultOnTouchRequired

func defaultOnTouchRequired() {
	fmt.Fprintln(os.Stderr, "Touch your security key now...")
}

// discoverDevices lists connected FIDO HID devices - a package-level
// swappable var (mirrors PINPrompt) so discoverOne's device-count
// handling can be tested without real hardware.
var discoverDevices = hid.Discover

// authenticatorClient is the subset of *ctap2.Client's behavior this
// package's orchestration logic depends on. Defined here, rather than
// using *ctap2.Client directly, so tests can substitute a fake instead
// of a real (or simulated) CTAPHID transport - package ctap2 already
// owns verifying that *ctap2.Client itself satisfies this correctly.
type authenticatorClient interface {
	GetInfo() (*ctap2.Info, error)
	GetPINToken(pin string, permission int, rpID string) ([]byte, error)
	MakeCredential(rpID string, clientDataHash, pinToken []byte) ([]byte, error)
	GetAssertion(rpID string, clientDataHash, credentialID, salt, pinToken []byte) ([]byte, error)
}

// connectFunc discovers exactly one connected authenticator and returns
// a live connection to it - a package-level swappable var (mirrors
// discoverDevices) so Enroll/GetSecret's own orchestration logic
// (capability checks, PIN handling, caching) can be tested against a
// fake client without a real device or hid.Device at all.
var connectFunc = connectReal

// connectReal is connectFunc's real implementation: discover, open, and
// allocate a CTAPHID channel on the one connected FIDO device, narrating
// via OnTouchRequired once the device signals it's waiting for a touch.
func connectReal() (authenticatorClient, io.Closer, error) {
	info, err := discoverOne()
	if err != nil {
		return nil, nil, err
	}
	dev, err := hid.Open(info)
	if err != nil {
		return nil, nil, err
	}
	client, err := ctap2.NewClient(dev)
	if err != nil {
		dev.Close() //nolint:errcheck // we're already returning the more useful NewClient error; a close failure on top of that isn't actionable
		return nil, nil, fmt.Errorf("connecting to your security key: %w", err)
	}
	touched := false
	client.OnKeepAlive = func(status byte) {
		if status == 0x02 && !touched { // "user presence needed"
			touched = true
			OnTouchRequired()
		}
	}
	return client, dev, nil
}

// discoverOne returns the single connected FIDO HID device, or an error
// naming what was found instead if there isn't exactly one - this
// package doesn't build a picker for multiple simultaneously-connected
// keys.
func discoverOne() (hid.Info, error) {
	infos, err := discoverDevices()
	if err != nil {
		return hid.Info{}, fmt.Errorf("looking for a security key: %w", err)
	}
	switch len(infos) {
	case 0:
		return hid.Info{}, fmt.Errorf("no FIDO2 security key found - plug one in and try again")
	case 1:
		return infos[0], nil
	default:
		names := make([]string, len(infos))
		for i, info := range infos {
			names[i] = describeDevice(info)
		}
		return hid.Info{}, fmt.Errorf("found %d FIDO2 security keys (%s) - unplug all but the one you want to use and try again", len(infos), strings.Join(names, ", "))
	}
}

func describeDevice(info hid.Info) string {
	if info.Product != "" {
		return info.Product
	}
	return fmt.Sprintf("VID:PID %04x:%04x", info.VendorID, info.ProductID)
}

func checkSupport(info *ctap2.Info) error {
	if !info.SupportsHMACSecret() {
		return fmt.Errorf("this security key doesn't support the hmac-secret extension")
	}
	if info.PINSet && !info.SupportsPINProtocolTwo() {
		return fmt.Errorf("this security key only supports an older PIN protocol that isn't implemented")
	}
	return nil
}

// tokenKey scopes a cached pinUvAuthToken to the rpID it was obtained
// for - required because a token minted with one rpID is rejected by the
// authenticator for any other, and unlike a single fixed-RP-ID
// application, this package's callers may legitimately use more than one
// rpID in the same process.
type tokenKey struct {
	rpID       string
	permission int
}

// session caches one connected authenticator (and any PIN tokens
// obtained from it) for the remainder of the process, so a caller trying
// more than one credential (e.g. across several enrolled keys) isn't
// re-prompted for a PIN, or asked to re-authenticate a fresh connection,
// once per attempt. A wrong credential ID against the same cached
// connection still fails fast with no extra touch prompt - see
// ctap2.Client.GetAssertion's doc comment - so caching here only removes
// redundant PIN prompts, not redundant touches.
var session struct {
	client authenticatorClient
	closer io.Closer
	info   *ctap2.Info
	tokens map[tokenKey][]byte
}

func getSession() (authenticatorClient, *ctap2.Info, error) {
	if session.client != nil {
		return session.client, session.info, nil
	}
	client, closer, err := connectFunc()
	if err != nil {
		return nil, nil, err
	}
	info, err := client.GetInfo()
	if err != nil {
		closer.Close() //nolint:errcheck // we're already returning the more useful GetInfo error
		return nil, nil, fmt.Errorf("reading your security key's capabilities: %w", err)
	}
	if err := checkSupport(info); err != nil {
		closer.Close() //nolint:errcheck // returning checkSupport's error instead
		return nil, nil, err
	}
	session.client, session.closer, session.info = client, closer, info
	session.tokens = map[tokenKey][]byte{}
	return client, info, nil
}

// sessionPINToken returns a cached pinUvAuthToken for (rpID, permission)
// if one was already obtained this session, prompting for the PIN and
// fetching a fresh one otherwise. Returns (nil, nil) - not an error - if
// info reports no PIN is set, since MakeCredential/GetAssertion both
// accept a nil token to mean exactly that.
func sessionPINToken(client authenticatorClient, info *ctap2.Info, rpID string, permission int) ([]byte, error) {
	if !info.PINSet {
		return nil, nil
	}
	key := tokenKey{rpID: rpID, permission: permission}
	if token, ok := session.tokens[key]; ok {
		return token, nil
	}
	pin, err := PINPrompt("Security key PIN: ")
	if err != nil {
		return nil, fmt.Errorf("reading your security key's PIN: %w", err)
	}
	token, err := client.GetPINToken(pin, permission, rpID)
	if err != nil {
		return nil, err
	}
	session.tokens[key] = token
	return token, nil
}

// Enroll discovers the one connected FIDO2 authenticator, confirms it
// supports the hmac-secret extension, and creates a new non-discoverable
// credential on it scoped to rpID - the credential ID GetSecret needs to
// later re-derive the same secret.
func Enroll(rpID string) ([]byte, error) {
	client, info, err := getSession()
	if err != nil {
		return nil, err
	}
	token, err := sessionPINToken(client, info, rpID, ctap2.PermissionMakeCredential)
	if err != nil {
		return nil, err
	}
	credID, err := client.MakeCredential(rpID, clientDataHash[:], token)
	if err != nil {
		return nil, fmt.Errorf("enrolling your security key: %w", err)
	}
	return credID, nil
}

// GetSecret returns the hmac-secret extension's derived secret for
// credentialID and salt, using a credential previously created by
// Enroll(rpID, ...) - rpID must be byte-identical to what Enroll was
// called with for this credential.
func GetSecret(rpID string, credentialID, salt []byte) ([]byte, error) {
	client, info, err := getSession()
	if err != nil {
		return nil, err
	}
	token, err := sessionPINToken(client, info, rpID, ctap2.PermissionGetAssertion)
	if err != nil {
		return nil, err
	}
	secret, err := client.GetAssertion(rpID, clientDataHash[:], credentialID, salt, token)
	if err != nil {
		return nil, fmt.Errorf("unlocking with your security key: %w", err)
	}
	return secret, nil
}
