package hmacsecret

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/tpyle/gohmacsecret/ctap2"
	"github.com/tpyle/gohmacsecret/hid"
)

const testRPID = "example-rp"

type fakeClient struct {
	info    *ctap2.Info
	infoErr error

	pinToken      []byte
	pinTokenErr   error
	pinTokenCalls int

	credID      []byte
	makeCredErr error

	secret          []byte
	getAssertionErr error

	lastPINToken []byte // whatever MakeCredential/GetAssertion was last called with
}

func (f *fakeClient) GetInfo() (*ctap2.Info, error) { return f.info, f.infoErr }

func (f *fakeClient) GetPINToken(pin string, _ int, rpID string) ([]byte, error) {
	f.pinTokenCalls++
	if f.pinTokenErr != nil {
		return nil, f.pinTokenErr
	}
	if f.pinToken != nil {
		return f.pinToken, nil
	}
	// Distinguish tokens per (pin, rpID) when a test doesn't set a fixed
	// pinToken, so cache-scoping tests can tell tokens apart.
	return []byte(fmt.Sprintf("token(%s,%s)", pin, rpID)), nil
}

func (f *fakeClient) MakeCredential(_ string, _, pinToken []byte) ([]byte, error) {
	f.lastPINToken = pinToken
	return f.credID, f.makeCredErr
}

func (f *fakeClient) GetAssertion(_ string, _, _, _, pinToken []byte) ([]byte, error) {
	f.lastPINToken = pinToken
	return f.secret, f.getAssertionErr
}

type fakeCloser struct{ closed bool }

func (c *fakeCloser) Close() error { c.closed = true; return nil }

func noPINInfo() *ctap2.Info {
	return &ctap2.Info{Extensions: []string{"hmac-secret"}, PINProtocols: []int{2}}
}

func pinSetInfo() *ctap2.Info {
	return &ctap2.Info{Extensions: []string{"hmac-secret"}, ClientPIN: true, PINSet: true, PINProtocols: []int{2}}
}

// withFakeSession points connectFunc/discoverDevices/PINPrompt at fakes
// for the duration of one test, resetting the package-level session cache
// first and restoring everything (including whatever the session cache
// ends up holding) afterward - required because getSession/session are
// shared package state, not per-call arguments.
func withFakeSession(t *testing.T, connect func() (authenticatorClient, io.Closer, error)) {
	t.Helper()
	origConnect, origDiscover, origPIN, origSession := connectFunc, discoverDevices, PINPrompt, session
	t.Cleanup(func() {
		connectFunc, discoverDevices, PINPrompt = origConnect, origDiscover, origPIN
		session = origSession
	})
	session = struct {
		client authenticatorClient
		closer io.Closer
		info   *ctap2.Info
		tokens map[tokenKey][]byte
	}{}
	connectFunc = connect
}

func TestDiscoverOneNoDevices(t *testing.T) {
	orig := discoverDevices
	defer func() { discoverDevices = orig }()
	discoverDevices = func() ([]hid.Info, error) { return nil, nil }

	if _, err := discoverOne(); err == nil {
		t.Fatal("expected an error when no devices are found, got nil")
	}
}

func TestDiscoverOneSingleDevice(t *testing.T) {
	orig := discoverDevices
	defer func() { discoverDevices = orig }()
	want := hid.Info{Path: "/dev/hidraw0", Product: "Test Key"}
	discoverDevices = func() ([]hid.Info, error) { return []hid.Info{want}, nil }

	got, err := discoverOne()
	if err != nil {
		t.Fatalf("discoverOne: %v", err)
	}
	if got != want {
		t.Errorf("discoverOne() = %+v, want %+v", got, want)
	}
}

func TestDiscoverOneMultipleDevicesNamesThemInError(t *testing.T) {
	orig := discoverDevices
	defer func() { discoverDevices = orig }()
	discoverDevices = func() ([]hid.Info, error) {
		return []hid.Info{{Product: "Key A"}, {VendorID: 0x1234, ProductID: 0x5678}}, nil
	}

	_, err := discoverOne()
	if err == nil {
		t.Fatal("expected an error for multiple devices, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "Key A") || !strings.Contains(got, "1234:5678") {
		t.Errorf("error = %q, want it to name both devices", got)
	}
}

func TestDiscoverOnePropagatesUnderlyingError(t *testing.T) {
	orig := discoverDevices
	defer func() { discoverDevices = orig }()
	discoverDevices = func() ([]hid.Info, error) { return nil, errors.New("permission denied") }

	if _, err := discoverOne(); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestGetSecretNoPIN(t *testing.T) {
	fc := &fakeClient{info: noPINInfo(), secret: []byte("the secret")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	got, err := GetSecret(testRPID, []byte("cred"), []byte("salt"))
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(got) != "the secret" {
		t.Errorf("GetSecret() = %q, want %q", got, "the secret")
	}
	if fc.pinTokenCalls != 0 {
		t.Errorf("GetPINToken called %d times for a PIN-less authenticator, want 0", fc.pinTokenCalls)
	}
	if fc.lastPINToken != nil {
		t.Errorf("GetAssertion was called with a non-nil PIN token: %x", fc.lastPINToken)
	}
}

func TestGetSecretWithPINPromptsOnce(t *testing.T) {
	fc := &fakeClient{info: pinSetInfo(), pinToken: []byte("token"), secret: []byte("secret")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	origPIN := PINPrompt
	defer func() { PINPrompt = origPIN }()
	pinPrompts := 0
	PINPrompt = func(string) (string, error) { pinPrompts++; return "1234", nil }

	if _, err := GetSecret(testRPID, []byte("cred1"), []byte("salt")); err != nil {
		t.Fatalf("GetSecret (first call): %v", err)
	}
	if _, err := GetSecret(testRPID, []byte("cred2"), []byte("salt")); err != nil {
		t.Fatalf("GetSecret (second call): %v", err)
	}
	if pinPrompts != 1 {
		t.Errorf("PIN prompted %d times across two GetSecret calls, want 1 (cached)", pinPrompts)
	}
	if fc.pinTokenCalls != 1 {
		t.Errorf("GetPINToken called %d times, want 1 (cached)", fc.pinTokenCalls)
	}
}

func TestGetSecretPINTokenScopedPerRPID(t *testing.T) {
	// A pinUvAuthToken minted for one rpID is meaningless for another -
	// the session cache must not share tokens across rpIDs, unlike a
	// single-fixed-RPID application.
	fc := &fakeClient{info: pinSetInfo(), secret: []byte("secret")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	origPIN := PINPrompt
	defer func() { PINPrompt = origPIN }()
	PINPrompt = func(string) (string, error) { return "1234", nil }

	if _, err := GetSecret("rp-a", []byte("cred"), []byte("salt")); err != nil {
		t.Fatalf("GetSecret(rp-a): %v", err)
	}
	if _, err := GetSecret("rp-b", []byte("cred"), []byte("salt")); err != nil {
		t.Fatalf("GetSecret(rp-b): %v", err)
	}
	if fc.pinTokenCalls != 2 {
		t.Errorf("GetPINToken called %d times across two rpIDs, want 2 (not cached across rpIDs)", fc.pinTokenCalls)
	}

	// A second call for an rpID already used must still hit the cache.
	if _, err := GetSecret("rp-a", []byte("cred"), []byte("salt")); err != nil {
		t.Fatalf("GetSecret(rp-a again): %v", err)
	}
	if fc.pinTokenCalls != 2 {
		t.Errorf("GetPINToken called %d times after repeating rp-a, want still 2 (cached)", fc.pinTokenCalls)
	}
}

func TestGetSecretCachesConnectionAcrossCalls(t *testing.T) {
	fc := &fakeClient{info: noPINInfo(), secret: []byte("secret")}
	connectCalls := 0
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) {
		connectCalls++
		return fc, &fakeCloser{}, nil
	})

	for range 3 {
		if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err != nil {
			t.Fatalf("GetSecret: %v", err)
		}
	}
	if connectCalls != 1 {
		t.Errorf("connectFunc called %d times across 3 GetSecret calls, want 1 (cached)", connectCalls)
	}
}

func TestGetSecretRejectsMissingHMACSecretSupport(t *testing.T) {
	fc := &fakeClient{info: &ctap2.Info{PINProtocols: []int{2}}} // no "hmac-secret" extension
	closer := &fakeCloser{}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, closer, nil })

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error for a device without hmac-secret support, got nil")
	}
	if !closer.closed {
		t.Error("device wasn't closed after a rejected capability check")
	}
}

func TestGetSecretRejectsOldPINProtocolWhenPINSet(t *testing.T) {
	fc := &fakeClient{info: &ctap2.Info{Extensions: []string{"hmac-secret"}, ClientPIN: true, PINSet: true, PINProtocols: []int{1}}}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error for a PIN-set device that only speaks PIN protocol one, got nil")
	}
}

func TestGetSecretPropagatesConnectError(t *testing.T) {
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return nil, nil, errors.New("no device") })
	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestGetSecretPropagatesGetInfoError(t *testing.T) {
	fc := &fakeClient{infoErr: errors.New("boom")}
	closer := &fakeCloser{}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, closer, nil })

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !closer.closed {
		t.Error("device wasn't closed after a GetInfo failure")
	}
}

func TestGetSecretPropagatesAssertionError(t *testing.T) {
	fc := &fakeClient{info: noPINInfo(), getAssertionErr: errors.New("no credentials")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestEnrollSuccess(t *testing.T) {
	fc := &fakeClient{info: noPINInfo(), credID: []byte("new-credential-id")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	got, err := Enroll(testRPID)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if string(got) != "new-credential-id" {
		t.Errorf("Enroll() = %q, want %q", got, "new-credential-id")
	}
}

func TestEnrollWithPINPassesTokenThrough(t *testing.T) {
	fc := &fakeClient{info: pinSetInfo(), pinToken: []byte("the-token"), credID: []byte("cred")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })
	origPIN := PINPrompt
	defer func() { PINPrompt = origPIN }()
	PINPrompt = func(string) (string, error) { return "123456", nil }

	if _, err := Enroll(testRPID); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if string(fc.lastPINToken) != "the-token" {
		t.Errorf("MakeCredential was called with PIN token %x, want %q", fc.lastPINToken, "the-token")
	}
}

func TestEnrollPropagatesMakeCredentialError(t *testing.T) {
	fc := &fakeClient{info: noPINInfo(), makeCredErr: errors.New("touch timed out")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })

	if _, err := Enroll(testRPID); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestSessionPINTokenPropagatesGetPINError(t *testing.T) {
	fc := &fakeClient{info: pinSetInfo()}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })
	origPIN := PINPrompt
	defer func() { PINPrompt = origPIN }()
	PINPrompt = func(string) (string, error) { return "", fmt.Errorf("no terminal") }

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error, got nil")
	}
}

func TestSessionPINTokenPropagatesGetPINTokenError(t *testing.T) {
	fc := &fakeClient{info: pinSetInfo(), pinTokenErr: errors.New("PIN invalid")}
	withFakeSession(t, func() (authenticatorClient, io.Closer, error) { return fc, &fakeCloser{}, nil })
	origPIN := PINPrompt
	defer func() { PINPrompt = origPIN }()
	PINPrompt = func(string) (string, error) { return "0000", nil }

	if _, err := GetSecret(testRPID, []byte("cred"), []byte("salt")); err == nil {
		t.Fatal("expected an error, got nil")
	}
}
