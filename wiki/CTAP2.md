# CTAP2

`github.com/tpyle/gohmacsecret/ctap2` is a hand-rolled CTAP2 client built
on package [`hid`](HID): CTAPHID framing (packet fragmentation/
reassembly, channel allocation, keep-alive handling) plus the small slice
of CTAP2 the `hmacsecret` facade needs. It's public in case that slice
happens to be exactly what another project needs too, but **it is not a
general-purpose CTAP2 or WebAuthn client** - see Scope below before
reaching for it directly.

```go
import "github.com/tpyle/gohmacsecret/ctap2"

client, err := ctap2.NewClient(dev) // dev is a hid.Device
info, err := client.GetInfo()

if !info.SupportsHMACSecret() {
    // ...
}

var token []byte
if info.PINSet {
    token, err = client.GetPINToken(pin, ctap2.PermissionMakeCredential, rpID)
}
credentialID, err := client.MakeCredential(rpID, clientDataHash, token)
```

## API

```go
type Transport interface {
	Write([]byte) error
	Read() ([]byte, error)
}

type Client struct {
	OnKeepAlive func(status byte) // called on each CTAPHID_KEEPALIVE frame
}

func NewClient(t Transport) (*Client, error)

type Info struct {
	Extensions   []string
	ClientPIN    bool
	PINSet       bool
	PINProtocols []int
}
func (*Info) SupportsHMACSecret() bool
func (*Info) SupportsPINProtocolTwo() bool

const PermissionMakeCredential = 0x01
const PermissionGetAssertion   = 0x02

func (c *Client) GetInfo() (*Info, error)
func (c *Client) GetPINToken(pin string, permission int, rpID string) ([]byte, error)
func (c *Client) MakeCredential(rpID string, clientDataHash, pinToken []byte) ([]byte, error)
func (c *Client) GetAssertion(rpID string, clientDataHash, credentialID, salt, pinToken []byte) ([]byte, error)

type Error struct{ Code byte } // implements error
```

`hid.Device` already implements `Transport` - pass one directly to
`NewClient`.

## Scope

This client implements exactly what `hmac-secret`-based secret derivation
needs, and nothing more:

* **Commands**: `authenticatorGetInfo`, `authenticatorClientPIN` (only
  the `getKeyAgreement`/`getPINToken` subcommands - no PIN
  set/change), `authenticatorMakeCredential` (always non-discoverable,
  `rk: false`), `authenticatorGetAssertion` (always requesting the
  `hmac-secret` extension).
* **PIN protocol**: only PIN/UV Auth Protocol **Two** - what
  current-generation security keys use. An authenticator that only
  supports the older Protocol One is detected via
  `Info.SupportsPINProtocolTwo` but not supported.
* **No discoverable credentials, no resident keys, no CTAP1/U2F
  fallback, no BLE/NFC transport** (only whatever `hid.Device` provides -
  USB HID).
* **No attestation verification** - `MakeCredential`'s returned
  credential ID is extracted from the raw response; the attestation
  statement itself isn't parsed or verified, since there's no relying
  party server here to protect against a malicious authenticator in the
  way WebAuthn attestation exists to do.

If you need full CTAP2/WebAuthn support (discoverable credentials,
biometric UV, attestation, other transports), this isn't the right
building block - see the top-level README's Implementation notes for why
this project doesn't depend on a more complete FIDO2 library instead.
