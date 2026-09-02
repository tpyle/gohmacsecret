# gohmacsecret

`gohmacsecret` derives a symmetric secret from a FIDO2 security key's
CTAP2 `hmac-secret` extension - enroll a new credential once, then
re-derive the same secret from it any number of times, given the
credential ID, a salt, and (if the authenticator has a PIN set) the PIN.
This is the same mechanism tools like
[`age-plugin-fido2-hmac`](https://github.com/olastor/age-plugin-fido2-hmac)
use for FIDO2-backed file encryption.

No cgo, no external process, no third-party FIDO2/CTAP2 library - talks
to the authenticator natively on Linux, Windows, and macOS.

```go
import hmacsecret "github.com/tpyle/gohmacsecret"

const rpID = "example.com"

credentialID, err := hmacsecret.Enroll(rpID)
// ... persist credentialID and a salt somewhere ...

secret, err := hmacsecret.GetSecret(rpID, credentialID, salt)
```

See [`examples/`](examples) for two small, runnable programs, and the
[wiki](https://github.com/tpyle/gohmacsecret/wiki) for full documentation.

## Packages

* [`hmacsecret`](.) (this module's root package) - the high-level
  `Enroll`/`GetSecret` facade most callers want.
* [`hid`](hid) - cgo-free USB HID transport (discover and exchange
  fixed-size reports with FIDO authenticators), public in case you need
  raw HID access for something other than `hmac-secret`.
* [`ctap2`](ctap2) - a narrow, hand-rolled CTAP2 client (CTAPHID framing,
  PIN/UV Auth Protocol Two, `authenticatorMakeCredential`/
  `GetAssertion` with the `hmac-secret` extension) built on `hid`, public
  for the same reason. It is **not** a general-purpose CTAP2/WebAuthn
  client - see [wiki/CTAP2.md](https://github.com/tpyle/gohmacsecret/wiki/CTAP2)
  for exactly what it does and doesn't implement.

## Implementation

Unlike most FIDO2 integrations you'll find in the Go ecosystem, this
project's CTAP2 client is hand-rolled rather than built on a third-party
FIDO2/PIV library. That's a direct consequence of the no-cgo goal: the
mature options (`go-piv`, `go-libfido2`) require cgo and a system PC/SC
library, and no sufficiently mature cgo-free FIDO2 Go library exists to
depend on instead. Every wire-format detail (CBOR field numbers, the PIN
protocol's key derivation, the `hmac-secret` extension's request/response
shape) was cross-checked against Yubico's own
[`python-fido2`](https://github.com/Yubico/python-fido2) reference
implementation, since there's no spec-conformance test suite to validate
a hand-rolled client against - only real hardware.

## Platform support

| Platform | How |
|---|---|
| Linux | `/dev/hidraw*` via `golang.org/x/sys/unix` ioctls |
| Windows | `hid.dll` + `CreateFile`/`ReadFile`/`WriteFile` via `golang.org/x/sys/windows` |
| macOS | IOKit's HID device API via the Objective-C/C runtime (`github.com/ebitengine/purego`) |

See [wiki/Platform-Support.md](https://github.com/tpyle/gohmacsecret/wiki/Platform-Support)
for implementation details and per-platform limitations.

## Scope

* `Enroll`/`GetSecret` only - no `Read` (paste-equivalent enumeration of
  arbitrary credentials, discoverable credentials, or attestation) is
  implemented.
* Only PIN/UV Auth Protocol Two - current-generation security keys. An
  authenticator that only supports the older Protocol One fails with a
  clear error rather than silently mismatching keys.
* One device at a time - if more than one FIDO HID device is connected,
  `Enroll`/`GetSecret` fail naming what was found instead of prompting to
  pick one.

## Testing

Protocol-level logic (CTAPHID framing, PIN protocol crypto, the
`hmac-secret` extension round trip) is unit-tested against a full
software authenticator fake with zero OS dependency. Pure per-platform
logic (Windows' report-ID framing, the FIDO usage-page/usage filter) is
factored into build-tag-free files so it unit-tests on any GOOS. Real HID
I/O against a physical FIDO2 key needs a real machine with a key plugged
in - CI can only exercise the "zero devices present" path per platform;
see [wiki/Platform-Support.md](https://github.com/tpyle/gohmacsecret/wiki/Platform-Support)'s
manual verification checklist before a release.
