# Getting Started

## Install

```sh
go get github.com/tpyle/gohmacsecret
```

The import path is `github.com/tpyle/gohmacsecret`; the package name is
`hmacsecret`:

```go
import hmacsecret "github.com/tpyle/gohmacsecret"
```

## Enrolling a credential

```go
credentialID, err := hmacsecret.Enroll("example.com")
if err != nil {
	log.Fatal(err)
}
// Persist credentialID (and a salt of your own choosing) - you'll need
// both, plus the same rpID, to re-derive the secret later.
```

`rpID` (the first argument) is your application's relying-party
identifier - any stable string that scopes the credential to your
application. It's not validated against a domain format the way a
browser-based WebAuthn client's origin would be (there is no browser or
origin here), but it **must** be byte-identical between `Enroll` and
every later `GetSecret` call for that credential, since the authenticator
binds them together internally.

`Enroll` fails if the connected authenticator doesn't support the
`hmac-secret` extension, or (when a PIN is set) only supports the older
PIN/UV Auth Protocol One.

## Deriving the secret

```go
secret, err := hmacsecret.GetSecret("example.com", credentialID, salt)
if err != nil {
	log.Fatal(err)
}
```

`salt` is any byte slice of your choosing - the same `(rpID,
credentialID, salt)` triple always derives the same `secret`, and
changing any one of them derives a different one. A typical use is
symmetric-key wrapping: derive `secret` once, use it (e.g. via HKDF) to
wrap/unwrap your application's actual data-encryption key, and store the
wrapped key alongside `credentialID` and `salt` - none of which need to
be kept secret themselves, since the wrapping key can only be
re-derived by touching the physical authenticator.

## PIN prompting and touch narration

If the authenticator has a PIN set, `Enroll`/`GetSecret` prompt for it via
`PINPrompt`:

```go
// PINPrompt reads a FIDO2 PIN from the user, given the prompt text.
var PINPrompt = defaultPINPrompt // func(prompt string) (string, error)
```

The default reads from the terminal without echo (or a plain line when
stdin isn't a terminal). Override it to integrate with your own
terminal/GUI/test harness:

```go
hmacsecret.PINPrompt = func(prompt string) (string, error) {
	return myGUI.PromptSecret(prompt)
}
```

Similarly, `OnTouchRequired` is called (at most once per `Enroll`/
`GetSecret` call) when the authenticator signals it's waiting for a
physical touch - the default prints `"Touch your security key now..."` to
stderr:

```go
var OnTouchRequired = defaultOnTouchRequired // func()
```

## Caching within a process

`Enroll`/`GetSecret` cache the connected authenticator and any PIN tokens
obtained from it for the life of the process, so calling either
repeatedly (e.g. trying several enrolled credentials in turn, or calling
`Enroll` and then immediately `GetSecret` to derive the new credential's
secret right away) doesn't re-prompt for a PIN or a fresh touch every
time - only the first call against a given `rpID` in a process does that
work. That first call requests a PIN token covering every operation this
package might need (not just the one it was called for), so a mixed
sequence like enroll-then-derive still needs only one PIN entry and one
touch, not one per operation. A wrong `credentialID` against the same
cached connection still fails fast, without an extra touch prompt.

## Errors

`ErrUnsupportedPlatform` (re-exported from package `hid`) is returned
when no HID backend is available for the current platform. Other errors
are returned as plain wrapped `error` values with a human-readable
message (e.g. "no FIDO2 security key found", "this security key doesn't
support the hmac-secret extension") - check `errors.Is(err,
hmacsecret.ErrUnsupportedPlatform)` for that specific case; treat
anything else as a message to show the user.

## Scope

`Enroll`/`GetSecret` only - see the top-level README's Scope section for
what's deliberately not implemented (paste/discoverable credentials, PIN
protocol one, multi-device selection).
