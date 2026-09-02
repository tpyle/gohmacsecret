# gohmacsecret wiki

`gohmacsecret` derives a symmetric secret from a FIDO2 security key's
CTAP2 `hmac-secret` extension, without cgo, without shelling out to any
external program, and without a third-party FIDO2/CTAP2 library, on
Linux, Windows, and macOS.

```go
import hmacsecret "github.com/tpyle/gohmacsecret"

credentialID, err := hmacsecret.Enroll("example.com")
secret, err := hmacsecret.GetSecret("example.com", credentialID, salt)
```

## Pages

* [Getting Started](Getting-Started) - installing the module, the
  `Enroll`/`GetSecret` API, PIN prompting, and touch narration.
* [Platform Support](Platform-Support) - how each platform's HID backend
  works, what it depends on, its limitations, and the manual verification
  checklist.
* [HID](HID) - the public `hid` package, for callers who want raw
  cgo-free USB HID access to a FIDO device without the `hmac-secret`
  orchestration on top.
* [CTAP2](CTAP2) - the public `ctap2` package: what CTAP2 surface this
  hand-rolled client does and doesn't implement.

See also the [`examples/`](../examples) directory for two small, runnable
programs.
