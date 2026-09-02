# HID

`github.com/tpyle/gohmacsecret/hid` is a cgo-free USB HID transport for
FIDO2 authenticators: discover connected devices, open one, and exchange
fixed-size 64-byte reports with it. It's public so callers who need raw
HID access to a FIDO device - without `hmacsecret`'s `hmac-secret`
orchestration on top - can use it directly, but it is deliberately narrow:
it only discovers devices on the FIDO CTAP HID usage page (`0xF1D0`/
`0x01`), not general-purpose HID devices.

```go
import "github.com/tpyle/gohmacsecret/hid"

devices, err := hid.Discover()
dev, err := hid.Open(devices[0])
defer dev.Close()

err = dev.Write(report)   // exactly 64 bytes
report, err := dev.Read() // exactly 64 bytes
```

## API

```go
// ErrUnsupportedPlatform is returned by Discover and Open on any GOOS
// this package doesn't implement a real backend for.
var ErrUnsupportedPlatform error

// Info identifies one discovered HID device, before it's opened.
type Info struct {
	Path                string // opaque, platform-specific
	VendorID, ProductID uint16
	Product             string // may be empty
}

// Device is an open USB HID connection.
type Device interface {
	Write(report []byte) error
	Read() ([]byte, error)
	Close() error
}

func Discover() ([]Info, error)
func Open(Info) (Device, error)
```

`Discover` silently skips devices that can't be opened/queried (a
permission problem, a device that vanished mid-enumeration) or aren't on
the FIDO usage page - exactly as any other HID-scanning client would.
`Open`'s errors, by contrast, are worth surfacing to the caller: they
mean the *specific* device the caller asked for couldn't be opened.

See [Platform Support](Platform-Support) for what each backend actually
does under the hood, and its limitations.
