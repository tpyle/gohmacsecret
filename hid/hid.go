// Package hid discovers and exchanges fixed-size 64-byte USB HID reports
// with FIDO authenticators (usage page 0xF1D0, usage 0x01), without cgo
// and without a third-party HID library - see package ctap2 for the
// CTAPHID framing built on top of this.
//
// Linux talks to /dev/hidraw* directly; Windows uses hid.dll plus
// CreateFile/ReadFile/WriteFile; macOS uses IOKit's HID Manager via
// github.com/ebitengine/purego. Discover and Open return
// ErrUnsupportedPlatform on any other GOOS.
package hid

import "errors"

// ErrUnsupportedPlatform is returned by Discover and Open on any GOOS
// this package doesn't implement a real backend for.
var ErrUnsupportedPlatform = errors.New("no FIDO2 HID backend is available on this platform")

// Info identifies one discovered HID device, before it's opened.
type Info struct {
	// Path is an opaque, platform-specific identifier suitable for
	// passing to Open - a device node path on Linux, a device interface
	// path on Windows.
	Path string
	// VendorID and ProductID are the device's USB VID/PID - useful only
	// for a human-readable error message when more than one device is
	// found (see package hmacsecret), never compared against a specific
	// list.
	VendorID, ProductID uint16
	// Product is the device's self-reported product name, if any -
	// e.g. "YubiKey OTP+FIDO+CCID". May be empty.
	Product string
}

// Device is an open USB HID connection: one Write/Read pair per
// fixed-size report, with no higher-level framing of its own.
type Device interface {
	Write(report []byte) error
	Read() ([]byte, error)
	Close() error
}
