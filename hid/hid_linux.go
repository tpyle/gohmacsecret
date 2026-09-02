//go:build linux

package hid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// reportSize is the fixed USB HID report size CTAPHID devices use in
// practice - hidraw doesn't expose a device's negotiated report length
// the way Windows/macOS do, so this package assumes it on Linux instead.
const reportSize = 64

// Discover lists every /dev/hidraw* device on the FIDO usage page.
// Devices that can't be opened (e.g. a keyboard or mouse this user
// doesn't have permission to read, or a security key blocked by a
// missing udev rule) or aren't a FIDO device at all are silently
// skipped, exactly as they would be by any other HID-scanning client -
// Open, not Discover, is where a permission problem on the device the
// caller actually wants is worth surfacing (see its doc comment).
func Discover() ([]Info, error) {
	matches, err := filepath.Glob("/dev/hidraw*")
	if err != nil {
		return nil, fmt.Errorf("hid: listing hidraw devices: %w", err)
	}
	var infos []Info
	for _, path := range matches {
		info, ok := describe(path)
		if ok {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func describe(path string) (Info, bool) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return Info{}, false
	}
	defer f.Close() //nolint:errcheck // read-only probe of a device we don't otherwise use; nothing meaningful to do with a close error here
	fd := int(f.Fd())

	raw, err := unix.IoctlHIDGetRawInfo(fd)
	if err != nil {
		return Info{}, false
	}
	size, err := unix.IoctlGetInt(fd, unix.HIDIOCGRDESCSIZE)
	if err != nil {
		return Info{}, false
	}
	desc := unix.HIDRawReportDescriptor{Size: uint32(size)} //nolint:gosec // HID report descriptors are a handful of bytes; the kernel itself caps this ioctl's size well under 4096
	if err := unix.IoctlHIDGetDesc(fd, &desc); err != nil {
		return Info{}, false
	}
	usagePage, usage, err := parseReportDescriptor(desc.Value[:size])
	if err != nil || usagePage != fidoUsagePage || usage != fidoUsage {
		return Info{}, false
	}

	product, _ := unix.IoctlHIDGetRawName(fd) // best-effort; not every device reports one
	return Info{
		Path:      path,
		VendorID:  uint16(raw.Vendor),  //nolint:gosec // reinterpreting the kernel's int16 wire representation as the unsigned VID it actually is, not a range-losing conversion
		ProductID: uint16(raw.Product), //nolint:gosec // see above
		Product:   product,
	}, true
}

// Open connects to the device identified by info (as returned by
// Discover).
func Open(info Info) (Device, error) {
	f, err := os.OpenFile(info.Path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, fmt.Errorf("hid: opening %s: %w (on Linux, a security key usually needs a udev rule granting non-root access - see wiki/Hardware-Keys.md)", info.Path, err)
		}
		return nil, fmt.Errorf("hid: opening %s: %w", info.Path, err)
	}
	return &hidrawDevice{f: f}, nil
}

type hidrawDevice struct {
	f *os.File
}

// Write sends one fixed-size report. Linux hidraw requires a leading
// report-ID byte on every write even for FIDO devices, which don't use
// numbered reports at all (their implicit report ID is always 0) - a
// well-known hidraw quirk every other hidraw-based HID client (including
// python-fido2's own Linux backend) works around the same way.
func (d *hidrawDevice) Write(report []byte) error {
	buf := make([]byte, 0, len(report)+1)
	buf = append(buf, 0x00)
	buf = append(buf, report...)
	n, err := d.f.Write(buf)
	if err != nil {
		return fmt.Errorf("hid: writing report: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("hid: short write (%d of %d bytes)", n, len(buf))
	}
	return nil
}

// Read receives one fixed-size report. Unlike Write, hidraw does NOT
// prepend a report-ID byte to what it reads back for a device that
// doesn't use numbered reports - only Write needs the workaround above.
func (d *hidrawDevice) Read() ([]byte, error) {
	buf := make([]byte, reportSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("hid: reading report: %w", err)
	}
	if n != reportSize {
		return nil, fmt.Errorf("hid: short read (%d of %d bytes)", n, reportSize)
	}
	return buf, nil
}

func (d *hidrawDevice) Close() error {
	return d.f.Close()
}
