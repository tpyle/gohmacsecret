//go:build windows

package hid

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	readTimeout  = 3 * time.Second
	writeTimeout = 3 * time.Second
)

// hidClassGUID is GUID_DEVINTERFACE_HID, the well-known, unchanging
// device-interface class GUID for HID devices (documented by Microsoft).
var hidClassGUID = windows.GUID{
	Data1: 0x4D1E55B2, Data2: 0xF16F, Data3: 0x11CF,
	Data4: [8]byte{0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30},
}

var (
	modHid                    = windows.NewLazySystemDLL("hid.dll")
	procHidDGetAttributes     = modHid.NewProc("HidD_GetAttributes")
	procHidDGetPreparsedData  = modHid.NewProc("HidD_GetPreparsedData")
	procHidDFreePreparsedData = modHid.NewProc("HidD_FreePreparsedData")
	procHidPGetCaps           = modHid.NewProc("HidP_GetCaps")
	procHidDGetProductString  = modHid.NewProc("HidD_GetProductString")
)

// hidpStatusSuccess is HIDP_STATUS_SUCCESS from hidpi.h:
// HIDP_ERROR_CODES(0, 0) == (0 << 28) | (0x11 << 16) | 0.
const hidpStatusSuccess = 0x00110000

// hidAttributes mirrors HIDD_ATTRIBUTES exactly (hidsdi.h): a ULONG Size
// followed by three USHORTs. C pads the struct to a 4-byte-aligned
// 12-byte total because of the leading ULONG - the trailing blank field
// exists only to match that padding, since HidD_GetAttributes writes the
// full 12-byte structure through our pointer regardless of what Go
// thinks the struct's size is.
type hidAttributes struct {
	Size          uint32
	VendorID      uint16
	ProductID     uint16
	VersionNumber uint16
	_             uint16
}

// hidCaps mirrors HIDP_CAPS exactly (hidpi.h): 32 consecutive USHORT
// fields, 64 bytes total, no padding. Only the first four fields are
// ever read; the rest exist so HidP_GetCaps's write through our pointer
// stays within this struct's real size.
type hidCaps struct {
	Usage                     uint16
	UsagePage                 uint16
	InputReportByteLength     uint16
	OutputReportByteLength    uint16
	FeatureReportByteLength   uint16
	reserved                  [17]uint16
	numberLinkCollectionNodes uint16
	numberInputButtonCaps     uint16
	numberInputValueCaps      uint16
	numberInputDataIndices    uint16
	numberOutputButtonCaps    uint16
	numberOutputValueCaps     uint16
	numberOutputDataIndices   uint16
	numberFeatureButtonCaps   uint16
	numberFeatureValueCaps    uint16
	numberFeatureDataIndices  uint16
}

// Discover lists every present HID device-interface path and keeps the
// ones on the FIDO usage page. Devices that can't be opened/queried (a
// permission problem, or a device that vanished between enumeration and
// probing) are silently skipped, exactly like the Linux backend.
func Discover() ([]Info, error) {
	paths, err := windows.CM_Get_Device_Interface_List("", &hidClassGUID, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil {
		return nil, fmt.Errorf("hid: listing HID devices: %w", err)
	}
	var infos []Info
	for _, path := range paths {
		if info, ok := probeDevice(path); ok {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

func probeDevice(path string) (Info, bool) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Info{}, false
	}
	h, err := windows.CreateFile(pathPtr, windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return Info{}, false
	}
	defer windows.CloseHandle(h) //nolint:errcheck // read-only probe of a device we don't otherwise use; nothing meaningful to do with a close error here

	attrs, ok := getAttributes(h)
	if !ok {
		return Info{}, false
	}
	caps, err := getCaps(h)
	if err != nil || caps.UsagePage != fidoUsagePage || caps.Usage != fidoUsage {
		return Info{}, false
	}

	return Info{
		Path:      path,
		VendorID:  attrs.VendorID,
		ProductID: attrs.ProductID,
		Product:   getProductString(h),
	}, true
}

func getAttributes(h windows.Handle) (hidAttributes, bool) {
	var attrs hidAttributes
	attrs.Size = uint32(unsafe.Sizeof(attrs))
	r, _, _ := procHidDGetAttributes.Call(uintptr(h), uintptr(unsafe.Pointer(&attrs))) //nolint:gosec // G103: required to pass the output pointer to HidD_GetAttributes
	return attrs, r != 0
}

func getCaps(h windows.Handle) (hidCaps, error) {
	var preparsed uintptr
	r, _, _ := procHidDGetPreparsedData.Call(uintptr(h), uintptr(unsafe.Pointer(&preparsed))) //nolint:gosec // G103: required to pass the output pointer to HidD_GetPreparsedData
	if r == 0 || preparsed == 0 {
		return hidCaps{}, errors.New("hid: HidD_GetPreparsedData failed")
	}
	defer procHidDFreePreparsedData.Call(preparsed) //nolint:errcheck // best-effort cleanup of the driver-allocated preparsed-data buffer

	var caps hidCaps
	status, _, _ := procHidPGetCaps.Call(preparsed, uintptr(unsafe.Pointer(&caps))) //nolint:gosec // G103: required to pass the output pointer to HidP_GetCaps
	statusCode := uint32(status)                                                    //nolint:gosec // G115: NTSTATUS is a 32-bit value; only the low 32 bits of the uintptr return matter
	if statusCode != hidpStatusSuccess {
		return hidCaps{}, fmt.Errorf("hid: HidP_GetCaps failed: status %#x", statusCode)
	}
	return caps, nil
}

func getProductString(h windows.Handle) string {
	buf := make([]uint16, 128)                                                                                  // 256 bytes, well under HidD_GetProductString's 4093-byte cap
	r, _, _ := procHidDGetProductString.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2)) //nolint:gosec // G103: required to pass the output buffer's address to HidD_GetProductString
	if r == 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// Open connects to the device identified by info (as returned by
// Discover), opened for overlapped (asynchronous) I/O - required for
// Read to support a timeout at all, since a plain synchronous handle
// blocks forever with no way to cancel a stuck read.
func Open(info Info) (Device, error) {
	pathPtr, err := windows.UTF16PtrFromString(info.Path)
	if err != nil {
		return nil, fmt.Errorf("hid: invalid device path %s: %w", info.Path, err)
	}
	h, err := windows.CreateFile(pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, fmt.Errorf("hid: opening %s: %w", info.Path, err)
	}

	caps, err := getCaps(h)
	if err != nil {
		windows.CloseHandle(h) //nolint:errcheck // we're already returning the more useful getCaps error
		return nil, err
	}

	return &winDevice{
		h:      h,
		inLen:  int(caps.InputReportByteLength),
		outLen: int(caps.OutputReportByteLength),
	}, nil
}

type winDevice struct {
	h             windows.Handle
	inLen, outLen int
}

// Write sends one fixed-size report. Windows always prepends a 0x00
// report-ID byte for a device that doesn't use numbered reports (every
// FIDO/CTAPHID authenticator) and expects a buffer of exactly the
// device's negotiated output report length - a well-known Windows HID
// quirk with no Linux hidraw equivalent (see buildOutputReport).
func (d *winDevice) Write(report []byte) error {
	buf := buildOutputReport(report, d.outLen)
	n, err := overlappedIO(d.h, buf, true, writeTimeout)
	if err != nil {
		return fmt.Errorf("hid: writing report: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("hid: short write (%d of %d bytes)", n, len(buf))
	}
	return nil
}

// Read receives one fixed-size report, stripping the leading 0x00
// report-ID byte Windows always prepends (see stripInputReportPrefix).
func (d *winDevice) Read() ([]byte, error) {
	buf := make([]byte, d.inLen)
	n, err := overlappedIO(d.h, buf, false, readTimeout)
	if err != nil {
		return nil, fmt.Errorf("hid: reading report: %w", err)
	}
	return stripInputReportPrefix(buf[:n])
}

func (d *winDevice) Close() error {
	return windows.CloseHandle(d.h)
}

// overlappedIO performs one overlapped ReadFile or WriteFile call and
// waits up to timeout for it to complete, canceling it on timeout -
// mirrors hidapi's own hid_read_timeout pattern for Windows.
func overlappedIO(h windows.Handle, buf []byte, write bool, timeout time.Duration) (int, error) {
	event, err := windows.CreateEvent(nil, 1, 0, nil) // manual-reset, initially non-signaled
	if err != nil {
		return 0, fmt.Errorf("hid: CreateEvent: %w", err)
	}
	defer windows.CloseHandle(event) //nolint:errcheck // best-effort cleanup of our own event handle

	ov := windows.Overlapped{HEvent: event}

	var ioErr error
	if write {
		ioErr = windows.WriteFile(h, buf, nil, &ov)
	} else {
		ioErr = windows.ReadFile(h, buf, nil, &ov)
	}
	if ioErr != nil && ioErr != windows.ERROR_IO_PENDING { //nolint:errorlint // ERROR_IO_PENDING is a sentinel syscall.Errno value, not a wrapped error
		return 0, ioErr
	}

	waitMS := uint32(timeout.Milliseconds()) //nolint:gosec // G115: timeout is a small fixed constant, never near uint32 range
	wait, err := windows.WaitForSingleObject(event, waitMS)
	if err != nil {
		return 0, fmt.Errorf("hid: WaitForSingleObject: %w", err)
	}
	if wait == uint32(windows.WAIT_TIMEOUT) {
		windows.CancelIoEx(h, &ov) //nolint:errcheck // best-effort cancellation; the timeout error below is what matters
		return 0, errors.New("hid: I/O timed out")
	}

	var n uint32
	if err := windows.GetOverlappedResult(h, &ov, &n, false); err != nil {
		return 0, fmt.Errorf("hid: GetOverlappedResult: %w", err)
	}
	return int(n), nil
}
