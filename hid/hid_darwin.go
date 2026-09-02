//go:build darwin

package hid

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	cfStringEncodingUTF8 = 0x08000100
	cfNumberSInt64Type   = 4

	kIOHIDReportTypeOutput = 1
	ioHIDDeviceOptionsNone = 0

	darwinIOTimeout      = 3 * time.Second
	darwinReportBufSize  = 64
	darwinRunLoopPollSec = 0.25 // how promptly Close is noticed between CFRunLoopRunInMode calls
)

var (
	iokit uintptr
	cf    uintptr
)

// IOKit functions - all plain C ABI, reachable via purego without cgo,
// exactly like this project's macOS clipboard sibling (goclip) already
// does for AppKit's Objective-C methods, just via RegisterLibFunc instead
// of objc_msgSend.
var (
	ioServiceMatching                 func(name *byte) uintptr
	ioServiceGetMatchingServices      func(mainPort uint32, matching uintptr, existing *uint32) int32
	ioServiceGetMatchingService       func(mainPort uint32, matching uintptr) uint32
	ioRegistryEntryIDMatching         func(entryID uint64) uintptr
	ioIteratorNext                    func(iterator uint32) uint32
	ioObjectRelease                   func(object uint32) int32
	ioRegistryEntryCreateCFProperty   func(entry uint32, key uintptr, allocator uintptr, options uint32) uintptr
	ioRegistryEntryGetRegistryEntryID func(entry uint32, entryID *uint64) int32
	ioHIDDeviceCreate                 func(allocator uintptr, service uint32) uintptr
	ioHIDDeviceOpen                   func(device uintptr, options int32) int32
	ioHIDDeviceClose                  func(device uintptr, options int32) int32
	ioHIDDeviceSetReport              func(device uintptr, reportType int32, reportID int32, report *byte, reportLength int) int32
	ioHIDDeviceRegisterInputReport    func(device uintptr, report uintptr, reportLen int, callback uintptr, context uintptr)
	ioHIDDeviceScheduleWithRunLoop    func(device uintptr, runLoop uintptr, mode uintptr)
	ioHIDDeviceUnscheduleFromRunLoop  func(device uintptr, runLoop uintptr, mode uintptr)
)

// CoreFoundation functions.
var (
	cfStringCreateWithCString func(alloc uintptr, cStr *byte, encoding uint32) uintptr
	cfStringGetCString        func(theString uintptr, buffer *byte, bufferSize int, encoding uint32) bool
	cfNumberGetValue          func(number uintptr, theType int32, valuePtr uintptr) bool
	cfRunLoopGetCurrent       func() uintptr
	cfRunLoopRunInMode        func(mode uintptr, seconds float64, returnAfterSourceHandled bool) int32
	cfRunLoopStop             func(rl uintptr)
	cfRelease                 func(cf uintptr)
)

// CoreFoundation global constants - these dylib symbols are themselves
// pointers to the actual CFTypeRef value, so derefSymbol dereferences
// once more after dlsym resolves the symbol's address.
var (
	kCFAllocatorDefault   uintptr
	kCFRunLoopDefaultMode uintptr
)

func init() {
	var err error
	iokit, err = purego.Dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", purego.RTLD_LAZY)
	if err != nil {
		panic(fmt.Sprintf("hid: dlopen IOKit: %v", err))
	}
	cf, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_LAZY)
	if err != nil {
		panic(fmt.Sprintf("hid: dlopen CoreFoundation: %v", err))
	}

	purego.RegisterLibFunc(&ioServiceMatching, iokit, "IOServiceMatching")
	purego.RegisterLibFunc(&ioServiceGetMatchingServices, iokit, "IOServiceGetMatchingServices")
	purego.RegisterLibFunc(&ioServiceGetMatchingService, iokit, "IOServiceGetMatchingService")
	purego.RegisterLibFunc(&ioRegistryEntryIDMatching, iokit, "IORegistryEntryIDMatching")
	purego.RegisterLibFunc(&ioIteratorNext, iokit, "IOIteratorNext")
	purego.RegisterLibFunc(&ioObjectRelease, iokit, "IOObjectRelease")
	purego.RegisterLibFunc(&ioRegistryEntryCreateCFProperty, iokit, "IORegistryEntryCreateCFProperty")
	purego.RegisterLibFunc(&ioRegistryEntryGetRegistryEntryID, iokit, "IORegistryEntryGetRegistryEntryID")
	purego.RegisterLibFunc(&ioHIDDeviceCreate, iokit, "IOHIDDeviceCreate")
	purego.RegisterLibFunc(&ioHIDDeviceOpen, iokit, "IOHIDDeviceOpen")
	purego.RegisterLibFunc(&ioHIDDeviceClose, iokit, "IOHIDDeviceClose")
	purego.RegisterLibFunc(&ioHIDDeviceSetReport, iokit, "IOHIDDeviceSetReport")
	purego.RegisterLibFunc(&ioHIDDeviceRegisterInputReport, iokit, "IOHIDDeviceRegisterInputReportCallback")
	purego.RegisterLibFunc(&ioHIDDeviceScheduleWithRunLoop, iokit, "IOHIDDeviceScheduleWithRunLoop")
	purego.RegisterLibFunc(&ioHIDDeviceUnscheduleFromRunLoop, iokit, "IOHIDDeviceUnscheduleFromRunLoop")

	purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
	purego.RegisterLibFunc(&cfStringGetCString, cf, "CFStringGetCString")
	purego.RegisterLibFunc(&cfNumberGetValue, cf, "CFNumberGetValue")
	purego.RegisterLibFunc(&cfRunLoopGetCurrent, cf, "CFRunLoopGetCurrent")
	purego.RegisterLibFunc(&cfRunLoopRunInMode, cf, "CFRunLoopRunInMode")
	purego.RegisterLibFunc(&cfRunLoopStop, cf, "CFRunLoopStop")
	purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")

	kCFAllocatorDefault = derefSymbol(cf, "kCFAllocatorDefault")
	kCFRunLoopDefaultMode = derefSymbol(cf, "kCFRunLoopDefaultMode")
}

// derefSymbol loads a global CFTypeRef constant from a dylib. dlsym
// returns the address of the global variable itself, which must be
// dereferenced once more to get the CFTypeRef value it holds - the
// double-pointer cast (rather than a direct uintptr->unsafe.Pointer
// conversion) is the same "circumvent go vet's unsafeptr check" idiom
// purego/objc's own code uses, and this package's goclip sibling uses
// for the same reason.
func derefSymbol(lib uintptr, name string) uintptr {
	sym, err := purego.Dlsym(lib, name)
	if err != nil || sym == 0 {
		return 0
	}
	return **(**uintptr)(unsafe.Pointer(&sym)) //nolint:gosec // G103: required to dereference a dlsym'd CoreFoundation global constant
}

func cString(s string) *byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	return &b[0]
}

func cfStr(s string) uintptr {
	return cfStringCreateWithCString(0, cString(s), cfStringEncodingUTF8)
}

// propInt reads an integer IORegistry property from a service - used for
// PrimaryUsagePage/PrimaryUsage/VendorID/ProductID, all of which macOS
// exposes as CFNumbers. A missing or wrong-type property reads as 0,
// which every caller already treats as "doesn't match"/"unknown" rather
// than needing to distinguish it from a genuine zero value.
func propInt(service uint32, key string) int64 {
	ref := ioRegistryEntryCreateCFProperty(service, cfStr(key), 0, 0)
	if ref == 0 {
		return 0
	}
	defer cfRelease(ref)
	var val int64
	if !cfNumberGetValue(ref, cfNumberSInt64Type, uintptr(unsafe.Pointer(&val))) { //nolint:gosec // G103: required to pass the output pointer to CFNumberGetValue
		return 0
	}
	return val
}

// propString reads a string IORegistry property from a service - used
// for the device's Product name.
func propString(service uint32, key string) (string, bool) {
	ref := ioRegistryEntryCreateCFProperty(service, cfStr(key), 0, 0)
	if ref == 0 {
		return "", false
	}
	defer cfRelease(ref)
	buf := make([]byte, 256)
	if !cfStringGetCString(ref, &buf[0], len(buf), cfStringEncodingUTF8) { //nolint:gosec // G103: required to pass the output buffer's address to CFStringGetCString
		return "", false
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf), true
}

// Discover lists every IOHIDDevice service on the FIDO usage page.
// Devices that can't be queried are silently skipped, exactly like the
// Linux and Windows backends.
func Discover() ([]Info, error) {
	matching := ioServiceMatching(cString("IOHIDDevice"))
	var it uint32
	if kr := ioServiceGetMatchingServices(0, matching, &it); kr != 0 {
		return nil, fmt.Errorf("hid: IOServiceGetMatchingServices failed: %#x", uint32(kr)) //nolint:gosec // G115: IOReturn is a 32-bit value
	}
	defer ioObjectRelease(it) //nolint:errcheck // best-effort cleanup of our own iterator handle

	var infos []Info
	for {
		svc := ioIteratorNext(it)
		if svc == 0 {
			break
		}
		if info, ok := describeService(svc); ok {
			infos = append(infos, info)
		}
		ioObjectRelease(svc) //nolint:errcheck // best-effort cleanup of our own probe reference
	}
	return infos, nil
}

// describeService reads a candidate IOHIDDevice service's usage page/
// usage/VID/PID/product, keeping only FIDO devices. The device path
// encodes its IORegistryEntryID - a stable identifier Open can later use
// to re-find this exact device - mirroring the "DevSrvsID:<id>" path
// convention hidapi's own macOS backend uses.
func describeService(svc uint32) (Info, bool) {
	usagePage := propInt(svc, "PrimaryUsagePage")
	usage := propInt(svc, "PrimaryUsage")
	if !matchesFIDO(int(usagePage), int(usage)) {
		return Info{}, false
	}

	var entryID uint64
	if kr := ioRegistryEntryGetRegistryEntryID(svc, &entryID); kr != 0 {
		return Info{}, false
	}

	vendorID := propInt(svc, "VendorID")
	productID := propInt(svc, "ProductID")
	product, _ := propString(svc, "Product")

	return Info{
		Path:      fmt.Sprintf("DevSrvsID:%d", entryID),
		VendorID:  uint16(vendorID),  //nolint:gosec // G115: USB VID is a 16-bit value by definition
		ProductID: uint16(productID), //nolint:gosec // G115: USB PID is a 16-bit value by definition
		Product:   product,
	}, true
}

// Open connects to the device identified by info (as returned by
// Discover), re-finding it by its IORegistryEntryID.
func Open(info Info) (Device, error) {
	var entryID uint64
	if _, err := fmt.Sscanf(info.Path, "DevSrvsID:%d", &entryID); err != nil {
		return nil, fmt.Errorf("hid: invalid device path %s: %w", info.Path, err)
	}

	svc := ioServiceGetMatchingService(0, ioRegistryEntryIDMatching(entryID))
	if svc == 0 {
		return nil, fmt.Errorf("hid: device %s not found (unplugged?)", info.Path)
	}
	defer ioObjectRelease(svc) //nolint:errcheck // IOHIDDeviceCreate below takes its own independent reference

	dev := ioHIDDeviceCreate(kCFAllocatorDefault, svc)
	if dev == 0 {
		return nil, fmt.Errorf("hid: IOHIDDeviceCreate failed for %s", info.Path)
	}
	if kr := ioHIDDeviceOpen(dev, ioHIDDeviceOptionsNone); kr != 0 {
		cfRelease(dev)                                                         //nolint:errcheck // best-effort cleanup on an already-failing path
		return nil, fmt.Errorf("hid: IOHIDDeviceOpen failed: %#x", uint32(kr)) //nolint:gosec // G115: IOReturn is a 32-bit value
	}

	d := &darwinDevice{
		dev:         dev,
		reports:     make(chan []byte, 1),
		stopRunLoop: make(chan struct{}),
		runLoopDone: make(chan struct{}),
		ready:       make(chan struct{}),
	}
	go d.pump()
	select {
	case <-d.ready:
		return d, nil
	case <-time.After(darwinIOTimeout):
		return nil, errors.New("hid: timed out starting the device's run loop")
	}
}

// darwinDevice owns one open IOHIDDevice for its entire lifetime: a
// single pinned-OS-thread goroutine (pump) schedules it on its own
// CFRunLoop and pumps that run loop until Close asks it to stop -
// required because IOKit only delivers input reports via a callback that
// fires while the device's run loop is actively being pumped on the
// exact thread that scheduled it (there is no blocking-read equivalent).
// Writes (IOHIDDeviceSetReport) are synchronous and need none of this.
type darwinDevice struct {
	dev         uintptr
	reports     chan []byte
	stopRunLoop chan struct{}
	runLoopDone chan struct{}
	ready       chan struct{}
	runLoop     uintptr // published once, before ready is closed; read-only afterward

	// reportBuf and callback must outlive every call IOKit might still
	// make into them - kept both as ordinary struct fields (reachable
	// for as long as the pump goroutine, which references d, is
	// running) and explicitly in gcRoots as documented, low-cost
	// insurance against relying on that reasoning alone.
	reportBuf []byte
	callback  uintptr
	gcRoots   []any
}

// pump owns the device's CFRunLoop for its entire lifetime: register the
// input-report callback, schedule the device, then pump the run loop
// until stopRunLoop is closed - at which point it unregisters, closes,
// and releases the device from this same thread, mirroring the ordering
// hidapi's own macOS backend uses to avoid tearing down a device from a
// different thread than the one servicing its run loop.
func (d *darwinDevice) pump() {
	runtime.LockOSThread() // never unlocked - this goroutine's exit ends the thread, which is correct here

	d.reportBuf = make([]byte, darwinReportBufSize)
	d.callback = purego.NewCallback(d.onReport)
	d.gcRoots = append(d.gcRoots, d.reportBuf, d.callback, d.onReport)

	bufPtr := uintptr(unsafe.Pointer(&d.reportBuf[0])) //nolint:gosec // G103: required to hand IOKit a pointer to a buffer it writes incoming reports into
	ioHIDDeviceRegisterInputReport(d.dev, bufPtr, darwinReportBufSize, d.callback, 0)

	d.runLoop = cfRunLoopGetCurrent()
	ioHIDDeviceScheduleWithRunLoop(d.dev, d.runLoop, kCFRunLoopDefaultMode)

	close(d.ready)

	for {
		select {
		case <-d.stopRunLoop:
			ioHIDDeviceRegisterInputReport(d.dev, bufPtr, darwinReportBufSize, 0, 0) // unregister before closing, per hidapi's mac backend
			ioHIDDeviceUnscheduleFromRunLoop(d.dev, d.runLoop, kCFRunLoopDefaultMode)
			ioHIDDeviceClose(d.dev, ioHIDDeviceOptionsNone) //nolint:errcheck // best-effort close; nothing actionable at shutdown
			cfRelease(d.dev)                                //nolint:errcheck // best-effort cleanup; nothing actionable at shutdown
			close(d.runLoopDone)
			return
		default:
		}
		cfRunLoopRunInMode(kCFRunLoopDefaultMode, darwinRunLoopPollSec, false)
	}
}

// onReport is IOKit's raw input-report callback - it must copy out of
// reportBuf immediately, since IOKit overwrites that same buffer on the
// next incoming report.
func (d *darwinDevice) onReport(_ uintptr, _ int32, _ uintptr, _ int32, _ uint32, report *byte, length int) {
	if length <= 0 {
		return
	}
	data := make([]byte, length)
	copy(data, unsafe.Slice(report, length)) //nolint:gosec // G103: report/length come directly from IOKit's own callback contract
	select {
	case d.reports <- data:
	default:
		// The reader hasn't kept up - drop the stale pending report so
		// Read sees the latest one, not an ever-growing backlog.
		select {
		case <-d.reports:
		default:
		}
		d.reports <- data
	}
}

// Write sends one fixed-size report. Unlike Windows, macOS takes the
// report ID as its own parameter rather than needing it prepended into
// the data buffer.
func (d *darwinDevice) Write(report []byte) error {
	if len(report) == 0 {
		return errors.New("hid: empty report")
	}
	kr := ioHIDDeviceSetReport(d.dev, kIOHIDReportTypeOutput, 0, &report[0], len(report)) //nolint:gosec // G103: required to pass the report buffer's address to IOHIDDeviceSetReport
	if kr != 0 {
		return fmt.Errorf("hid: IOHIDDeviceSetReport failed: %#x", uint32(kr)) //nolint:gosec // G115: IOReturn is a 32-bit value
	}
	return nil
}

// Read receives one fixed-size report, delivered by the run loop pump
// goroutine's callback.
func (d *darwinDevice) Read() ([]byte, error) {
	select {
	case r := <-d.reports:
		return r, nil
	case <-time.After(darwinIOTimeout):
		return nil, errors.New("hid: read timed out")
	}
}

func (d *darwinDevice) Close() error {
	close(d.stopRunLoop)
	cfRunLoopStop(d.runLoop) // wakes a blocked CFRunLoopRunInMode immediately rather than waiting out its poll interval
	<-d.runLoopDone
	return nil
}
