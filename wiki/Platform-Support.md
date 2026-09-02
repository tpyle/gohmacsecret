# Platform Support

| Platform | How | Real hardware tested this session? |
|---|---|---|
| Linux | `/dev/hidraw*` via `golang.org/x/sys/unix` ioctls | No physical FIDO2 key was available in the development environment - relies on protocol-level fakes plus the pre-existing, previously-verified Linux implementation this module was extracted from |
| Windows | `hid.dll` + `CreateFile`/`ReadFile`/`WriteFile` via `golang.org/x/sys/windows` | No - cross-compiled and linted only |
| macOS | IOKit's HID device API via `github.com/ebitengine/purego` | No - cross-compiled and linted only |

All three platforms filter devices on the FIDO CTAP HID transport's
dedicated usage page/usage (`0xF1D0`/`0x01`), a platform-independent
convention every backend uses identically - only the OS API used to read
those two numbers differs.

## Linux

Talks to `/dev/hidraw*` device nodes directly: opens each with plain
`os.OpenFile`, reads its raw HID report descriptor via
`unix.IoctlHIDGetDesc`, and hand-parses it (a small, direct port of
python-fido2's own descriptor parser) to find the usage page/usage and
confirm both an Input and an Output report are declared. Every FIDO/
CTAPHID report is a fixed 64 bytes. Writes need a leading `0x00`
report-ID byte (a hidraw quirk every hidraw-based client, including
python-fido2's own, works around the same way); reads don't.

Non-root access typically needs a udev rule:

```
KERNEL=="hidraw*", SUBSYSTEM=="hidraw", MODE="0660", TAG+="uaccess"
```

## Windows

Enumerates HID device interfaces via `windows.CM_Get_Device_Interface_List`
(the modern replacement for `SetupDiEnumDeviceInterfaces`), then uses a
small, fixed set of `hid.dll` functions (`HidD_GetAttributes`,
`HidD_GetPreparsedData`/`HidP_GetCaps`, `HidD_GetProductString`) -
`HidP_GetCaps` in particular parses the device's report descriptor for
you, unlike Linux where this package does it by hand.

Windows always prepends a `0x00` report-ID byte to both directions for a
device that doesn't use numbered reports (every FIDO/CTAPHID
authenticator) - reads must strip it, writes must include it and pad to
exactly the device's negotiated output report length. Reading needs
overlapped (asynchronous) I/O to support a timeout at all - a plain
synchronous handle blocks forever with no way to cancel a stuck read.

## macOS

Enumerates `IOHIDDevice` IOKit services (filtering by
`PrimaryUsagePage`/`PrimaryUsage` registry properties, read via
`IORegistryEntryCreateCFProperty`), then opens the matching device via
`IOHIDDeviceCreate`/`IOHIDDeviceOpen`. Every call is a plain C-ABI call
into `IOKit.framework`/`CoreFoundation.framework` via
[`ebitengine/purego`](https://github.com/ebitengine/purego)'s
`Dlopen`/`RegisterLibFunc` - the same technique this module's sibling
[`goclip`](https://github.com/tpyle/goclip) uses for AppKit's
Objective-C methods, just via plain C function pointers instead of
`objc_msgSend`.

**Writing** (`IOHIDDeviceSetReport`) is a single synchronous call from
any thread - no report-ID prefix byte is needed (the report ID is a
separate parameter, unlike Windows).

**Reading is structurally different from Linux/Windows.** IOKit only
delivers input reports via a callback that fires while the device is
scheduled on a `CFRunLoop` actively being pumped on the exact thread that
scheduled it - there's no blocking-read equivalent. Each opened device
gets one dedicated, OS-thread-pinned goroutine that schedules the device,
registers the input-report callback, and pumps the run loop in a loop
until the device is closed; the callback copies each incoming report into
a channel a synchronous `Read()` (called from any other goroutine)
receives from. This mirrors the read-thread architecture
[hidapi's own macOS backend](https://github.com/libusb/hidapi/blob/master/mac/hid.c)
uses, and was cross-checked against a real, working, zero-cgo purego+IOKit
Go project ([`taigrr/apple-silicon-accelerometer`](https://github.com/taigrr/apple-silicon-accelerometer))
for the exact `purego.NewCallback` trampoline shape and IOKit call
sequence - but **has not been run against real hardware**, since no Mac
was available in the development environment. Treat the macOS backend as
the least-proven of the three until it's been exercised for real.

A device's path is encoded as its stable `IORegistryEntryID`
(`"DevSrvsID:<id>"`, the same convention hidapi's own macOS backend
uses), so `Open` can re-find the exact device `Discover` found via
`IORegistryEntryIDMatching` + `IOServiceGetMatchingService`, rather than
re-enumerating and re-filtering by usage page a second time.

## Testing

Pure, OS-independent logic is factored into build-tag-free files so it
unit-tests on any GOOS, including a Linux machine with no Windows/macOS
box at all: `buildOutputReport`/`stripInputReportPrefix` (Windows' report
framing) and `matchesFIDO` (the usage-page/usage filter every backend
uses). Real HID I/O against a physical device needs the real OS and real
hardware; CI can only exercise "zero devices present" on each platform's
runner (confirms enumeration doesn't crash/hang), not an actual read/
write round trip.

### Manual verification checklist

Before relying on a given platform's backend for anything real:

1. **Linux**: `Enroll`/`GetSecret` against a physical key; confirm a
   clear "no device found" error when unplugged, and a clear "found N
   security keys" error with more than one connected.
2. **Windows**: same, on a real Windows machine. Specifically confirm a
   PIN-set device round-trips correctly (report-ID framing bugs tend to
   surface as garbled/rejected CTAPHID packets, not crashes) and that a
   touch prompt while the key is waiting doesn't time out prematurely.
3. **macOS**: same, on a real Mac. Specifically confirm `Close()` doesn't
   hang or crash (the run-loop teardown ordering was written against a
   reference implementation, not verified against a real IOKit device
   yet), and that a second `Open`/`Close` cycle in the same process works
   (confirms the per-device goroutine/thread teardown is clean).
