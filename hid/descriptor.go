package hid

import (
	"encoding/binary"
	"fmt"
)

// HID report descriptor item tags this package needs to recognize - a
// tiny subset of the full USB HID item set, sufficient to find a
// top-level Usage Page/Usage and confirm both an Input and an Output
// report are declared (every well-formed CTAPHID device has both).
const (
	itemKeyMask  = 0xFC
	itemSizeMask = 0x03 // treated as a literal byte count (0-3), not USB HID's official size-code mapping (which maps code 3 to 4 bytes) - real FIDO descriptors never use size code 3 for these particular short items, so the two interpretations never disagree in practice; kept this way to match python-fido2's own parser, which has been validated against real hardware for years

	itemInput       = 0x80
	itemOutput      = 0x90
	itemUsagePage   = 0x04
	itemUsage       = 0x08
	itemReportCount = 0x94
	itemReportSize  = 0x74
)

const (
	fidoUsagePage = 0xF1D0
	fidoUsage     = 0x01
)

// parseReportDescriptor scans a raw HID report descriptor for its
// top-level Usage Page and Usage, additionally requiring that both an
// Input and an Output report be declared (every well-formed CTAPHID
// device has both) before accepting it as a FIDO device. This is a
// direct port of python-fido2's parse_report_descriptor - a real FIDO
// device's report descriptor is only ever a few dozen bytes, and this
// linear scan (rather than a full HID descriptor parser with collection
// nesting) is exactly what that reference implementation relies on.
func parseReportDescriptor(data []byte) (usagePage, usage int, err error) {
	haveReportCount, haveReportSize := false, false
	haveInput, haveOutput := false, false
	remaining := 4 // usagePage, usage, an Input report, and an Output report

	for len(data) > 0 && remaining > 0 {
		head := data[0]
		data = data[1:]
		key := int(head) & itemKeyMask
		size := int(head) & itemSizeMask
		if size > len(data) {
			return 0, 0, fmt.Errorf("hid: truncated report descriptor")
		}
		buf := make([]byte, 4)
		copy(buf, data[:size])
		value := int(binary.LittleEndian.Uint32(buf))
		data = data[size:]

		if haveReportCount && haveReportSize {
			switch key {
			case itemInput:
				if !haveInput {
					haveInput = true
					haveReportCount, haveReportSize = false, false
					remaining--
				}
			case itemOutput:
				if !haveOutput {
					haveOutput = true
					haveReportCount, haveReportSize = false, false
					remaining--
				}
			}
		}
		switch key {
		case itemUsagePage:
			if usagePage == 0 {
				usagePage = value
				remaining--
			}
		case itemUsage:
			if usage == 0 {
				usage = value
				remaining--
			}
		case itemReportCount:
			haveReportCount = true
		case itemReportSize:
			haveReportSize = true
		}
	}

	if remaining != 0 {
		return 0, 0, fmt.Errorf("hid: incomplete report descriptor")
	}
	return usagePage, usage, nil
}
