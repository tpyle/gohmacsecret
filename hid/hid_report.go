package hid

import "fmt"

// buildOutputReport returns a Windows-shaped output report: a leading
// 0x00 report-ID byte (FIDO devices don't use numbered reports) followed
// by report, zero-padded or truncated to exactly outLen bytes total -
// WriteFile silently mishandles a buffer shorter than the device's
// negotiated output report length.
func buildOutputReport(report []byte, outLen int) []byte {
	if outLen < 1 {
		outLen = 1
	}
	buf := make([]byte, outLen)
	// buf[0] is left 0x00 (the report-ID byte); copy starts at index 1.
	copy(buf[1:], report)
	return buf
}

// stripInputReportPrefix removes the leading 0x00 report-ID byte Windows
// always prepends to what ReadFile returns for a report-ID-less device.
func stripInputReportPrefix(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("hid: empty input report")
	}
	return buf[1:], nil
}
