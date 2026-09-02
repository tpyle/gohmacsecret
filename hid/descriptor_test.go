package hid

import "testing"

// fidoDescriptor builds a minimal, well-formed report descriptor
// declaring usage page/usage plus one Input and one Output report -
// shaped like (though not byte-identical to) a real FIDO security key's
// descriptor, sufficient to exercise parseReportDescriptor's actual
// logic rather than a real device's exact bytes.
func fidoDescriptor(usagePage, usage uint16) []byte {
	return []byte{
		0x06, byte(usagePage), byte(usagePage >> 8), //nolint:gosec // deliberate low/high byte split of a test fixture value, not a truncation
		0x09, byte(usage), //nolint:gosec // test fixture always passes a value that fits in one byte
		0x75, 0x08, // Report Size (8)
		0x95, 0x40, // Report Count (64)
		0x81, 0x02, // Input (Data,Var,Abs) - consumes Report Size/Count, resetting both
		0x75, 0x08, // Report Size (8) again, for Output - parseReportDescriptor
		0x95, 0x40, // Report Count (64) again, for Output - requires BOTH freshly
		0x91, 0x02, // Output (Data,Var,Abs) - re-set since the last Input consumed them
	}
}

func TestParseReportDescriptorFIDODevice(t *testing.T) {
	usagePage, usage, err := parseReportDescriptor(fidoDescriptor(fidoUsagePage, fidoUsage))
	if err != nil {
		t.Fatalf("parseReportDescriptor: %v", err)
	}
	if usagePage != fidoUsagePage {
		t.Errorf("usagePage = %#x, want %#x", usagePage, fidoUsagePage)
	}
	if usage != fidoUsage {
		t.Errorf("usage = %#x, want %#x", usage, fidoUsage)
	}
}

func TestParseReportDescriptorNonFIDODevice(t *testing.T) {
	// A well-formed descriptor for some other device (e.g. a keyboard,
	// usage page 0x01/usage 0x06) parses fine - callers are expected to
	// check the returned usage page/usage themselves, not treat a parse
	// error as "not FIDO".
	usagePage, usage, err := parseReportDescriptor(fidoDescriptor(0x01, 0x06))
	if err != nil {
		t.Fatalf("parseReportDescriptor: %v", err)
	}
	if usagePage == fidoUsagePage && usage == fidoUsage {
		t.Fatal("got FIDO usage page/usage from a descriptor that didn't declare them")
	}
}

func TestParseReportDescriptorMissingOutput(t *testing.T) {
	// Everything except the trailing Output item - an Input-only device
	// (or any descriptor missing one of the four required elements)
	// must be rejected, not silently accepted with a zero-value usage.
	d := fidoDescriptor(fidoUsagePage, fidoUsage)
	incomplete := d[:len(d)-2] // drop the final Output item
	if _, _, err := parseReportDescriptor(incomplete); err == nil {
		t.Fatal("expected an error for a descriptor missing an Output report, got nil")
	}
}

func TestParseReportDescriptorEmpty(t *testing.T) {
	if _, _, err := parseReportDescriptor(nil); err == nil {
		t.Fatal("expected an error for an empty descriptor, got nil")
	}
}

func TestParseReportDescriptorTruncatedItem(t *testing.T) {
	// A Usage Page item claiming a 2-byte value with only 1 byte left.
	if _, _, err := parseReportDescriptor([]byte{0x06, 0xD0}); err == nil {
		t.Fatal("expected an error for a truncated item, got nil")
	}
}
