package hid

import "testing"

func TestMatchesFIDO(t *testing.T) {
	if !matchesFIDO(0xF1D0, 0x01) {
		t.Error("matchesFIDO(0xF1D0, 0x01) = false, want true")
	}
	if matchesFIDO(0xFF00, 0x01) {
		t.Error("matchesFIDO(0xFF00, 0x01) = true, want false (wrong usage page)")
	}
	if matchesFIDO(0xF1D0, 0x02) {
		t.Error("matchesFIDO(0xF1D0, 0x02) = true, want false (wrong usage)")
	}
}
