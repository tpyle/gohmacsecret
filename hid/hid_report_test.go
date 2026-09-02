package hid

import (
	"bytes"
	"testing"
)

func TestBuildOutputReport(t *testing.T) {
	tests := []struct {
		name   string
		report []byte
		outLen int
		want   []byte
	}{
		{
			name:   "prepends report ID and pads",
			report: []byte{1, 2, 3},
			outLen: 8,
			want:   []byte{0, 1, 2, 3, 0, 0, 0, 0},
		},
		{
			name:   "exact fit",
			report: []byte{1, 2, 3},
			outLen: 4,
			want:   []byte{0, 1, 2, 3},
		},
		{
			name:   "truncates a report longer than outLen-1",
			report: []byte{1, 2, 3, 4, 5},
			outLen: 4,
			want:   []byte{0, 1, 2, 3},
		},
		{
			name:   "outLen of zero is treated as one",
			report: []byte{1, 2, 3},
			outLen: 0,
			want:   []byte{0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildOutputReport(tt.report, tt.outLen)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("buildOutputReport(%v, %d) = %v, want %v", tt.report, tt.outLen, got, tt.want)
			}
		})
	}
}

func TestStripInputReportPrefix(t *testing.T) {
	got, err := stripInputReportPrefix([]byte{0, 1, 2, 3})
	if err != nil {
		t.Fatalf("stripInputReportPrefix() err = %v", err)
	}
	if want := []byte{1, 2, 3}; !bytes.Equal(got, want) {
		t.Errorf("stripInputReportPrefix() = %v, want %v", got, want)
	}
}

func TestStripInputReportPrefix_Empty(t *testing.T) {
	if _, err := stripInputReportPrefix(nil); err == nil {
		t.Fatal("stripInputReportPrefix(nil) = nil error, want an error")
	}
}
