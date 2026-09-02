//go:build !linux && !windows && !darwin

package hid

import (
	"errors"
	"testing"
)

func TestDiscover_UnsupportedPlatform(t *testing.T) {
	if _, err := Discover(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Discover() err = %v, want ErrUnsupportedPlatform", err)
	}
}

func TestOpen_UnsupportedPlatform(t *testing.T) {
	if _, err := Open(Info{}); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Open() err = %v, want ErrUnsupportedPlatform", err)
	}
}
