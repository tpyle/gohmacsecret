//go:build !linux && !windows && !darwin

package hid

// Discover always returns ErrUnsupportedPlatform - this package has no
// backend for this GOOS.
func Discover() ([]Info, error) {
	return nil, ErrUnsupportedPlatform
}

// Open always returns ErrUnsupportedPlatform - this package has no
// backend for this GOOS.
func Open(Info) (Device, error) {
	return nil, ErrUnsupportedPlatform
}
