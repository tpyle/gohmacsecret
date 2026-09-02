package hid

// matchesFIDO reports whether the given HID usage page/usage identify a
// FIDO2 CTAPHID authenticator - the same 0xF1D0/0x01 convention every
// platform's backend filters on, factored out as a pure function so it's
// unit-testable without a real macOS IOKit service to query.
func matchesFIDO(usagePage, usage int) bool {
	return usagePage == fidoUsagePage && usage == fidoUsage
}
