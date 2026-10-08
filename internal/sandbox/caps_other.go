//go:build !linux

package sandbox

// DropAmbientCaps is a no-op outside Linux, which has no ambient capabilities.
func DropAmbientCaps() error { return nil }
