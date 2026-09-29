package version

import "runtime"

// Build-time variables injected via -ldflags.
// Defaults are used when the binary is built without the Makefile (e.g. go run).
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
	Branch    = "unknown"
)

// GoVersion reports the Go toolchain that compiled this binary (for example
// "go1.27.1"). It is read from the binary itself, so unlike the -ldflags values
// above it is never missing or wrong, whichever way the binary was built.
func GoVersion() string { return runtime.Version() }
