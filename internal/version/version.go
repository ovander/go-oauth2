package version

// Build-time variables injected via -ldflags.
// Defaults are used when the binary is built without the Makefile (e.g. go run).
var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
	Branch    = "unknown"
)
