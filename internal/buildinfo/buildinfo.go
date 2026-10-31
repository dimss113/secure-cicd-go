// Package buildinfo carries values stamped in at build time with -ldflags -X.
package buildinfo

var (
	Commit    = "dev"
	BuildTime = "unknown"
)
