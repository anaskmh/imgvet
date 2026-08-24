// Package scan defines the pluggable vulnerability scanner interface.
// Backends wrap external engines (trivy, grype, ...) and normalize their
// output into the report schema.
package scan

import (
	"context"
	"time"

	"github.com/anaskmh/imgvet/pkg/report"
)

// Input is what a scanner backend receives. The image has already been
// exported to a docker-archive tar so backends never pull it again.
type Input struct {
	ImageRef string // original reference, for metadata only
	TarPath  string // docker-archive tar on local disk
}

// Meta describes the backend that produced the findings.
type Meta struct {
	Version   string
	DBUpdated *time.Time
}

// Scanner is a vulnerability scanning backend.
type Scanner interface {
	Name() string
	// Available reports whether the backend can run (e.g. binary on PATH),
	// returning an actionable error (install hint) when it cannot.
	Available(ctx context.Context) error
	Scan(ctx context.Context, in Input) ([]report.Vulnerability, Meta, error)
}
