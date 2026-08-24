// Package jsonout emits the canonical JSON form of a report.
package jsonout

import (
	"encoding/json"
	"io"

	"github.com/anaskmh/imgvet/pkg/report"
)

// Render writes the report as indented JSON.
func Render(w io.Writer, r *report.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
