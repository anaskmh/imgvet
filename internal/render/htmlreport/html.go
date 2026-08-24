// Package htmlreport renders a self-contained single-file HTML report: the
// embedded template carries inline CSS/JS and the report JSON, so the file
// works offline as a CI artifact or email attachment.
package htmlreport

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"

	"github.com/anaskmh/imgvet/pkg/report"
)

//go:embed assets/template.html
var template []byte

const placeholder = "__REPORT_JSON__"

// maxEmbeddedVulns caps the vulnerability list embedded in the HTML so
// pathological images don't produce unloadable files.
const maxEmbeddedVulns = 5000

// Render writes the report as a standalone HTML file.
func Render(w io.Writer, r *report.Report) error {
	trimmed := *r
	if len(trimmed.Vulnerabilities) > maxEmbeddedVulns {
		trimmed.Vulnerabilities = trimmed.Vulnerabilities[:maxEmbeddedVulns]
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// SetEscapeHTML escapes <, >, and & in JSON strings, so report content
	// cannot break out of the <script> element.
	enc.SetEscapeHTML(true)
	if err := enc.Encode(&trimmed); err != nil {
		return fmt.Errorf("encoding report: %w", err)
	}

	out := bytes.Replace(template, []byte(placeholder), bytes.TrimSpace(buf.Bytes()), 1)
	_, err := w.Write(out)
	return err
}
