package htmlreport

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/greentruth/imgvet/pkg/report"
)

func sampleReport() *report.Report {
	return &report.Report{
		SchemaVersion: report.SchemaVersion,
		GeneratedAt:   time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC),
		Tool:          report.ToolInfo{Name: "imgvet", Version: "test"},
		Image: report.ImageInfo{
			Ref: "example.com/app:1.0", Digest: "sha256:abc", Platform: "linux/amd64", TotalSize: 1000,
		},
		Layers: []report.Layer{{Index: 0, Digest: "sha256:l0", Size: 1000, Command: "ADD rootfs /", FileCount: 3}},
		Vulnerabilities: []report.Vulnerability{{
			ID: "CVE-2026-0001", Severity: "HIGH", Package: "libfoo", Installed: "1.0",
			// Script-breakout attempt: must not terminate the JSON <script> block.
			Title: "</script><script>alert(1)</script>", Source: "trivy",
		}},
		Summary: report.Summary{VulnCounts: map[string]int{"HIGH": 1}, TotalSize: 1000},
	}
}

func TestRenderWellFormedHTML(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	if _, err := html.Parse(strings.NewReader(out)); err != nil {
		t.Fatalf("output is not parseable HTML: %v", err)
	}
	if !strings.Contains(out, `id="report-data"`) {
		t.Error("missing embedded report JSON block")
	}
	if strings.Contains(out, placeholder) {
		t.Error("placeholder not substituted")
	}
	if !strings.Contains(out, "CVE-2026-0001") {
		t.Error("report data not embedded")
	}
	// The raw closing tag from the malicious title must have been escaped.
	if strings.Contains(out, "</script><script>alert(1)</script>") {
		t.Error("unescaped </script> in embedded JSON: XSS/breakout risk")
	}
}

func TestRenderCapsVulnList(t *testing.T) {
	r := sampleReport()
	r.Vulnerabilities = make([]report.Vulnerability, maxEmbeddedVulns+100)
	for i := range r.Vulnerabilities {
		r.Vulnerabilities[i] = report.Vulnerability{ID: "CVE-X", Severity: "LOW", Source: "trivy"}
	}
	var buf bytes.Buffer
	if err := Render(&buf, r); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(buf.String(), `"CVE-X"`); n != maxEmbeddedVulns {
		t.Errorf("embedded %d vulns, want cap of %d", n, maxEmbeddedVulns)
	}
}
