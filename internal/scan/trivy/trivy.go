// Package trivy adapts the trivy CLI as a scan.Scanner. It execs the binary
// and consumes trivy's versioned JSON output — the supported integration
// surface — rather than importing trivy's unstable Go API.
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/anaskmh/imgvet/internal/scan"
	"github.com/anaskmh/imgvet/pkg/report"
)

const installHint = "trivy not found on PATH. Install it (https://trivy.dev/latest/getting-started/installation/):\n" +
	"  brew install trivy         # macOS\n" +
	"  apt-get install trivy      # Debian/Ubuntu (see docs for repo setup)\n" +
	"or rerun with --skip-vulns / --scanner none to scan without vulnerability data."

// Scanner runs the trivy binary.
type Scanner struct {
	// Binary is the trivy executable; defaults to "trivy" on PATH.
	Binary string
}

func New() *Scanner { return &Scanner{Binary: "trivy"} }

func (s *Scanner) Name() string { return "trivy" }

func (s *Scanner) Available(ctx context.Context) error {
	if _, err := exec.LookPath(s.Binary); err != nil {
		return fmt.Errorf("%s", installHint)
	}
	return nil
}

func (s *Scanner) Scan(ctx context.Context, in scan.Input) ([]report.Vulnerability, scan.Meta, error) {
	meta := s.meta(ctx)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, s.Binary, "image",
		"--input", in.TarPath,
		"--format", "json",
		"--scanners", "vuln",
		"--quiet",
	)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, meta, fmt.Errorf("trivy failed: %w\n%s", err, lastLines(stderr.String(), 5))
	}

	vulns, err := Parse(stdout.Bytes())
	if err != nil {
		return nil, meta, err
	}
	return vulns, meta, nil
}

// meta best-effort collects trivy's version and vulnerability DB age.
func (s *Scanner) meta(ctx context.Context) scan.Meta {
	out, err := exec.CommandContext(ctx, s.Binary, "--version", "--format", "json").Output()
	if err != nil {
		return scan.Meta{}
	}
	var v struct {
		Version         string `json:"Version"`
		VulnerabilityDB struct {
			UpdatedAt time.Time `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if json.Unmarshal(out, &v) != nil {
		return scan.Meta{}
	}
	m := scan.Meta{Version: v.Version}
	if !v.VulnerabilityDB.UpdatedAt.IsZero() {
		t := v.VulnerabilityDB.UpdatedAt
		m.DBUpdated = &t
	}
	return m
}

func lastLines(s string, n int) string {
	lines := bytes.Split(bytes.TrimSpace([]byte(s)), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return string(bytes.Join(lines, []byte("\n")))
}
