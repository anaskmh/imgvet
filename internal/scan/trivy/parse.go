package trivy

import (
	"encoding/json"
	"fmt"

	"github.com/greentruth/imgvet/pkg/report"
)

// supportedSchemaVersion is the trivy JSON schema this adapter understands.
// The contract test in parse_test.go fails loudly if trivy drifts.
const supportedSchemaVersion = 2

type trivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	Results       []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string      `json:"Target"`
	Class           string      `json:"Class"`
	Type            string      `json:"Type"`
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
	Layer            struct {
		Digest string `json:"Digest"`
		DiffID string `json:"DiffID"`
	} `json:"Layer"`
}

var validSeverities = map[string]bool{
	"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true,
}

// Parse converts trivy JSON output into normalized vulnerabilities.
func Parse(data []byte) ([]report.Vulnerability, error) {
	var tr trivyReport
	if err := json.Unmarshal(data, &tr); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}
	if tr.SchemaVersion != supportedSchemaVersion {
		return nil, fmt.Errorf("unsupported trivy JSON schema version %d (imgvet supports %d); upgrade imgvet or pin trivy",
			tr.SchemaVersion, supportedSchemaVersion)
	}

	var out []report.Vulnerability
	for _, res := range tr.Results {
		for _, v := range res.Vulnerabilities {
			sev := v.Severity
			if !validSeverities[sev] {
				sev = "UNKNOWN"
			}
			layerRef := v.Layer.Digest
			if layerRef == "" {
				layerRef = v.Layer.DiffID
			}
			out = append(out, report.Vulnerability{
				ID:          v.VulnerabilityID,
				Severity:    sev,
				Package:     v.PkgName,
				Installed:   v.InstalledVersion,
				FixedIn:     v.FixedVersion,
				LayerDigest: layerRef,
				Title:       v.Title,
				URL:         v.PrimaryURL,
				Source:      "trivy",
			})
		}
	}
	return out, nil
}
