package trivy

import (
	"os"
	"testing"
)

func TestParseFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/ubuntu-22.04.json")
	if err != nil {
		t.Fatal(err)
	}
	vulns, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(vulns) != 3 {
		t.Fatalf("got %d vulns, want 3", len(vulns))
	}

	v := vulns[0]
	if v.ID != "CVE-2026-27456" {
		t.Errorf("ID = %q", v.ID)
	}
	if v.Severity != "MEDIUM" {
		t.Errorf("Severity = %q", v.Severity)
	}
	if v.Package != "bsdutils" {
		t.Errorf("Package = %q", v.Package)
	}
	if v.Installed != "1:2.37.2-4ubuntu3.5" {
		t.Errorf("Installed = %q", v.Installed)
	}
	if v.LayerDigest == "" {
		t.Error("LayerDigest empty; layer correlation broken")
	}
	if v.Source != "trivy" {
		t.Errorf("Source = %q", v.Source)
	}
	for _, v := range vulns {
		if v.Severity == "" {
			t.Errorf("%s: empty severity after normalization", v.ID)
		}
	}
}

func TestParseUnsupportedSchema(t *testing.T) {
	_, err := Parse([]byte(`{"SchemaVersion": 99, "Results": []}`))
	if err == nil {
		t.Fatal("want error for unsupported schema version, got nil")
	}
}

func TestParseNormalizesBogusSeverity(t *testing.T) {
	vulns, err := Parse([]byte(`{"SchemaVersion": 2, "Results": [
		{"Target": "t", "Vulnerabilities": [
			{"VulnerabilityID": "CVE-1", "PkgName": "p", "Severity": "BANANA"}
		]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if vulns[0].Severity != "UNKNOWN" {
		t.Errorf("Severity = %q, want UNKNOWN", vulns[0].Severity)
	}
}
