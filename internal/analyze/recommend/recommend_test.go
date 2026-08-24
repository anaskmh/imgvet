package recommend

import (
	"strings"
	"testing"

	"github.com/anaskmh/imgvet/pkg/report"
)

func TestNodeImageGetsSlimRec(t *testing.T) {
	img := report.ImageInfo{
		Ref:    "index.docker.io/library/node:18",
		Config: report.ImageConfig{Env: []string{"NODE_VERSION=18.20.4", "PATH=/usr/bin"}},
	}
	recs := Recommend(img, nil)
	if len(recs) != 1 {
		t.Fatalf("got %d recs, want 1: %+v", len(recs), recs)
	}
	if !strings.Contains(recs[0].Suggested, "node:18-slim") {
		t.Errorf("suggested = %q, want node:18-slim variant", recs[0].Suggested)
	}
}

func TestAlpineVariantGetsNoRecs(t *testing.T) {
	img := report.ImageInfo{
		Ref:    "index.docker.io/library/node:18-alpine",
		Config: report.ImageConfig{Env: []string{"NODE_VERSION=18.20.4"}},
	}
	if recs := Recommend(img, nil); len(recs) != 0 {
		t.Errorf("alpine variant should get no recs, got %+v", recs)
	}
}

func TestUbuntuBaseRec(t *testing.T) {
	img := report.ImageInfo{Ref: "index.docker.io/library/ubuntu:22.04"}
	recs := Recommend(img, map[string]string{"ID": "ubuntu", "VERSION_ID": "22.04"})
	if len(recs) != 1 {
		t.Fatalf("got %d recs, want 1: %+v", len(recs), recs)
	}
	if !strings.Contains(recs[0].Suggested, "slim") {
		t.Errorf("suggested = %q, want a slim suggestion", recs[0].Suggested)
	}
}

func TestGoToolchainRec(t *testing.T) {
	img := report.ImageInfo{
		Ref:    "index.docker.io/library/golang:1.27",
		Config: report.ImageConfig{Env: []string{"GOLANG_VERSION=1.27.0"}},
	}
	recs := Recommend(img, map[string]string{"ID": "debian"})
	if len(recs) != 1 || !strings.Contains(recs[0].Suggested, "distroless") {
		t.Errorf("want a distroless multi-stage rec, got %+v", recs)
	}
}
