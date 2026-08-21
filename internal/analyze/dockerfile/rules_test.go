package dockerfile

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

func findingIDs(t *testing.T, path string) map[string]int {
	t.Helper()
	findings, err := Lint(path)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, f := range findings {
		ids[f.RuleID]++
	}
	return ids
}

func TestLintBadDockerfile(t *testing.T) {
	ids := findingIDs(t, "testdata/bad.Dockerfile")
	for _, want := range []string{
		"IV-DF-001", // apt cache not cleaned
		"IV-DF-003", // pip without --no-cache-dir
		"IV-DF-004", // COPY . .
		"IV-DF-005", // ADD where COPY suffices
		"IV-DF-006", // unpinned base tag
		"IV-DF-007", // no non-root USER
		"IV-DF-008", // secret in ENV
		"IV-DF-009", // missing multi-stage
	} {
		if ids[want] == 0 {
			t.Errorf("rule %s did not fire on bad.Dockerfile; got %v", want, ids)
		}
	}
}

func TestLintGoodDockerfile(t *testing.T) {
	ids := findingIDs(t, "testdata/good.Dockerfile")
	if len(ids) != 0 {
		t.Errorf("good.Dockerfile should be clean, got findings: %v", ids)
	}
}

func TestLintFindingsHaveLines(t *testing.T) {
	findings, err := Lint("testdata/bad.Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "IV-DF-001" && f.Line != 3 {
			t.Errorf("IV-DF-001 line = %d, want 3", f.Line)
		}
		if f.RuleID == "IV-DF-008" && f.Line != 2 {
			t.Errorf("IV-DF-008 line = %d, want 2", f.Line)
		}
	}
}

func TestLintHistory(t *testing.T) {
	history := []v1.History{
		{CreatedBy: "/bin/sh -c apt-get update && apt-get install -y curl"},
		{CreatedBy: "/bin/sh -c #(nop) CMD [\"bash\"]", EmptyLayer: true},
		{CreatedBy: "RUN /bin/sh -c apk add git # buildkit"},
		{CreatedBy: "RUN /bin/sh -c apk add --no-cache jq # buildkit"},
		{CreatedBy: "/bin/sh -c apt-get install -y vim && rm -rf /var/lib/apt/lists/*"},
	}
	findings := LintHistory(history)
	ids := map[string]int{}
	for _, f := range findings {
		ids[f.RuleID]++
	}
	if ids["IV-DF-001"] != 1 {
		t.Errorf("IV-DF-001 count = %d, want 1 (cleaned apt run must not fire)", ids["IV-DF-001"])
	}
	if ids["IV-DF-002"] != 1 {
		t.Errorf("IV-DF-002 count = %d, want 1 (--no-cache apk run must not fire)", ids["IV-DF-002"])
	}
}
