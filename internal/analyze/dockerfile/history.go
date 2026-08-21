package dockerfile

import (
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/greentruth/imgvet/pkg/report"
)

// LintHistory runs the RUN-command heuristics against image config history.
// This catches package-cache waste even when no Dockerfile is available;
// findings carry no file/line, only the offending command.
func LintHistory(history []v1.History) []report.Finding {
	var out []report.Finding
	seen := map[string]bool{}
	for _, h := range history {
		if h.EmptyLayer {
			continue
		}
		cmd := h.CreatedBy
		for _, issue := range checkRunCommand(cmd) {
			// Dedup identical rule+command pairs (multi-arch manifests can
			// repeat history entries).
			key := issue.RuleID + "|" + cmd
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, report.Finding{
				RuleID:   issue.RuleID,
				Severity: "warn",
				Message:  issue.Message + " (from image history: " + truncate(cmd, 100) + ")",
			})
		}
	}
	return out
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
