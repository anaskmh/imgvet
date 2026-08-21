// Package dockerfile lints Dockerfiles with size- and security-focused
// heuristics. It parses with buildkit's canonical parser for line-accurate
// findings, and can also run a reduced rule set against image config history
// when no Dockerfile is available.
package dockerfile

import (
	"fmt"
	"os"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"

	"github.com/greentruth/imgvet/pkg/report"
)

// Lint parses the Dockerfile at path and runs all rules.
func Lint(path string) ([]report.Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	res, err := parser.Parse(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	stages, _, err := instructions.Parse(res.AST, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing %s instructions: %w", path, err)
	}

	df := &file{path: path, stages: stages}
	var findings []report.Finding
	for _, rule := range rules {
		findings = append(findings, rule(df)...)
	}
	return findings, nil
}

// file is the parsed Dockerfile handed to rules.
type file struct {
	path   string
	stages []instructions.Stage
}

// finalStage returns the stage that becomes the image.
func (f *file) finalStage() *instructions.Stage {
	if len(f.stages) == 0 {
		return nil
	}
	return &f.stages[len(f.stages)-1]
}

func (f *file) finding(ruleID, severity, msg string, line int) report.Finding {
	return report.Finding{
		RuleID:   ruleID,
		Severity: severity,
		Message:  msg,
		File:     f.path,
		Line:     line,
	}
}

func line(c instructions.Command) int {
	loc := c.Location()
	if len(loc) > 0 {
		return loc[0].Start.Line
	}
	return 0
}
