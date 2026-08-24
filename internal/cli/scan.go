package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anaskmh/imgvet/internal/engine"
	"github.com/anaskmh/imgvet/internal/image"
	"github.com/anaskmh/imgvet/internal/render/htmlreport"
	"github.com/anaskmh/imgvet/internal/render/jsonout"
	"github.com/anaskmh/imgvet/internal/render/table"
	"github.com/anaskmh/imgvet/pkg/report"
)

// policyError signals a CI gate failure (exit code 2, not 1).
type policyError struct{ msg string }

func (e *policyError) Error() string { return e.msg }

func asPolicyError(err error, target **policyError) bool {
	return errors.As(err, target)
}

func newScanCmd() *cobra.Command {
	var (
		format       string
		output       string
		dockerfile   string
		platform     string
		cacheDir     string
		scanner      string
		severities   []string
		failOn       string
		minScore     float64
		skipVulns    bool
		skipOptimize bool
		timeout      time.Duration
	)

	cmd := &cobra.Command{
		Use:   "scan IMAGE",
		Short: "Scan an image for vulnerabilities and optimization opportunities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "table" && format != "json" && format != "html" {
				return fmt.Errorf("unsupported format %q (supported: table, json, html)", format)
			}
			if scanner != "trivy" && scanner != "none" {
				return fmt.Errorf("unsupported scanner %q (supported: trivy, none)", scanner)
			}
			if failOn != "" && report.SeverityRank(strings.ToUpper(failOn)) >= len(report.Severities) {
				return fmt.Errorf("invalid --fail-on severity %q (one of: %s)", failOn, strings.Join(report.Severities, ", "))
			}

			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}

			rep, err := engine.Run(ctx, engine.Options{
				ImageRef:       args[0],
				Platform:       platform,
				DockerfilePath: dockerfile,
				CacheDir:       cacheDir,
				Scanner:        scanner,
				SkipVulns:      skipVulns,
				SkipOptimize:   skipOptimize,
				Version:        Version,
			})
			if err != nil {
				return err
			}

			filterSeverities(rep, severities)

			out := cmd.OutOrStdout()
			var closeOut func() error
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				out, closeOut = f, f.Close
			}

			var renderErr error
			switch format {
			case "json":
				renderErr = jsonout.Render(out, rep)
			case "html":
				renderErr = htmlreport.Render(out, rep)
			default:
				renderErr = table.Render(out, rep)
			}
			if closeOut != nil {
				if err := closeOut(); err != nil && renderErr == nil {
					renderErr = err
				}
			}
			if renderErr != nil {
				return renderErr
			}
			return gatePolicy(rep, failOn, minScore)
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "table", "output format: table, json")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write output to file instead of stdout")
	cmd.Flags().StringVar(&dockerfile, "dockerfile", "", "path to the image's Dockerfile for lint analysis")
	cmd.Flags().StringVar(&platform, "platform", "", "platform for multi-arch images, e.g. linux/amd64")
	cmd.Flags().StringVar(&cacheDir, "cache-dir", image.DefaultCacheDir(), "directory for cached image tars")
	cmd.Flags().StringVar(&scanner, "scanner", "trivy", "vulnerability scanner backend: trivy, none")
	cmd.Flags().StringSliceVar(&severities, "severity", nil, "only report these severities, e.g. CRITICAL,HIGH")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit 2 if a vulnerability at or above this severity is found")
	cmd.Flags().Float64Var(&minScore, "min-score", 0, "exit 2 if the efficiency score is below this value (0-100)")
	cmd.Flags().BoolVar(&skipVulns, "skip-vulns", false, "skip vulnerability scanning")
	cmd.Flags().BoolVar(&skipOptimize, "skip-optimize", false, "skip optimization analysis")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "overall scan timeout")
	return cmd
}

// filterSeverities drops vulnerabilities outside the requested set and
// recomputes the summary counts.
func filterSeverities(rep *report.Report, severities []string) {
	if len(severities) == 0 {
		return
	}
	keep := map[string]bool{}
	for _, s := range severities {
		keep[strings.ToUpper(strings.TrimSpace(s))] = true
	}
	filtered := rep.Vulnerabilities[:0]
	for _, v := range rep.Vulnerabilities {
		if keep[v.Severity] {
			filtered = append(filtered, v)
		}
	}
	rep.Vulnerabilities = filtered
	counts := map[string]int{}
	for _, v := range rep.Vulnerabilities {
		counts[v.Severity]++
	}
	rep.Summary.VulnCounts = counts
}

// gatePolicy enforces the CI gates: --fail-on (vulnerability severity) and
// --min-score (efficiency). Violations exit with code 2.
func gatePolicy(rep *report.Report, failOn string, minScore float64) error {
	var failures []string
	if failOn != "" {
		threshold := report.SeverityRank(strings.ToUpper(failOn))
		count := 0
		for _, v := range rep.Vulnerabilities {
			if report.SeverityRank(v.Severity) <= threshold {
				count++
			}
		}
		if count > 0 {
			failures = append(failures, fmt.Sprintf("%d vulnerabilities at or above %s", count, strings.ToUpper(failOn)))
		}
	}
	if minScore > 0 && rep.Optimization.EfficiencyScore < minScore {
		failures = append(failures, fmt.Sprintf("efficiency score %.1f below minimum %.1f", rep.Optimization.EfficiencyScore, minScore))
	}
	if len(failures) > 0 {
		return &policyError{msg: "policy failure: " + strings.Join(failures, "; ")}
	}
	return nil
}
