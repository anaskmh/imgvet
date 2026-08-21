// Package table renders a human-readable terminal report.
package table

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/greentruth/imgvet/pkg/report"
)

// Render writes a terminal-friendly summary of the report.
func Render(w io.Writer, r *report.Report) error {
	fmt.Fprintf(w, "Image:    %s\n", r.Image.Ref)
	fmt.Fprintf(w, "Digest:   %s\n", r.Image.Digest)
	fmt.Fprintf(w, "Platform: %s\n", r.Image.Platform)
	fmt.Fprintf(w, "Size:     %s (compressed, %d layers)\n", humanBytes(r.Image.TotalSize), len(r.Layers))
	if !r.Image.Created.IsZero() {
		fmt.Fprintf(w, "Created:  %s\n", r.Image.Created.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w, "LAYERS")
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  #\tSIZE\tFILES\tCOMMAND")
	for _, l := range r.Layers {
		fmt.Fprintf(tw, "  %d\t%s\t%d\t%s\n", l.Index, humanBytes(l.Size), l.FileCount, truncate(l.Command, 80))
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	if len(r.Vulnerabilities) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "VULNERABILITIES")
		tw = tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tID\tPACKAGE\tINSTALLED\tFIXED IN")
		for _, v := range r.Vulnerabilities {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", v.Severity, v.ID, v.Package, v.Installed, orDash(v.FixedIn))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(r.Optimization.WastedFiles) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "TOP WASTED FILES")
		tw = tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SIZE\tREASON\tPATH")
		max := len(r.Optimization.WastedFiles)
		if max > 15 {
			max = 15
		}
		for _, f := range r.Optimization.WastedFiles[:max] {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", humanBytes(f.Bytes), f.Reason, truncate(f.Path, 70))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}

	if len(r.Optimization.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "FINDINGS")
		for _, f := range r.Optimization.Findings {
			loc := ""
			if f.File != "" {
				loc = fmt.Sprintf(" (%s:%d)", f.File, f.Line)
			}
			fmt.Fprintf(w, "  [%s] %s: %s%s\n", strings.ToUpper(f.Severity), f.RuleID, f.Message, loc)
		}
	}

	if len(r.Optimization.BaseImageRecs) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "BASE IMAGE RECOMMENDATIONS")
		for _, rec := range r.Optimization.BaseImageRecs {
			fmt.Fprintf(w, "  %s → %s\n    %s\n", rec.Current, rec.Suggested, rec.Rationale)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "SUMMARY")
	if len(r.Summary.VulnCounts) > 0 {
		fmt.Fprintf(w, "  Vulnerabilities: %s\n", formatCounts(r.Summary.VulnCounts))
	}
	fmt.Fprintf(w, "  Total size:      %s\n", humanBytes(r.Summary.TotalSize))
	if r.Summary.WastedBytes > 0 {
		fmt.Fprintf(w, "  Wasted:          %s\n", humanBytes(r.Summary.WastedBytes))
	}
	if r.Summary.EfficiencyScore > 0 {
		fmt.Fprintf(w, "  Efficiency:      %.1f/100\n", r.Summary.EfficiencyScore)
	}
	return nil
}

var severityOrder = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

func formatCounts(counts map[string]int) string {
	var parts []string
	for _, sev := range severityOrder {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(sev)))
		}
	}
	if len(parts) == 0 {
		return "none found"
	}
	return strings.Join(parts, ", ")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
