// Package engine orchestrates the scan pipeline: image resolution, analyzer
// fan-out, and report assembly.
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/errgroup"

	"github.com/anaskmh/imgvet/internal/analyze/dockerfile"
	"github.com/anaskmh/imgvet/internal/analyze/filetree"
	"github.com/anaskmh/imgvet/internal/analyze/layers"
	"github.com/anaskmh/imgvet/internal/analyze/recommend"
	"github.com/anaskmh/imgvet/internal/image"
	"github.com/anaskmh/imgvet/internal/scan"
	"github.com/anaskmh/imgvet/internal/scan/trivy"
	"github.com/anaskmh/imgvet/pkg/report"
)

// Options configures a single scan run.
type Options struct {
	ImageRef       string
	Platform       string
	DockerfilePath string
	CacheDir       string
	Scanner        string // "trivy" (default) or "none"
	SkipVulns      bool
	SkipOptimize   bool
	Version        string // imgvet version for ToolInfo
}

// Run executes the pipeline and returns the assembled report.
func Run(ctx context.Context, opts Options) (*report.Report, error) {
	resolved, err := image.Resolve(ctx, opts.ImageRef, image.Options{Platform: opts.Platform})
	if err != nil {
		return nil, err
	}

	digest, err := resolved.Image.Digest()
	if err != nil {
		return nil, fmt.Errorf("computing digest: %w", err)
	}
	mediaType, err := resolved.Image.MediaType()
	if err != nil {
		return nil, fmt.Errorf("reading media type: %w", err)
	}
	cfg, err := resolved.Image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	scanner := selectScanner(opts)

	var (
		layerInfo []report.Layer
		treeRes   *filetree.Result
		vulns     = []report.Vulnerability{}
		scanMeta  scan.Meta
	)

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		var err error
		layerInfo, err = layers.Analyze(resolved.Image)
		if err != nil {
			return fmt.Errorf("analyzing layers: %w", err)
		}
		return nil
	})
	if !opts.SkipOptimize {
		g.Go(func() error {
			var err error
			treeRes, err = filetree.Analyze(resolved.Image)
			if err != nil {
				return fmt.Errorf("analyzing filetree: %w", err)
			}
			return nil
		})
	}
	if scanner != nil {
		g.Go(func() error {
			if err := scanner.Available(gctx); err != nil {
				// Degrade gracefully: report without vulns rather than failing.
				slog.Warn("vulnerability scanning skipped", "reason", err.Error())
				return nil
			}
			cacheDir := opts.CacheDir
			if cacheDir == "" {
				cacheDir = image.DefaultCacheDir()
			}
			tarPath, err := image.Export(resolved.Image, resolved.Ref, cacheDir)
			if err != nil {
				return fmt.Errorf("exporting image for scanner: %w", err)
			}
			v, meta, err := scanner.Scan(gctx, scan.Input{ImageRef: resolved.Ref, TarPath: tarPath})
			if err != nil {
				return err
			}
			sortVulns(v)
			vulns, scanMeta = v, meta
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	var optimization report.Optimization
	if treeRes != nil {
		for i := range layerInfo {
			if i < len(treeRes.PerLayer) {
				layerInfo[i].FileCount = treeRes.PerLayer[i].FileCount
				layerInfo[i].WastedBytes = treeRes.PerLayer[i].WastedBytes
			}
		}
		optimization = report.Optimization{
			EfficiencyScore: treeRes.EfficiencyScore,
			WastedBytes:     treeRes.WastedBytes,
			WastedFiles:     topN(treeRes.WastedFiles, 50),
		}
	}

	if !opts.SkipOptimize {
		optimization.Findings = collectFindings(opts, cfg)
		optimization.EfficiencyScore = penalize(optimization.EfficiencyScore, optimization.Findings)
	}

	var totalSize int64
	for _, l := range layerInfo {
		totalSize += l.Size
	}

	r := &report.Report{
		SchemaVersion: report.SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Tool: report.ToolInfo{
			Name:    "imgvet",
			Version: opts.Version,
		},
		Image: report.ImageInfo{
			Ref:       resolved.Ref,
			Digest:    digest.String(),
			MediaType: string(mediaType),
			Platform:  cfg.OS + "/" + cfg.Architecture,
			TotalSize: totalSize,
			Created:   cfg.Created.UTC(),
			OS:        cfg.OS,
			Config: report.ImageConfig{
				Env:        cfg.Config.Env,
				Entrypoint: cfg.Config.Entrypoint,
				Cmd:        cfg.Config.Cmd,
				User:       cfg.Config.User,
				WorkingDir: cfg.Config.WorkingDir,
			},
		},
		Layers:          layerInfo,
		Vulnerabilities: vulns,
		Optimization:    optimization,
	}

	// OS details from /etc/os-release, base image from the OCI annotation.
	if treeRes != nil && treeRes.OSRelease != nil {
		r.Image.OS = firstNonEmpty(treeRes.OSRelease["ID"], r.Image.OS)
		r.Image.OSVersion = treeRes.OSRelease["VERSION_ID"]
	}
	if m, err := resolved.Image.Manifest(); err == nil && m != nil {
		if base := m.Annotations["org.opencontainers.image.base.name"]; base != "" {
			r.Image.BaseImage = base
		}
	}
	if !opts.SkipOptimize {
		var osRelease map[string]string
		if treeRes != nil {
			osRelease = treeRes.OSRelease
		}
		r.Optimization.BaseImageRecs = recommend.Recommend(r.Image, osRelease)
	}

	if scanner != nil {
		r.Tool.Scanner = scanner.Name()
		r.Tool.ScannerVersion = scanMeta.Version
		r.Tool.VulnDBUpdated = scanMeta.DBUpdated
	}
	r.Summary = summarize(r)
	return r, nil
}

// collectFindings lints the Dockerfile when one is available and always runs
// the reduced history-based rules against the image config.
func collectFindings(opts Options, cfg *v1.ConfigFile) []report.Finding {
	var findings []report.Finding
	dfPath := opts.DockerfilePath
	if dfPath == "" {
		if _, err := os.Stat("Dockerfile"); err == nil {
			dfPath = "Dockerfile"
			slog.Info("linting ./Dockerfile (pass --dockerfile to override)")
		}
	}
	if dfPath != "" {
		f, err := dockerfile.Lint(dfPath)
		if err != nil {
			slog.Warn("dockerfile lint skipped", "path", dfPath, "reason", err)
		} else {
			findings = append(findings, f...)
		}
		return findings
	}
	// No Dockerfile: fall back to image history heuristics.
	return dockerfile.LintHistory(cfg.History)
}

// penalize subtracts a capped penalty for lint findings from the base
// efficiency score: 2 points per error, 1 per warning, at most 15 total.
func penalize(score float64, findings []report.Finding) float64 {
	penalty := 0.0
	for _, f := range findings {
		switch f.Severity {
		case "error":
			penalty += 2
		case "warn":
			penalty += 1
		}
	}
	if penalty > 15 {
		penalty = 15
	}
	s := score - penalty
	if s < 0 {
		return 0
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// topN truncates the wasted-file list to keep reports a manageable size.
func topN(files []report.WastedFile, n int) []report.WastedFile {
	if len(files) > n {
		return files[:n]
	}
	return files
}

func selectScanner(opts Options) scan.Scanner {
	if opts.SkipVulns || opts.Scanner == "none" {
		return nil
	}
	return trivy.New()
}

func sortVulns(v []report.Vulnerability) {
	sort.SliceStable(v, func(i, j int) bool {
		ri, rj := report.SeverityRank(v[i].Severity), report.SeverityRank(v[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return v[i].ID > v[j].ID // newer CVEs first within a severity
	})
}

func summarize(r *report.Report) report.Summary {
	s := report.Summary{
		VulnCounts:      map[string]int{},
		FindingCounts:   map[string]int{},
		TotalSize:       r.Image.TotalSize,
		WastedBytes:     r.Optimization.WastedBytes,
		EfficiencyScore: r.Optimization.EfficiencyScore,
	}
	for _, v := range r.Vulnerabilities {
		s.VulnCounts[v.Severity]++
	}
	for _, f := range r.Optimization.Findings {
		s.FindingCounts[f.Severity]++
	}
	return s
}
