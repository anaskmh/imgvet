// Package report defines the unified imgvet report schema. It is the public
// JSON contract consumed by downstream tooling; changes must bump SchemaVersion.
package report

import "time"

// SchemaVersion is the current version of the report JSON schema.
const SchemaVersion = 1

// Report is the top-level result of scanning a single image.
type Report struct {
	SchemaVersion   int             `json:"schemaVersion"`
	GeneratedAt     time.Time       `json:"generatedAt"`
	Tool            ToolInfo        `json:"tool"`
	Image           ImageInfo       `json:"image"`
	Layers          []Layer         `json:"layers"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	Optimization    Optimization    `json:"optimization"`
	Summary         Summary         `json:"summary"`
}

// ToolInfo records what produced the report.
type ToolInfo struct {
	Name           string     `json:"name"`
	Version        string     `json:"version"`
	Scanner        string     `json:"scanner,omitempty"`
	ScannerVersion string     `json:"scannerVersion,omitempty"`
	VulnDBUpdated  *time.Time `json:"vulnDBUpdated,omitempty"`
}

// ImageInfo describes the scanned image.
type ImageInfo struct {
	Ref       string      `json:"ref"`
	Digest    string      `json:"digest"`
	MediaType string      `json:"mediaType"`
	Platform  string      `json:"platform"` // e.g. linux/amd64
	TotalSize int64       `json:"totalSize"` // sum of compressed layer sizes
	Created   time.Time   `json:"created"`
	OS        string      `json:"os,omitempty"`
	OSVersion string      `json:"osVersion,omitempty"`
	BaseImage string      `json:"baseImage,omitempty"` // best-effort
	Config    ImageConfig `json:"config"`
}

// ImageConfig is the subset of the OCI image config relevant to findings.
type ImageConfig struct {
	Env        []string `json:"env,omitempty"`
	Entrypoint []string `json:"entrypoint,omitempty"`
	Cmd        []string `json:"cmd,omitempty"`
	User       string   `json:"user,omitempty"`
	WorkingDir string   `json:"workingDir,omitempty"`
}

// Layer is one image layer with its provenance and waste stats.
type Layer struct {
	Index       int    `json:"index"`
	Digest      string `json:"digest"`
	DiffID      string `json:"diffID"`
	Size        int64  `json:"size"` // compressed
	Command     string `json:"command,omitempty"`
	FileCount   int    `json:"fileCount"`
	WastedBytes int64  `json:"wastedBytes"`
}

// Vulnerability is a normalized finding from a scanner backend.
type Vulnerability struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"` // CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN
	Package     string `json:"package"`
	Installed   string `json:"installedVersion"`
	FixedIn     string `json:"fixedVersion,omitempty"`
	LayerDigest string `json:"layerDigest,omitempty"`
	Title       string `json:"title,omitempty"`
	URL         string `json:"url,omitempty"`
	Source      string `json:"source"`
}

// Optimization aggregates size and quality findings.
type Optimization struct {
	EfficiencyScore float64        `json:"efficiencyScore"` // 0-100
	WastedBytes     int64          `json:"wastedBytes"`
	WastedFiles     []WastedFile   `json:"wastedFiles,omitempty"`
	Findings        []Finding      `json:"findings,omitempty"`
	BaseImageRecs   []BaseImageRec `json:"baseImageRecommendations,omitempty"`
}

// WastedFile is a path whose bytes are shadowed or deleted across layers.
type WastedFile struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	Reason string `json:"reason"` // overwritten | deleted | duplicate
	Layers []int  `json:"layers"`
}

// Finding is a Dockerfile or image-history heuristic result.
type Finding struct {
	RuleID           string `json:"ruleId"`
	Severity         string `json:"severity"` // info|warn|error
	Message          string `json:"message"`
	File             string `json:"file,omitempty"`
	Line             int    `json:"line,omitempty"`
	EstimatedSavings int64  `json:"estimatedSavingsBytes,omitempty"`
}

// BaseImageRec suggests an alternative base image.
type BaseImageRec struct {
	Current            string `json:"current"`
	Suggested          string `json:"suggested"`
	Rationale          string `json:"rationale"`
	EstimatedSizeDelta int64  `json:"estimatedSizeDelta,omitempty"`
}

// Severities in descending order of impact.
var Severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}

// SeverityRank returns a sortable rank: lower is more severe.
// Unrecognized severities rank below UNKNOWN.
func SeverityRank(s string) int {
	for i, sev := range Severities {
		if s == sev {
			return i
		}
	}
	return len(Severities)
}

// Summary contains everything a CI gate needs in one place.
type Summary struct {
	VulnCounts      map[string]int `json:"vulnCounts"`
	FindingCounts   map[string]int `json:"findingCounts"`
	EfficiencyScore float64        `json:"efficiencyScore"`
	TotalSize       int64          `json:"totalSize"`
	WastedBytes     int64          `json:"wastedBytes"`
}
