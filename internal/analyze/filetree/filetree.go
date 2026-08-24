// Package filetree streams every layer's tar headers (bodies are never read)
// and diffs the resulting file trees across layers to find wasted bytes:
// files that a later layer overwrites or deletes (OCI whiteouts), which still
// ship in the image. It also derives per-layer file counts and the overall
// efficiency score.
package filetree

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/anaskmh/imgvet/pkg/report"
)

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
)

// LayerStats is the per-layer output of the analysis.
type LayerStats struct {
	FileCount   int
	WastedBytes int64 // bytes in this layer that a later layer shadows or deletes
}

// Result is the full filetree analysis.
type Result struct {
	PerLayer        []LayerStats
	WastedFiles     []report.WastedFile
	WastedBytes     int64
	TotalFileBytes  int64 // sum of all regular-file bytes across all layers
	EfficiencyScore float64
	OSRelease       map[string]string // parsed /etc/os-release (ID, VERSION_ID, PRETTY_NAME, ...)
}

// osReleasePaths are the canonical locations of os-release, in tar form.
var osReleasePaths = map[string]bool{
	"etc/os-release":     true,
	"usr/lib/os-release": true,
}

// fileRef records where a path's current bytes live.
type fileRef struct {
	size  int64
	layer int
}

// wasteEntry accumulates waste per path.
type wasteEntry struct {
	bytes  int64
	reason string
	layers map[int]struct{}
}

// Analyze streams all layers in order and computes the diff.
func Analyze(img v1.Image) (*Result, error) {
	imgLayers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading layers: %w", err)
	}

	res := &Result{PerLayer: make([]LayerStats, len(imgLayers))}
	current := map[string]fileRef{} // merged filesystem state: path -> live bytes
	waste := map[string]*wasteEntry{}

	shadow := func(p string, reason string, byLayer int) {
		prev, ok := current[p]
		if !ok {
			return
		}
		delete(current, p)
		if prev.size == 0 {
			return
		}
		res.PerLayer[prev.layer].WastedBytes += prev.size
		res.WastedBytes += prev.size
		w := waste[p]
		if w == nil {
			w = &wasteEntry{layers: map[int]struct{}{}}
			waste[p] = w
		}
		w.bytes += prev.size
		w.reason = reason
		w.layers[prev.layer] = struct{}{}
		w.layers[byLayer] = struct{}{}
	}

	// shadowDir wastes every live file strictly under dir.
	shadowDir := func(dir, reason string, byLayer int) {
		prefix := dir + "/"
		for p := range current {
			if strings.HasPrefix(p, prefix) {
				shadow(p, reason, byLayer)
			}
		}
	}

	for i, l := range imgLayers {
		if err := walkLayer(l, func(hdr *tar.Header, tr *tar.Reader) {
			p := cleanPath(hdr.Name)
			if p == "" {
				return
			}
			base := path.Base(p)
			dir := path.Dir(p)

			switch {
			case base == opaqueMarker:
				// Everything previously under dir is hidden by this layer.
				if dir != "." {
					shadowDir(dir, "deleted", i)
				}
			case strings.HasPrefix(base, whiteoutPrefix):
				target := path.Join(dir, strings.TrimPrefix(base, whiteoutPrefix))
				shadow(target, "deleted", i)
				shadowDir(target, "deleted", i)
			case hdr.Typeflag == tar.TypeReg:
				res.PerLayer[i].FileCount++
				shadow(p, "overwritten", i)
				current[p] = fileRef{size: hdr.Size, layer: i}
				res.TotalFileBytes += hdr.Size
				// os-release is the one file whose body we read: it's tiny
				// and drives OS detection. Later layers override earlier ones.
				if osReleasePaths[p] && hdr.Size < 8192 {
					if data, err := io.ReadAll(io.LimitReader(tr, 8192)); err == nil {
						if parsed := parseOSRelease(string(data)); len(parsed) > 0 {
							res.OSRelease = parsed
						}
					}
				}
			case hdr.Typeflag == tar.TypeDir:
				// no-op for waste tracking
			default:
				// Symlinks/hardlinks/devices carry no file bytes; replacing a
				// regular file with one still shadows it.
				shadow(p, "overwritten", i)
			}
		}); err != nil {
			return nil, fmt.Errorf("layer %d: %w", i, err)
		}
	}

	for p, w := range waste {
		layers := make([]int, 0, len(w.layers))
		for l := range w.layers {
			layers = append(layers, l)
		}
		sort.Ints(layers)
		res.WastedFiles = append(res.WastedFiles, report.WastedFile{
			Path:   "/" + p,
			Bytes:  w.bytes,
			Reason: w.reason,
			Layers: layers,
		})
	}
	sort.Slice(res.WastedFiles, func(i, j int) bool {
		if res.WastedFiles[i].Bytes != res.WastedFiles[j].Bytes {
			return res.WastedFiles[i].Bytes > res.WastedFiles[j].Bytes
		}
		return res.WastedFiles[i].Path < res.WastedFiles[j].Path
	})

	res.EfficiencyScore = Score(res.WastedBytes, res.TotalFileBytes)
	return res, nil
}

// Score computes the base efficiency score: the share of shipped file bytes
// that are actually live in the final filesystem, scaled to 0-100.
func Score(wasted, total int64) float64 {
	if total <= 0 {
		return 100
	}
	s := 100 * (1 - float64(wasted)/float64(total))
	if s < 0 {
		return 0
	}
	return s
}

func walkLayer(l v1.Layer, fn func(*tar.Header, *tar.Reader)) error {
	rc, err := l.Uncompressed()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// Tolerate slightly malformed tars rather than failing the scan.
			return nil
		}
		fn(hdr, tr)
	}
}

// parseOSRelease extracts KEY=value pairs from os-release content.
func parseOSRelease(content string) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		k, v, ok := strings.Cut(ln, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

func cleanPath(name string) string {
	p := path.Clean(strings.TrimPrefix(name, "/"))
	p = strings.TrimPrefix(p, "./")
	if p == "." || p == "" {
		return ""
	}
	return p
}
