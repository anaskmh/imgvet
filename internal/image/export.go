package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Export writes the image to a docker-archive tar in cacheDir, content-addressed
// by the image digest so repeated scans of the same image reuse the file.
// Scanner backends (e.g. trivy --input) consume this tar so the image is only
// pulled once. Returns the tar path.
func Export(img v1.Image, ref string, cacheDir string) (string, error) {
	digest, err := img.Digest()
	if err != nil {
		return "", fmt.Errorf("computing image digest: %w", err)
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("creating cache dir: %w", err)
	}
	path := filepath.Join(cacheDir, strings.ReplaceAll(digest.String(), ":", "-")+".tar")
	if _, err := os.Stat(path); err == nil {
		return path, nil // cache hit
	}

	tag, err := name.NewTag(sanitizeRefForTag(ref))
	if err != nil {
		// Fall back to a fixed tag; the tar's internal name is cosmetic.
		tag, _ = name.NewTag("imgvet.local/export:latest")
	}

	tmp, err := os.CreateTemp(cacheDir, "export-*.tar")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	if err := tarball.WriteToFile(tmpPath, tag, img); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("exporting image tar: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return "", err
	}
	return path, nil
}

// sanitizeRefForTag strips digest suffixes so the ref parses as a tag.
func sanitizeRefForTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if !strings.Contains(ref, ":") {
		ref += ":latest"
	}
	return ref
}

// DefaultCacheDir returns the per-user imgvet cache directory.
func DefaultCacheDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "imgvet")
}
