// Package image acquires container images from the local daemon, a remote
// registry, or a tarball, and exposes them as go-containerregistry v1.Image.
package image

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Source identifies where an image was loaded from.
type Source string

const (
	SourceDaemon   Source = "daemon"
	SourceRegistry Source = "registry"
	SourceTarball  Source = "tarball"
)

// Resolved is an acquired image plus provenance metadata.
type Resolved struct {
	Image  v1.Image
	Ref    string // normalized reference (or file path for tarballs)
	Source Source
}

// Options controls image resolution.
type Options struct {
	// Platform selects a platform for multi-arch remote images, e.g. "linux/amd64".
	Platform string
}

// Resolve fetches an image. Supported inputs:
//   - "daemon://ref"  force the local Docker daemon
//   - "tar://path" or a path to an existing .tar file
//   - plain reference: tries the daemon first (if reachable and present),
//     then falls back to the registry.
func Resolve(ctx context.Context, ref string, opts Options) (*Resolved, error) {
	switch {
	case strings.HasPrefix(ref, "daemon://"):
		return fromDaemon(ctx, strings.TrimPrefix(ref, "daemon://"))
	case strings.HasPrefix(ref, "tar://"):
		return fromTarball(strings.TrimPrefix(ref, "tar://"))
	}
	if looksLikeTarPath(ref) {
		return fromTarball(ref)
	}

	// Plain reference: prefer a local daemon copy to avoid a network pull,
	// but only when no explicit platform was requested (the daemon has
	// exactly one platform per tag).
	if opts.Platform == "" {
		if r, err := fromDaemon(ctx, ref); err == nil {
			return r, nil
		}
	}
	return fromRegistry(ctx, ref, opts)
}

func looksLikeTarPath(ref string) bool {
	if !strings.HasSuffix(ref, ".tar") && !strings.HasSuffix(ref, ".tar.gz") {
		return false
	}
	_, err := os.Stat(ref)
	return err == nil
}

func fromDaemon(ctx context.Context, ref string) (*Resolved, error) {
	tag, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", ref, err)
	}
	img, err := daemon.Image(tag, daemon.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("loading %q from docker daemon: %w", ref, err)
	}
	return &Resolved{Image: img, Ref: tag.Name(), Source: SourceDaemon}, nil
}

func fromRegistry(ctx context.Context, ref string, opts Options) (*Resolved, error) {
	tag, err := name.ParseReference(ref)
	if err != nil {
		return nil, fmt.Errorf("parsing reference %q: %w", ref, err)
	}
	remoteOpts := []remote.Option{
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}
	if opts.Platform != "" {
		p, err := v1.ParsePlatform(opts.Platform)
		if err != nil {
			return nil, fmt.Errorf("parsing platform %q: %w", opts.Platform, err)
		}
		remoteOpts = append(remoteOpts, remote.WithPlatform(*p))
	}
	img, err := remote.Image(tag, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("pulling %q from registry: %w", ref, err)
	}
	return &Resolved{Image: img, Ref: tag.Name(), Source: SourceRegistry}, nil
}

func fromTarball(path string) (*Resolved, error) {
	img, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		return nil, fmt.Errorf("loading tarball %q: %w", path, err)
	}
	return &Resolved{Image: img, Ref: path, Source: SourceTarball}, nil
}
