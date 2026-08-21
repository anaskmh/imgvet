// Package layers extracts per-layer metadata: sizes and the Dockerfile
// command that created each layer (from config history). File-level stats
// come from the filetree analyzer, which streams tar headers once.
package layers

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/greentruth/imgvet/pkg/report"
)

// Analyze returns one report.Layer per non-empty image layer, in order.
func Analyze(img v1.Image) ([]report.Layer, error) {
	imgLayers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("reading layers: %w", err)
	}
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	commands := layerCommands(cfg)

	out := make([]report.Layer, 0, len(imgLayers))
	for i, l := range imgLayers {
		digest, err := l.Digest()
		if err != nil {
			return nil, fmt.Errorf("layer %d digest: %w", i, err)
		}
		diffID, err := l.DiffID()
		if err != nil {
			return nil, fmt.Errorf("layer %d diffID: %w", i, err)
		}
		size, err := l.Size()
		if err != nil {
			return nil, fmt.Errorf("layer %d size: %w", i, err)
		}
		layer := report.Layer{
			Index:  i,
			Digest: digest.String(),
			DiffID: diffID.String(),
			Size:   size,
		}
		if i < len(commands) {
			layer.Command = commands[i]
		}
		out = append(out, layer)
	}
	return out, nil
}

// layerCommands maps non-empty history entries to layers, cleaning up
// buildkit/shell prefixes for readability.
func layerCommands(cfg *v1.ConfigFile) []string {
	var cmds []string
	for _, h := range cfg.History {
		if h.EmptyLayer {
			continue
		}
		cmds = append(cmds, cleanCommand(h.CreatedBy))
	}
	return cmds
}

func cleanCommand(s string) string {
	s = strings.TrimSpace(s)
	for _, prefix := range []string{"/bin/sh -c #(nop) ", "/bin/sh -c #(nop)", "/bin/sh -c "} {
		if strings.HasPrefix(s, prefix) {
			return strings.TrimSpace(strings.TrimPrefix(s, prefix))
		}
	}
	// buildkit style: "RUN /bin/sh -c apt-get update # buildkit"
	s = strings.TrimSuffix(s, "# buildkit")
	return strings.TrimSpace(s)
}
