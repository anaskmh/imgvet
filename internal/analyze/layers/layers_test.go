package layers

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// synthLayer builds an uncompressed tar layer with the given regular files.
func synthLayer(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, content := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	// Add a directory entry to verify it is not counted as a file.
	if err := tw.WriteHeader(&tar.Header{Name: "somedir/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

func TestAnalyze(t *testing.T) {
	l1 := synthLayer(t, map[string]string{"bin/app": "hello", "etc/conf": "x=1"})
	l2 := synthLayer(t, map[string]string{"var/log/app.log": "log line"})

	img, err := mutate.Append(empty.Image,
		mutate.Addendum{Layer: l1, History: v1.History{CreatedBy: "/bin/sh -c #(nop) ADD rootfs.tar /"}},
		mutate.Addendum{Layer: l2, History: v1.History{CreatedBy: "RUN /bin/sh -c touch /var/log/app.log # buildkit"}},
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := Analyze(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d layers, want 2", len(got))
	}
	if got[0].Command != "ADD rootfs.tar /" {
		t.Errorf("layer 0 command = %q, want %q", got[0].Command, "ADD rootfs.tar /")
	}
	if got[1].Command != "RUN /bin/sh -c touch /var/log/app.log" {
		t.Errorf("layer 1 command = %q", got[1].Command)
	}
	if got[0].Digest == "" || got[0].DiffID == "" {
		t.Error("layer 0 missing digest/diffID")
	}
	if got[0].Size <= 0 {
		t.Errorf("layer 0 size = %d, want > 0", got[0].Size)
	}
}

func TestCleanCommand(t *testing.T) {
	cases := map[string]string{
		"/bin/sh -c #(nop)  CMD [\"/bin/bash\"]": "CMD [\"/bin/bash\"]",
		"/bin/sh -c apt-get update":              "apt-get update",
		"RUN apk add curl # buildkit":            "RUN apk add curl",
		"  plain  ":                              "plain",
	}
	for in, want := range cases {
		if got := cleanCommand(in); got != want {
			t.Errorf("cleanCommand(%q) = %q, want %q", in, got, want)
		}
	}
}
