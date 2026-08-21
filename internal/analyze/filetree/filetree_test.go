package filetree

import (
	"archive/tar"
	"bytes"
	"io"
	"math"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	name string
	size int64
	typ  byte
}

func synthLayer(t *testing.T, entries []entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: typ}
		if typ == tar.TypeReg {
			hdr.Size = e.size
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg && e.size > 0 {
			if _, err := tw.Write(bytes.Repeat([]byte("x"), int(e.size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func synthImage(t *testing.T, layerEntries ...[]entry) v1.Image {
	t.Helper()
	img := empty.Image
	for _, entries := range layerEntries {
		var err error
		img, err = mutate.AppendLayers(img, synthLayer(t, entries))
		if err != nil {
			t.Fatal(err)
		}
	}
	return img
}

func TestOverwriteAndWhiteout(t *testing.T) {
	img := synthImage(t,
		[]entry{{name: "big", size: 1000}, {name: "keep", size: 10}},
		[]entry{{name: "big", size: 500}, {name: ".wh.keep"}},
	)
	res, err := Analyze(img)
	if err != nil {
		t.Fatal(err)
	}

	if res.WastedBytes != 1010 {
		t.Errorf("WastedBytes = %d, want 1010", res.WastedBytes)
	}
	if res.TotalFileBytes != 1510 {
		t.Errorf("TotalFileBytes = %d, want 1510", res.TotalFileBytes)
	}
	if res.PerLayer[0].WastedBytes != 1010 {
		t.Errorf("layer 0 wasted = %d, want 1010", res.PerLayer[0].WastedBytes)
	}
	if res.PerLayer[1].WastedBytes != 0 {
		t.Errorf("layer 1 wasted = %d, want 0", res.PerLayer[1].WastedBytes)
	}
	if res.PerLayer[0].FileCount != 2 || res.PerLayer[1].FileCount != 1 {
		t.Errorf("file counts = %d,%d want 2,1 (whiteouts must not count)",
			res.PerLayer[0].FileCount, res.PerLayer[1].FileCount)
	}

	wantScore := 100 * (1 - 1010.0/1510.0)
	if math.Abs(res.EfficiencyScore-wantScore) > 0.01 {
		t.Errorf("score = %.2f, want %.2f", res.EfficiencyScore, wantScore)
	}

	if len(res.WastedFiles) != 2 {
		t.Fatalf("got %d wasted files, want 2: %+v", len(res.WastedFiles), res.WastedFiles)
	}
	// Sorted by bytes desc: big (1000, overwritten) then keep (10, deleted).
	if res.WastedFiles[0].Path != "/big" || res.WastedFiles[0].Reason != "overwritten" {
		t.Errorf("wastedFiles[0] = %+v", res.WastedFiles[0])
	}
	if res.WastedFiles[1].Path != "/keep" || res.WastedFiles[1].Reason != "deleted" {
		t.Errorf("wastedFiles[1] = %+v", res.WastedFiles[1])
	}
}

func TestOpaqueDir(t *testing.T) {
	img := synthImage(t,
		[]entry{{name: "dir/a", size: 100}, {name: "dir/b", size: 50}, {name: "other", size: 10}},
		[]entry{{name: "dir/.wh..wh..opq"}},
	)
	res, err := Analyze(img)
	if err != nil {
		t.Fatal(err)
	}
	if res.WastedBytes != 150 {
		t.Errorf("WastedBytes = %d, want 150 (opaque dir hides dir/a and dir/b)", res.WastedBytes)
	}
}

func TestWhiteoutOfDirectory(t *testing.T) {
	img := synthImage(t,
		[]entry{{name: "cache", typ: tar.TypeDir}, {name: "cache/x", size: 200}, {name: "cache/sub/y", size: 300}},
		[]entry{{name: ".wh.cache"}},
	)
	res, err := Analyze(img)
	if err != nil {
		t.Fatal(err)
	}
	if res.WastedBytes != 500 {
		t.Errorf("WastedBytes = %d, want 500 (deleting a dir wastes everything under it)", res.WastedBytes)
	}
}

func TestCleanImageScores100(t *testing.T) {
	img := synthImage(t, []entry{{name: "app", size: 100}})
	res, err := Analyze(img)
	if err != nil {
		t.Fatal(err)
	}
	if res.EfficiencyScore != 100 {
		t.Errorf("score = %.2f, want 100", res.EfficiencyScore)
	}
	if len(res.WastedFiles) != 0 {
		t.Errorf("wasted files = %+v, want none", res.WastedFiles)
	}
}
