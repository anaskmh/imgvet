// Package recommend suggests smaller or safer base images. Recommendations
// are best-effort heuristics driven by the image reference, environment
// variables set by official base images, and the detected OS — they are
// informational and never gate CI.
package recommend

import (
	"fmt"
	"strings"

	"github.com/anaskmh/imgvet/pkg/report"
)

// Recommend returns base-image suggestions for the scanned image.
// osRelease is the parsed /etc/os-release, possibly empty.
func Recommend(img report.ImageInfo, osRelease map[string]string) []report.BaseImageRec {
	ref := strings.ToLower(img.Ref)

	// Already on a minimal variant: nothing to suggest.
	for _, slim := range []string{"-alpine", "-slim", "distroless", "chainguard", "scratch", "wolfi"} {
		if strings.Contains(ref, slim) {
			return nil
		}
	}

	env := envMap(img.Config.Env)
	var recs []report.BaseImageRec

	if v := env["NODE_VERSION"]; v != "" {
		major := majorVersion(v)
		recs = append(recs, report.BaseImageRec{
			Current:   currentBase(img, "node:"+v),
			Suggested: fmt.Sprintf("node:%s-slim or node:%s-alpine", major, major),
			Rationale: "Node runtime detected. The default node image includes a full Debian toolchain (~350MB compressed); -slim drops it and -alpine is smaller still (musl-based — verify native module compatibility).",
		})
	}
	if v := env["PYTHON_VERSION"]; v != "" {
		mm := majorMinor(v)
		recs = append(recs, report.BaseImageRec{
			Current:   currentBase(img, "python:"+v),
			Suggested: fmt.Sprintf("python:%s-slim", mm),
			Rationale: "Python runtime detected. python:<ver>-slim omits the build toolchain; install build deps only in a builder stage if wheels need compiling.",
		})
	}
	if v := env["GOLANG_VERSION"]; v != "" {
		recs = append(recs, report.BaseImageRec{
			Current:   currentBase(img, "golang:"+v),
			Suggested: "multi-stage: build in golang, run in gcr.io/distroless/static or scratch",
			Rationale: "Go toolchain detected in the image. Go binaries are static; the compiler (~250MB) should not ship to production.",
		})
	}
	if v := env["JAVA_VERSION"]; v != "" {
		recs = append(recs, report.BaseImageRec{
			Current:   currentBase(img, "java:"+v),
			Suggested: "eclipse-temurin:<ver>-jre or gcr.io/distroless/java",
			Rationale: "Java detected. A JRE-only or distroless base drops the JDK compiler and tooling from the runtime image.",
		})
	}

	// Bare OS bases with no detected runtime.
	if len(recs) == 0 {
		switch osRelease["ID"] {
		case "ubuntu":
			recs = append(recs, report.BaseImageRec{
				Current:   currentBase(img, "ubuntu:"+osRelease["VERSION_ID"]),
				Suggested: "debian:stable-slim, alpine, or a distroless/chainguard base",
				Rationale: "Generic Ubuntu base. If the app doesn't need Ubuntu specifically, slimmer bases cut size and CVE surface substantially.",
			})
		case "debian":
			if !strings.Contains(ref, "slim") {
				recs = append(recs, report.BaseImageRec{
					Current:   currentBase(img, "debian:"+osRelease["VERSION_ID"]),
					Suggested: "debian:" + strings.ToLower(firstNonEmpty(osRelease["VERSION_CODENAME"], "stable")) + "-slim",
					Rationale: "Full Debian base. The -slim variant drops docs, locales, and other non-essentials (~50MB compressed).",
				})
			}
		}
	}
	return recs
}

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, e := range env {
		if k, v, ok := strings.Cut(e, "="); ok {
			m[k] = v
		}
	}
	return m
}

// currentBase prefers the explicit base-image annotation when the builder
// recorded one, falling back to the heuristic guess.
func currentBase(img report.ImageInfo, guess string) string {
	if img.BaseImage != "" {
		return img.BaseImage
	}
	return guess
}

func majorVersion(v string) string {
	if i := strings.Index(v, "."); i > 0 {
		return v[:i]
	}
	return v
}

func majorMinor(v string) string {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
