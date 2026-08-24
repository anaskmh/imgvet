# imgvet

**Scan and optimize container images in one pass.**

`imgvet` combines what today takes three tools — vulnerability scanning (Trivy), layer/size analysis (Dive), and image linting (Dockle) — into a single CLI with one unified, actionable report: terminal, JSON, or a self-contained HTML file.

```
$ imgvet scan myapp:latest --dockerfile Dockerfile

Image:    index.docker.io/library/myapp:latest
Size:     376.9 MB (compressed, 9 layers)

LAYERS
  #  SIZE      FILES  COMMAND
  0  48.3 MB   9296   ADD rootfs.tar /
  ...

VULNERABILITIES
  SEVERITY  ID              PACKAGE     INSTALLED   FIXED IN
  HIGH      CVE-2026-1234   libssl3     3.0.2       3.0.9
  ...

TOP WASTED FILES
  20.0 MB   deleted      /tmp/bigfile
  2.2 MB    overwritten  /var/cache/debconf/templates.dat

FINDINGS
  [WARN] IV-DF-001: apt install without cleaning /var/lib/apt/lists ... (Dockerfile:12)
  [ERROR] IV-DF-008: ENV API_KEY looks like a secret baked into the image (Dockerfile:4)

BASE IMAGE RECOMMENDATIONS
  buildpack-deps:bookworm → node:18-slim or node:18-alpine

SUMMARY
  Vulnerabilities: 2 high, 8 medium, 17 low
  Wasted:          22.4 MB
  Efficiency:      39.1/100
```

## Install

```sh
go install github.com/anaskmh/imgvet@latest
```

Or grab a binary from [Releases](../../releases). For vulnerability scanning, also install [trivy](https://trivy.dev/latest/getting-started/installation/) (`brew install trivy`) — without it, imgvet still runs all optimization analysis.

## Usage

```sh
# Full scan: vulnerabilities + optimization
imgvet scan node:18

# Include Dockerfile lint findings with line numbers
imgvet scan myapp:latest --dockerfile ./Dockerfile

# Self-contained HTML report (works offline, email/CI-artifact friendly)
imgvet scan myapp:latest --format html -o report.html

# JSON for tooling; re-render it later without rescanning
imgvet scan myapp:latest --format json -o report.json
imgvet render report.json --format html -o report.html

# CI gates: exit code 2 on policy failure
imgvet scan myapp:latest --fail-on high --min-score 80

# Optimization-only (air-gapped, no trivy)
imgvet scan ./image.tar --scanner none
```

**Image sources:** plain references try the local Docker daemon first, then the registry (using your existing Docker credentials and credential helpers). Force a source with `daemon://ref` or `tar://path`, or pass a `.tar` from `docker save`. `--platform linux/amd64` selects a variant of multi-arch images.

**Exit codes:** `0` success · `1` error · `2` policy gate failed (`--fail-on`, `--min-score`).

## What it checks

**Vulnerabilities** — via a pluggable scanner interface; the default backend execs `trivy` against the image tar (pulled once) and normalizes its JSON. Each CVE is tied to the layer that introduced it.

**Wasted space** — streams every layer's tar headers (contents are never extracted) and diffs the file trees across layers: files overwritten by later layers, deleted files (OCI whiteouts/opaque dirs) that still ship in earlier layers, per-layer waste attribution.

**Dockerfile lint** (`IV-DF-*` rules) — uncleaned apt/apk/yum/pip caches, `COPY . .` bloat, `ADD` misuse, unpinned base tags, missing non-root `USER`, secrets in `ENV`, single-stage builds that compile code. When no Dockerfile is given, a reduced rule set runs against the image history.

**Base image recommendations** — detects the runtime (node/python/go/java from official-image env vars, OS from `/etc/os-release`, base from OCI annotations) and suggests slim/alpine/distroless alternatives. Best-effort and informational; never gates CI.

### Efficiency score

`score = 100 × (1 − wastedBytes / totalFileBytes)`, minus a capped penalty for lint findings (2 points per error, 1 per warning, max 15), floored at 0. A clean minimal image scores 100.

## Comparison

| | imgvet | trivy | dive | dockle |
|---|---|---|---|---|
| CVE scanning | ✅ (via trivy) | ✅ | – | – |
| Layer waste analysis | ✅ | – | ✅ (TUI) | – |
| Dockerfile lint | ✅ | ✅ (misconfig) | – | ✅ |
| Base image recommendations | ✅ | – | – | – |
| Single unified report (JSON/HTML) | ✅ | – | – | – |
| CI gates on both CVEs *and* size | ✅ | CVEs only | score only | ✅ |

## JSON schema

The report follows a versioned schema (`schemaVersion: 1`) defined in [`pkg/report`](pkg/report/report.go) — Go consumers can import that package directly.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — adding a lint rule or a scanner backend (grype is a natural next one) is deliberately easy. Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
