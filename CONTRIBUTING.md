# Contributing to imgvet

Thanks for your interest! Contributions of all kinds are welcome — bug reports, lint rules, scanner adapters, docs.

## Development setup

Requirements: Go 1.24+, Docker (for e2e and daemon-mode scans), and optionally [trivy](https://trivy.dev) for vulnerability scanning.

```sh
git clone https://github.com/anaskmh/imgvet && cd imgvet
go build -o imgvet .
go test ./...
./imgvet scan alpine:3.20
```

## Project layout

- `pkg/report/` — the public JSON schema. Changes here are breaking; bump `SchemaVersion` and say so in the PR.
- `internal/engine/` — pipeline orchestration (analyzer fan-out, report assembly).
- `internal/analyze/` — analyzers: `layers` (metadata), `filetree` (waste/score), `dockerfile` (lint rules), `recommend` (base images).
- `internal/scan/` — the `Scanner` interface and backends (`trivy/`).
- `internal/render/` — `table`, `jsonout`, `htmlreport` renderers.

## Adding a lint rule

1. Add the rule function in `internal/analyze/dockerfile/rules.go` and register it in the `rules` slice. Use the next free `IV-DF-NNN` ID.
2. If the rule can be detected from image history strings alone, extend `checkRunCommand` so it also fires for images scanned without a Dockerfile.
3. Add a positive case to `testdata/bad.Dockerfile` (or a new fixture) and make sure `testdata/good.Dockerfile` stays clean.
4. Severity guide: `error` = security problem (secrets, etc.), `warn` = size/reproducibility waste, `info` = style.

## Adding a scanner backend

Implement `scan.Scanner` (see `internal/scan/scanner.go`) in a new package under `internal/scan/`. Backends receive an already-exported docker-archive tar — never pull the image again. Parse the tool's **JSON output** rather than importing its internals, normalize severities to `CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN`, and add recorded-output fixtures under `testdata/`.

## Before you send a PR

```sh
go vet ./...
go test -race ./...
```

CI also runs golangci-lint and an e2e scan of an intentionally bloated image (`testdata/bloated/`).
