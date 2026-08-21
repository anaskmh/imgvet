# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead, use GitHub's
[private vulnerability reporting](../../security/advisories/new) on this repository.
You should receive a response within a few days.

## Scope notes

- imgvet execs the `trivy` binary found on `PATH` (or configured backend). It never
  auto-downloads scanner binaries.
- imgvet reads image layer tar **headers** and a single small file (`/etc/os-release`);
  layer contents are never extracted to disk.
- HTML reports embed the report JSON with HTML-escaped encoding; report content
  (package names, CVE titles) cannot inject script. If you find a bypass, report it.

## Supported versions

Only the latest release receives security fixes.
