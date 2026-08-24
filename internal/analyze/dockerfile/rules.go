package dockerfile

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/anaskmh/imgvet/pkg/report"
)

// rules are run in order; each returns zero or more findings.
var rules = []func(*file) []report.Finding{
	ruleAptCacheNotCleaned,
	ruleApkNoCache,
	rulePipNoCacheDir,
	ruleCopyDotDot,
	ruleAddWhereCopySuffices,
	ruleLatestBase,
	ruleRootUser,
	ruleSecretsInEnv,
	ruleMissingMultiStage,
}

// --- RUN-command heuristics shared with history-based linting ---

var (
	aptInstallRe  = regexp.MustCompile(`apt(-get)?\s+(-\S+\s+)*install`)
	aptCleanRe    = regexp.MustCompile(`rm\s+(-\S+\s+)*/var/lib/apt/lists|apt(-get)?\s+clean`)
	yumInstallRe  = regexp.MustCompile(`(yum|dnf)\s+(-\S+\s+)*install`)
	yumCleanRe    = regexp.MustCompile(`(yum|dnf)\s+clean\s+all|rm\s+(-\S+\s+)*/var/cache/(yum|dnf)`)
	apkAddRe      = regexp.MustCompile(`apk\s+(-\S+\s+)*add`)
	apkNoCacheRe  = regexp.MustCompile(`apk\s+(-\S+\s+)*add\s+(-\S+\s+)*--no-cache|rm\s+(-\S+\s+)*/var/cache/apk`)
	pipInstallRe  = regexp.MustCompile(`pip3?\s+(-\S+\s+)*install`)
	pipNoCacheRe  = regexp.MustCompile(`--no-cache-dir|PIP_NO_CACHE_DIR`)
	compilerRe    = regexp.MustCompile(`\b(gcc|g\+\+|make|cmake|maven|mvn|go build|cargo build|npm run build|yarn build)\b`)
	secretNameRe  = regexp.MustCompile(`(?i)(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key)`)
	buildToolPkgs = regexp.MustCompile(`\b(build-essential|gcc|g\+\+|make|cmake|golang|maven|gradle)\b`)
)

// checkRunCommand applies package-manager cache heuristics to one shell
// command line. Used for both Dockerfile RUN commands and image history.
func checkRunCommand(cmdline string) []historyIssue {
	var issues []historyIssue
	if aptInstallRe.MatchString(cmdline) && !aptCleanRe.MatchString(cmdline) {
		issues = append(issues, historyIssue{
			RuleID:  "IV-DF-001",
			Message: "apt install without cleaning /var/lib/apt/lists in the same RUN; the package index ships in the layer (add `&& rm -rf /var/lib/apt/lists/*`)",
		})
	}
	if yumInstallRe.MatchString(cmdline) && !yumCleanRe.MatchString(cmdline) {
		issues = append(issues, historyIssue{
			RuleID:  "IV-DF-001",
			Message: "yum/dnf install without `clean all` in the same RUN; the package cache ships in the layer",
		})
	}
	if apkAddRe.MatchString(cmdline) && !apkNoCacheRe.MatchString(cmdline) {
		issues = append(issues, historyIssue{
			RuleID:  "IV-DF-002",
			Message: "apk add without --no-cache; the apk index ships in the layer (use `apk add --no-cache`)",
		})
	}
	if pipInstallRe.MatchString(cmdline) && !pipNoCacheRe.MatchString(cmdline) {
		issues = append(issues, historyIssue{
			RuleID:  "IV-DF-003",
			Message: "pip install without --no-cache-dir; the wheel cache ships in the layer",
		})
	}
	return issues
}

type historyIssue struct {
	RuleID  string
	Message string
}

func eachRun(f *file, fn func(stageIdx int, cmd *instructions.RunCommand)) {
	for si, stage := range f.stages {
		for _, c := range stage.Commands {
			if run, ok := c.(*instructions.RunCommand); ok {
				fn(si, run)
			}
		}
	}
}

func runCmdline(run *instructions.RunCommand) string {
	return strings.Join(run.CmdLine, " ")
}

func ruleAptCacheNotCleaned(f *file) []report.Finding {
	return runRule(f, "IV-DF-001")
}
func ruleApkNoCache(f *file) []report.Finding {
	return runRule(f, "IV-DF-002")
}
func rulePipNoCacheDir(f *file) []report.Finding {
	return runRule(f, "IV-DF-003")
}

// runRule applies checkRunCommand and keeps issues matching the given rule ID.
func runRule(f *file, ruleID string) []report.Finding {
	var out []report.Finding
	eachRun(f, func(_ int, run *instructions.RunCommand) {
		for _, issue := range checkRunCommand(runCmdline(run)) {
			if issue.RuleID == ruleID {
				out = append(out, f.finding(issue.RuleID, "warn", issue.Message, line(run)))
			}
		}
	})
	return out
}

func ruleCopyDotDot(f *file) []report.Finding {
	var out []report.Finding
	final := f.finalStage()
	for si, stage := range f.stages {
		isFinal := final != nil && si == len(f.stages)-1
		for _, c := range stage.Commands {
			cp, ok := c.(*instructions.CopyCommand)
			if !ok || cp.From != "" {
				continue // COPY --from is a multi-stage copy, usually fine
			}
			srcs := cp.SourcePaths
			for _, src := range srcs {
				if src == "." || src == "./" {
					sev := "info"
					msg := fmt.Sprintf("COPY %s copies the entire build context", src)
					if isFinal {
						sev = "warn"
						msg += " into the final image; prefer copying only what the image needs, and keep a .dockerignore"
					}
					out = append(out, f.finding("IV-DF-004", sev, msg, line(cp)))
				}
			}
		}
	}
	return out
}

func ruleAddWhereCopySuffices(f *file) []report.Finding {
	var out []report.Finding
	for _, stage := range f.stages {
		for _, c := range stage.Commands {
			add, ok := c.(*instructions.AddCommand)
			if !ok {
				continue
			}
			simple := true
			for _, src := range add.SourcePaths {
				if strings.Contains(src, "://") || isArchive(src) {
					simple = false
					break
				}
			}
			if simple {
				out = append(out, f.finding("IV-DF-005", "info",
					"ADD used for a plain local file; use COPY (ADD's URL-fetch and auto-extract behaviors invite surprises)", line(add)))
			}
		}
	}
	return out
}

func isArchive(s string) bool {
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".txz"} {
		if strings.HasSuffix(s, ext) {
			return true
		}
	}
	return false
}

func ruleLatestBase(f *file) []report.Finding {
	var out []report.Finding
	for _, stage := range f.stages {
		base := stage.BaseName
		if base == "" || base == "scratch" || isStageRef(f, base) {
			continue
		}
		if strings.Contains(base, "@sha256:") {
			continue // digest-pinned
		}
		if !strings.Contains(base, ":") || strings.HasSuffix(base, ":latest") {
			out = append(out, report.Finding{
				RuleID: "IV-DF-006", Severity: "warn", File: f.path, Line: stageLine(stage),
				Message: fmt.Sprintf("base image %q is not pinned to a tag; builds are not reproducible and can silently change", base),
			})
		}
	}
	return out
}

func isStageRef(f *file, name string) bool {
	for _, s := range f.stages {
		if s.Name != "" && strings.EqualFold(s.Name, name) {
			return true
		}
	}
	return false
}

func stageLine(s instructions.Stage) int {
	if len(s.Location) > 0 {
		return s.Location[0].Start.Line
	}
	return 0
}

func ruleRootUser(f *file) []report.Finding {
	final := f.finalStage()
	if final == nil {
		return nil
	}
	user := ""
	for _, c := range final.Commands {
		if u, ok := c.(*instructions.UserCommand); ok {
			user = u.User
		}
	}
	if user == "" || user == "root" || user == "0" {
		return []report.Finding{f.finding("IV-DF-007", "warn",
			"final stage has no non-root USER; the container runs as root", stageLine(*final))}
	}
	return nil
}

func ruleSecretsInEnv(f *file) []report.Finding {
	var out []report.Finding
	for _, stage := range f.stages {
		for _, c := range stage.Commands {
			env, ok := c.(*instructions.EnvCommand)
			if !ok {
				continue
			}
			for _, kv := range env.Env {
				if secretNameRe.MatchString(kv.Key) && kv.Value != "" {
					out = append(out, f.finding("IV-DF-008", "error",
						fmt.Sprintf("ENV %s looks like a secret baked into the image; ENV values are visible in the image config and every layer consumer", kv.Key),
						line(env)))
				}
			}
		}
	}
	return out
}

func ruleMissingMultiStage(f *file) []report.Finding {
	if len(f.stages) != 1 {
		return nil
	}
	stage := f.stages[0]
	for _, c := range stage.Commands {
		run, ok := c.(*instructions.RunCommand)
		if !ok {
			continue
		}
		cmdline := runCmdline(run)
		if compilerRe.MatchString(cmdline) || (aptInstallRe.MatchString(cmdline) && buildToolPkgs.MatchString(cmdline)) {
			return []report.Finding{f.finding("IV-DF-009", "warn",
				"single-stage build that compiles code; build tools and sources ship in the final image — use a multi-stage build",
				line(run))}
		}
	}
	return nil
}
