// Package cli defines the imgvet command tree.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via -ldflags.
var Version = "dev"

// Exit codes: 0 success, 1 error, 2 policy gate failure (--fail-on / --min-score).
const (
	ExitOK     = 0
	ExitError  = 1
	ExitPolicy = 2
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "imgvet",
		Short:         "Scan and optimize container images in one pass",
		Long:          "imgvet scans container images for vulnerabilities and size/layer waste,\nproducing a single unified report.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newScanCmd())
	root.AddCommand(newRenderCmd())
	root.AddCommand(newVersionCmd())
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		var pe *policyError
		if ok := asPolicyError(err, &pe); ok {
			fmt.Fprintln(os.Stderr, pe.Error())
			return ExitPolicy
		}
		fmt.Fprintln(os.Stderr, "Error:", err)
		return ExitError
	}
	return ExitOK
}
