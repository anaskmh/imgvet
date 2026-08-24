package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anaskmh/imgvet/internal/render/htmlreport"
	"github.com/anaskmh/imgvet/internal/render/jsonout"
	"github.com/anaskmh/imgvet/internal/render/table"
	"github.com/anaskmh/imgvet/pkg/report"
)

func newRenderCmd() *cobra.Command {
	var (
		format string
		output string
	)
	cmd := &cobra.Command{
		Use:   "render REPORT.json",
		Short: "Re-render a saved JSON report as a table or HTML",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			var rep report.Report
			if err := json.Unmarshal(data, &rep); err != nil {
				return fmt.Errorf("parsing %s: %w", args[0], err)
			}
			if rep.SchemaVersion > report.SchemaVersion {
				return fmt.Errorf("%s has schema version %d, this imgvet supports up to %d; upgrade imgvet",
					args[0], rep.SchemaVersion, report.SchemaVersion)
			}

			out := cmd.OutOrStdout()
			var closeOut func() error
			if output != "" {
				f, err := os.Create(output)
				if err != nil {
					return err
				}
				out, closeOut = f, f.Close
			}
			var renderErr error
			switch format {
			case "html":
				renderErr = htmlreport.Render(out, &rep)
			case "json":
				renderErr = jsonout.Render(out, &rep)
			case "table":
				renderErr = table.Render(out, &rep)
			default:
				renderErr = fmt.Errorf("unsupported format %q (supported: table, json, html)", format)
			}
			if closeOut != nil {
				if err := closeOut(); err != nil && renderErr == nil {
					renderErr = err
				}
			}
			return renderErr
		},
	}
	cmd.Flags().StringVarP(&format, "format", "f", "html", "output format: table, json, html")
	cmd.Flags().StringVarP(&output, "output", "o", "", "write output to file instead of stdout")
	return cmd
}
