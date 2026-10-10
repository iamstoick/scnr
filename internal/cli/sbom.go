package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/gerald/scnr/internal/audit"
	"github.com/gerald/scnr/internal/domain"
	"github.com/gerald/scnr/internal/engine/image"
	"github.com/gerald/scnr/internal/engine/sca"
	"github.com/gerald/scnr/internal/safety"
	"github.com/gerald/scnr/internal/sbom"
	"github.com/gerald/scnr/internal/target"
)

func (a *App) sbomCmd() *cobra.Command {
	var format, out, typ string
	cmd := &cobra.Command{
		Use:   "sbom TARGET",
		Short: "Write a CycloneDX software bill of materials for a directory or local image archive",
		Long:  "Collects packages from lockfiles (and apk/dpkg databases inside a `docker save` tarball or OCI layout) and writes a CycloneDX 1.5 JSON BOM. Nothing is executed and no network is used.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if format != sbom.FormatCycloneDXJSON {
				return exitf(ExitUsage, "unknown --format %q (available: %s)", format, sbom.FormatCycloneDXJSON)
			}
			override, err := target.ParseType(typ)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			if err := a.Open(ctx); err != nil {
				return err
			}
			t, err := a.Detector().Detect(ctx, args[0], override)
			if err != nil {
				return exitf(ExitUsage, "%v", a.redactErr(err))
			}
			if t.Type != domain.TargetPath && t.Type != domain.TargetImage {
				return exitf(ExitUsage, "sbom needs a directory or a local image archive, got %s", t.Type)
			}
			if t.Type == domain.TargetImage && !image.IsLocal(t) {
				return exitf(ExitUsage, "%v", image.SkipRegistry(t))
			}
			scaEng, err := sca.New(nil)
			if err != nil {
				return err
			}
			img, err := image.New(scaEng)
			if err != nil {
				return err
			}
			inv, err := sbom.Collect(ctx, t, img)
			if err != nil {
				return exitf(ExitUsage, "%v", err)
			}
			w := a.Stdout
			if out != "" {
				if err := os.MkdirAll(filepath.Dir(out), 0o750); err != nil {
					return err
				}
				f, err := safety.CreateOutputFile(out)
				if err != nil {
					return exitf(ExitUsage, "--out %v", err)
				}
				defer f.Close()
				w = f
			}
			if err := sbom.Write(w, inv, a.Version, time.Now()); err != nil {
				return err
			}
			_ = a.Audit.Log(ctx, audit.ActionSBOM, "", map[string]any{"target": a.redact(t.Raw), "type": t.Type, "format": format, "components": len(inv.Packages), "out": out})
			if out != "" {
				fmt.Fprintf(a.Stderr, "SBOM: %d component(s) written to %s\n", len(inv.Packages), out)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&format, "format", sbom.FormatCycloneDXJSON, "output format")
	cmd.Flags().StringVar(&out, "out", "", "write to this file instead of stdout")
	cmd.Flags().StringVar(&typ, "type", "", "override target detection: path|image (a directory is read as an OCI image layout only with --type image)")
	return cmd
}
