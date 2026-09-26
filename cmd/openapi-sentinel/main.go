// Command openapi-sentinel reviews an OpenAPI 3 specification for
// endpoints that are unauthenticated or otherwise weakly protected.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/httpEduardo/openapi-sentinel/internal/audit"
	"github.com/httpEduardo/openapi-sentinel/internal/spec"
)

const (
	exitOK       = 0
	exitFindings = 1
	exitUsage    = 2
)

var version = "dev"

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("openapi-sentinel", flag.ContinueOnError)
	fs.SetOutput(stderr)

	input := fs.String("input", "openapi.json", "path to the OpenAPI 3 document (JSON)")
	format := fs.String("format", "text", "output format: text or json")
	failOn := fs.String("fail-on", "high", "exit with code 1 when a finding reaches this severity")
	showVersion := fs.Bool("version", false, "print the version and exit")
	var public multiFlag
	fs.Var(&public, "public", `endpoint that is intentionally public, e.g. "GET /health" or "/docs/*" (repeatable)`)

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return exitOK
		}
		return exitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return exitOK
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "error: unknown format %q (want text or json)\n", *format)
		return exitUsage
	}
	threshold, err := audit.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	doc, err := spec.Load(*input)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	findings, err := audit.Run(doc, audit.Options{Public: public})
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	if *format == "json" {
		if findings == nil {
			findings = []audit.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"spec":       *input,
			"title":      doc.Title,
			"operations": len(doc.Operations),
			"findings":   findings,
		})
	} else {
		writeText(stdout, doc, findings)
	}

	if audit.Worst(findings) >= threshold {
		return exitFindings
	}
	return exitOK
}

func writeText(w io.Writer, doc *spec.Document, findings []audit.Finding) {
	title := doc.Title
	if title == "" {
		title = "untitled API"
	}
	fmt.Fprintf(w, "%s (OpenAPI %s): %d operations reviewed\n\n", title, doc.OpenAPI, len(doc.Operations))
	if len(findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}

	counts := map[audit.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		label := strings.ToUpper(f.Severity.String())
		if f.Operation != "" {
			fmt.Fprintf(w, "  [%s] %-8s %s %s\n", f.RuleID, label, f.Operation, f.Message)
		} else {
			fmt.Fprintf(w, "  [%s] %-8s %s\n", f.RuleID, label, f.Message)
		}
	}

	var parts []string
	for _, s := range []audit.Severity{audit.Critical, audit.High, audit.Medium, audit.Low} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	fmt.Fprintf(w, "\nSummary: %s\n", strings.Join(parts, ", "))
}
