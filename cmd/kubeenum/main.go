package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/output"
	"github.com/babywyrm/kubefall/internal/rbac"
)

func main() {
	var (
		dump    = flag.Bool("dump", false, "Dump resources if readable (secrets, configmaps, pods, services)")
		jsonOut = flag.Bool("json", false, "Output results in JSON (machine-readable)")
		mode    = flag.String("mode", "red", "Output mode: red (exploit-focused), blue (detection-focused), audit (compliance)")
		explain = flag.Bool("explain", false, "Explain why findings are significant")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `kubeenum - Kubernetes RBAC Enumerator
-------------------------------------

Usage:
  kubeenum [options]

Options:
  --dump       Dump resources if readable (secrets, configmaps, pods, services)
  --json       Output results in JSON (machine-readable)
  --mode       Output mode: red (exploit-focused), blue (detection-focused), audit (compliance) [default: red]
  --explain    Explain why findings are significant
  -h, --help   Show this help message

Examples:
  kubeenum
  kubeenum --dump
  kubeenum --json
  kubeenum --json --dump
  kubeenum --mode blue --explain
`)
	}

	flag.Parse()

	// Detect environment context
	ctx, err := context.Detect()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not fully detect context: %v\n", err)
		ctx = &context.Context{} // Use empty context
	}

	// Initialize RBAC enumerator
	enumerator, err := rbac.NewEnumerator()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to initialize RBAC enumerator: %v\n", err)
		os.Exit(1)
	}

	// Run enumeration
	results, err := enumerator.Enumerate(*dump)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Enumeration failed: %v\n", err)
		os.Exit(1)
	}

	// Add context to results (enhance with token claims if available)
	if results.Claims != nil {
		enhancedCtx, err := context.DetectFromToken(results.Claims)
		if err == nil {
			ctx = enhancedCtx
		}
	}
	results.Context = ctx

	// Output results
	outputMode := output.ParseMode(*mode)
	formatter := output.NewFormatter(outputMode, *explain)

	if *jsonOut {
		formatter.OutputJSON(results, os.Stdout)
	} else {
		formatter.OutputHuman(results, os.Stdout)
	}
}
