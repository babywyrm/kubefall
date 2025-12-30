package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/babywyrm/kubefall/internal/analysis"
	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/discovery"
	"github.com/babywyrm/kubefall/internal/output"
	"github.com/babywyrm/kubefall/internal/rbac"
)

func main() {
	var (
		dump    = flag.Bool("dump", false, "Dump resources if readable (secrets, configmaps, pods, services, serviceaccounts)")
		full    = flag.Bool("full", false, "Print full contents of extracted resources (use with --dump)")
		jsonOut = flag.Bool("json", false, "Output results in JSON (machine-readable)")
		mode    = flag.String("mode", "red", "Output mode: red (exploit-focused), blue (detection-focused), audit (compliance)")
		explain = flag.Bool("explain", false, "Explain why findings are significant")
		verbose = flag.Bool("verbose", false, "Show detailed progress of what is being checked")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `kubeenum - Kubernetes RBAC Enumerator
-------------------------------------

Usage:
  kubeenum [options]

Options:
  --dump       Dump resources if readable (secrets, configmaps, pods, services, serviceaccounts)
  --full       Print full contents of extracted resources (use with --dump)
  --json       Output results in JSON (machine-readable)
  --mode       Output mode: red (exploit-focused), blue (detection-focused), audit (compliance) [default: red]
  --explain    Explain why findings are significant
  --verbose    Show detailed progress of what is being checked
  -h, --help   Show this help message

Examples:
  kubeenum
  kubeenum --dump
  kubeenum --dump --full
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
	enumerator, err := rbac.NewEnumerator(*verbose)
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

	// Discover services if we can list them
	namespaces := []string{results.Namespace}
	for ns := range results.Permissions.Namespaces {
		namespaces = append(namespaces, ns)
	}
	services := discovery.DiscoverServices(enumerator.GetClient(), enumerator.GetToken(), namespaces)
	results.Services = services

	// Extract useful data from dumps
	if *dump {
		extracted := make(map[string]interface{})
		for ns, perms := range results.Permissions.Namespaces {
			if cmData, ok := perms.Dumps["configmaps"]; ok && cmData != "" {
				extracted[ns+"/configmaps"] = analysis.ExtractFromConfigMap(cmData)
			}
			if secretData, ok := perms.Dumps["secrets"]; ok && secretData != "" {
				extracted[ns+"/secrets"] = analysis.ExtractFromSecret(secretData)
			}
		}
		if len(extracted) > 0 {
			results.Extracted = extracted
		}
	}

	// Output results
	outputMode := output.ParseMode(*mode)
	formatter := output.NewFormatter(outputMode, *explain, *full)

	if *jsonOut {
		formatter.OutputJSON(results, os.Stdout)
	} else {
		formatter.OutputHuman(results, os.Stdout)
	}
}
