package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/babywyrm/kubefall/internal/analysis"
	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/discovery"
	"github.com/babywyrm/kubefall/internal/output"
	"github.com/babywyrm/kubefall/internal/rbac"
)

func containsAny(slice []string, values []string) bool {
	for _, v := range slice {
		for _, val := range values {
			if v == val {
				return true
			}
		}
	}
	return false
}

func main() {
	var (
		dump        = flag.Bool("dump", false, "Dump resources if readable (secrets, configmaps, pods, services, serviceaccounts)")
		events      = flag.Bool("events", false, "Analyze Kubernetes events for security-relevant patterns")
		eventsSince = flag.String("events-since", "", "Only analyze events since this duration (e.g., 24h, 1h, 30m)")
		eventsLimit = flag.Int("events-limit", 20, "Maximum number of events to show per category")
		full        = flag.Bool("full", false, "Print full contents of extracted resources (use with --dump)")
		jsonOut     = flag.Bool("json", false, "Output results in JSON (machine-readable)")
		format      = flag.String("format", "text", "Output format: text, json, csv, html, markdown")
		outputFile  = flag.String("output", "", "Write output to file (default: stdout)")
		severity    = flag.String("severity", "", "Filter by severity: critical,high,interesting,normal (comma-separated, e.g. 'critical,high')")
		summaryOnly = flag.Bool("summary-only", false, "Show only summary section")
		noColor     = flag.Bool("no-color", false, "Disable colored output")
		mode        = flag.String("mode", "red", "Output mode: red (exploit-focused), blue (detection-focused), audit (compliance)")
		explain     = flag.Bool("explain", false, "Explain why findings are significant")
		verbose     = flag.Bool("verbose", false, "Show detailed progress of what is being checked")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `kubeenum - Kubernetes RBAC Enumerator
-------------------------------------

Usage:
  kubeenum [options]

Options:
  --dump         Dump resources if readable (secrets, configmaps, pods, services, serviceaccounts)
  --events       Analyze Kubernetes events for security-relevant patterns
  --events-since Only analyze events since this duration (e.g., 24h, 1h, 30m)
  --events-limit Maximum number of events to show per category [default: 20]
  --full         Print full contents of extracted resources (use with --dump)
  --format       Output format: text, json, csv, html, markdown [default: text]
  --output       Write output to file (default: stdout)
  --severity     Filter by severity: critical,high,interesting,normal (comma-separated)
  --summary-only Show only summary section
  --no-color     Disable colored output
  --mode         Output mode: red (exploit-focused), blue (detection-focused), audit (compliance) [default: red]
  --explain      Explain why findings are significant
  --verbose      Show detailed progress of what is being checked
  -h, --help     Show this help message

Examples:
  kubeenum
  kubeenum --dump
  kubeenum --dump --full
  kubeenum --events
  kubeenum --events --events-since 24h
  kubeenum --events --events-limit 50
  kubeenum --format json --output results.json
  kubeenum --severity critical,high
  kubeenum --summary-only
  kubeenum --format csv --output findings.csv
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
	results, err := enumerator.Enumerate(*dump, *events)
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

	// Discover cluster version
	if clusterInfo, err := discovery.DiscoverClusterVersion(enumerator.GetClient(), enumerator.GetToken()); err == nil {
		results.ClusterInfo = clusterInfo
	}

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
		podSecurityMap := make(map[string]interface{})
		tokenExtraction := &analysis.TokenExtraction{
			ServiceAccountTokens: []analysis.ServiceAccountToken{},
			HighPrivilegeSAs:     []analysis.ServiceAccountInfo{},
			AllServiceAccounts:   []analysis.ServiceAccountInfo{},
		}

		for ns, perms := range results.Permissions.Namespaces {
			if cmData, ok := perms.Dumps["configmaps"]; ok && cmData != "" {
				extracted[ns+"/configmaps"] = analysis.ExtractFromConfigMap(cmData)
			}
			if secretData, ok := perms.Dumps["secrets"]; ok && secretData != "" {
				extracted[ns+"/secrets"] = analysis.ExtractFromSecret(secretData)
				// Extract ServiceAccount tokens from secrets
				saTokens := analysis.ExtractSATokensFromSecrets(secretData)
				tokenExtraction.ServiceAccountTokens = append(tokenExtraction.ServiceAccountTokens, saTokens...)
			}
			if podsData, ok := perms.Dumps["pods"]; ok && podsData != "" {
				podSecurityMap[ns] = analysis.AnalyzePodSecurity(podsData)
				// Extract ServiceAccounts from pods
				saFromPods := analysis.ExtractServiceAccountsFromPods(podsData)
				tokenExtraction.AllServiceAccounts = append(tokenExtraction.AllServiceAccounts, saFromPods...)
			}
			if saData, ok := perms.Dumps["serviceaccounts"]; ok && saData != "" {
				saFromList := analysis.ExtractServiceAccountsFromSAList(saData)
				// Merge with existing SAs
				existingMap := make(map[string]bool)
				for _, sa := range tokenExtraction.AllServiceAccounts {
					existingMap[sa.Namespace+":"+sa.Name] = true
				}
				for _, sa := range saFromList {
					key := sa.Namespace + ":" + sa.Name
					if !existingMap[key] {
						tokenExtraction.AllServiceAccounts = append(tokenExtraction.AllServiceAccounts, sa)
					}
				}
			}
		}

		// Identify high-privilege ServiceAccounts
		for _, sa := range tokenExtraction.AllServiceAccounts {
			if analysis.IsHighPrivilegeSA(sa.Name) {
				tokenExtraction.HighPrivilegeSAs = append(tokenExtraction.HighPrivilegeSAs, sa)
			}
		}

		if len(extracted) > 0 {
			results.Extracted = extracted
		}
		if len(podSecurityMap) > 0 {
			results.PodSecurity = podSecurityMap
		}
		if len(tokenExtraction.ServiceAccountTokens) > 0 || len(tokenExtraction.HighPrivilegeSAs) > 0 || len(tokenExtraction.AllServiceAccounts) > 0 {
			results.TokenExtraction = tokenExtraction
		}
	}

	// Analyze RBAC if we can read cluster roles/bindings
	if clusterRoleBindings, ok := results.Permissions.Cluster.Resources["clusterrolebindings"]; ok {
		if containsAny(clusterRoleBindings, []string{"get", "list"}) {
			bindingsData := enumerator.DumpClusterResource("clusterrolebindings")
			if bindingsData != "" {
				rbacAnalysis := analysis.AnalyzeClusterRoleBindings(bindingsData)
				results.RBACAnalysis = rbacAnalysis
			}
		}
	}

	// Analyze events if requested with --events flag
	if *events {
		// Parse events-since duration if provided
		var eventsSinceDuration time.Duration
		if *eventsSince != "" {
			var err error
			eventsSinceDuration, err = time.ParseDuration(*eventsSince)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Invalid --events-since duration '%s': %v\n", *eventsSince, err)
				fmt.Fprintf(os.Stderr, "         Using default (no time filter)\n")
			}
		}

		eventAnalysisMap := make(map[string]interface{})
		eventsAnalyzedCount := 0
		for ns, perms := range results.Permissions.Namespaces {
			if eventsData, ok := perms.Dumps["events"]; ok && eventsData != "" {
				eventsAnalyzedCount++
				eventAnalysis := analysis.AnalyzeEvents(eventsData, eventsSinceDuration)
				// Include analysis if there are security-relevant findings
				if len(eventAnalysis.FailedAuth) > 0 ||
					len(eventAnalysis.SecretAccess) > 0 ||
					len(eventAnalysis.PodCreations) > 0 ||
					len(eventAnalysis.RBACChanges) > 0 ||
					len(eventAnalysis.ImagePullFailures) > 0 ||
					len(eventAnalysis.NetworkViolations) > 0 ||
					len(eventAnalysis.RecentEvents) > 0 {
					eventAnalysisMap[ns] = eventAnalysis
				}
			}
		}
		// Set EventAnalysis if we analyzed events (empty map {} in JSON means analyzed but no findings)
		if eventsAnalyzedCount > 0 {
			results.EventAnalysis = eventAnalysisMap
		}
	}

	// Determine output writer
	var w io.Writer = os.Stdout
	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create output file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		w = file
	}

	// Parse severity filter
	severityFilter := []string{}
	if *severity != "" {
		severityFilter = strings.Split(*severity, ",")
		for i := range severityFilter {
			severityFilter[i] = strings.TrimSpace(strings.ToLower(severityFilter[i]))
		}
	}

	// Output results
	outputMode := output.ParseMode(*mode)
	formatter := output.NewFormatter(outputMode, *explain, *full, *noColor, *summaryOnly, severityFilter, *eventsLimit)

	// Handle format
	if *jsonOut || *format == "json" {
		formatter.OutputJSON(results, w)
	} else {
		switch *format {
		case "csv":
			formatter.OutputCSV(results, w)
		case "html":
			formatter.OutputHTML(results, w)
		case "markdown":
			formatter.OutputMarkdown(results, w)
		default:
			formatter.OutputHuman(results, w)
		}
	}
}
