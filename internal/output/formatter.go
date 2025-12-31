package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/babywyrm/kubefall/internal/analysis"
	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/discovery"
	"github.com/babywyrm/kubefall/internal/rbac"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorBlue   = "\033[94m"
	colorBold   = "\033[1m"
)

func (f *Formatter) getColor(color string) string {
	if f.noColor {
		return ""
	}
	return color
}

type Mode int

const (
	ModeRed Mode = iota
	ModeBlue
	ModeAudit
)

func ParseMode(s string) Mode {
	switch strings.ToLower(s) {
	case "blue":
		return ModeBlue
	case "audit":
		return ModeAudit
	default:
		return ModeRed
	}
}

type Formatter struct {
	mode          Mode
	explain       bool
	full          bool
	noColor       bool
	summaryOnly   bool
	severityFilter []string
	eventsLimit   int
}

func NewFormatter(mode Mode, explain bool, full bool, noColor bool, summaryOnly bool, severityFilter []string, eventsLimit int) *Formatter {
	return &Formatter{
		mode:          mode,
		explain:       explain,
		full:          full,
		noColor:       noColor,
		summaryOnly:   summaryOnly,
		severityFilter: severityFilter,
		eventsLimit:   eventsLimit,
	}
}

func (f *Formatter) OutputJSON(results *rbac.Results, w io.Writer) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(w, "Error marshaling JSON: %v\n", err)
		return
	}
	fmt.Fprintln(w, string(data))
}

type Finding struct {
	Severity   string
	Resource   string
	Namespace  string
	Verbs      []string
	Message    string
	Explanation string
}

type Findings struct {
	Critical   []Finding
	High       []Finding
	Interesting []Finding
	Normal     []Finding
}

func (f *Formatter) OutputHuman(results *rbac.Results, w io.Writer) {
	findings := f.collectFindings(results)
	
	// Apply severity filter
	if len(f.severityFilter) > 0 {
		findings = f.filterFindings(findings)
	}

	allNamespaces := f.getAllNamespaces(results)

	if f.summaryOnly {
		f.printSummaryWithNamespaces(w, findings, allNamespaces, results)
		return
	}

	f.printHeader(w, results)
	f.printClusterInfo(w, results)
	f.printCriticalFindings(w, findings)
	f.printHighFindings(w, findings)
	f.printRBACAnalysis(w, results)
	f.printTokenExtraction(w, results)
	f.printPodSecurity(w, results)
	f.printExtractedData(w, results)
	f.printServices(w, results)
	f.printDetailedResults(w, results, findings)
	f.printSummaryWithNamespaces(w, findings, allNamespaces, results)
	f.printEventAnalysis(w, results)
}

func (f *Formatter) getAllNamespaces(results *rbac.Results) []string {
	namespaces := []string{}
	for ns := range results.Permissions.Namespaces {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	return namespaces
}

func (f *Formatter) printHeader(w io.Writer, results *rbac.Results) {
	fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", f.getColor(colorBold), f.getColor(colorReset))
	fmt.Fprintf(w, "%s║%s  %sKUBEFALL - Kubernetes RBAC Enumeration%s                    %s║%s\n", f.getColor(colorBold), f.getColor(colorReset), f.getColor(colorBold), f.getColor(colorReset), f.getColor(colorBold), f.getColor(colorReset))
	fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", f.getColor(colorBold), f.getColor(colorReset))

	if results.Context != nil {
		if ctx, ok := results.Context.(*context.Context); ok {
			fmt.Fprintf(w, "%s[ENV]%s Type: %s%s%s", colorBlue, colorReset, colorBold, ctx.Type, colorReset)
			if ctx.Cloud != "" {
				fmt.Fprintf(w, " | Cloud: %s%s%s", colorBold, ctx.Cloud, colorReset)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	if results.Claims != nil {
		if sub, ok := results.Claims["sub"].(string); ok {
			fmt.Fprintf(w, "%s[SA]%s  %s\n", colorBlue, colorReset, sub)
		}
		fmt.Fprintf(w, "%s[NS]%s  %s\n\n", colorBlue, colorReset, results.Namespace)
	}
}

func (f *Formatter) printCriticalFindings(w io.Writer, findings Findings) {
	if len(findings.Critical) == 0 {
		return
	}

	fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", f.getColor(colorRed), f.getColor(colorReset))
	fmt.Fprintf(w, "%s║%s  %s🔴 CRITICAL FINDINGS 🔴%s                                    %s║%s\n", f.getColor(colorRed), f.getColor(colorReset), f.getColor(colorBold), f.getColor(colorReset), f.getColor(colorRed), f.getColor(colorReset))
	fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", f.getColor(colorRed), f.getColor(colorReset))

	for _, finding := range findings.Critical {
		fmt.Fprintf(w, "%s[CRITICAL]%s %s%s%s in %s%s%s\n", 
			f.getColor(colorRed), f.getColor(colorReset), f.getColor(colorBold), finding.Resource, f.getColor(colorReset), 
			f.getColor(colorYellow), finding.Namespace, f.getColor(colorReset))
		fmt.Fprintf(w, "         Verbs: %s%s%s\n", f.getColor(colorBold), strings.Join(finding.Verbs, ", "), f.getColor(colorReset))
		fmt.Fprintf(w, "         %s%s%s\n", f.getColor(colorRed), finding.Message, f.getColor(colorReset))
		if f.explain && finding.Explanation != "" {
			fmt.Fprintf(w, "         %s→ %s%s\n", f.getColor(colorYellow), finding.Explanation, f.getColor(colorReset))
		}
		fmt.Fprintf(w, "\n")
	}
}

func (f *Formatter) printHighFindings(w io.Writer, findings Findings) {
	if len(findings.High) == 0 {
		return
	}

	fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", f.getColor(colorYellow), f.getColor(colorReset))
	fmt.Fprintf(w, "%s║%s  %s🟠 HIGH SEVERITY FINDINGS 🟠%s                                %s║%s\n", f.getColor(colorYellow), f.getColor(colorReset), f.getColor(colorBold), f.getColor(colorReset), f.getColor(colorYellow), f.getColor(colorReset))
	fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", f.getColor(colorYellow), f.getColor(colorReset))

	for _, finding := range findings.High {
		fmt.Fprintf(w, "%s[HIGH]%s     %s%s%s in %s%s%s\n", 
			f.getColor(colorYellow), f.getColor(colorReset), f.getColor(colorBold), finding.Resource, f.getColor(colorReset), 
			f.getColor(colorYellow), finding.Namespace, f.getColor(colorReset))
		fmt.Fprintf(w, "         Verbs: %s%s%s\n", f.getColor(colorBold), strings.Join(finding.Verbs, ", "), f.getColor(colorReset))
		fmt.Fprintf(w, "         %s%s%s\n", f.getColor(colorYellow), finding.Message, f.getColor(colorReset))
		if f.explain && finding.Explanation != "" {
			fmt.Fprintf(w, "         %s→ %s%s\n", f.getColor(colorYellow), finding.Explanation, f.getColor(colorReset))
		}
		fmt.Fprintf(w, "\n")
	}
}

func (f *Formatter) printDetailedResults(w io.Writer, results *rbac.Results, findings Findings) {
	if len(findings.Interesting) > 0 {
		fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorYellow, colorReset)
		fmt.Fprintf(w, "%sINTERESTING FINDINGS%s\n", colorBold, colorReset)
		fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorYellow, colorReset)

		for _, finding := range findings.Interesting {
			fmt.Fprintf(w, "%s[!]%s %s%s%s (%s) - %s\n", 
				colorYellow, colorReset, colorBold, finding.Resource, colorReset,
				finding.Namespace, finding.Message)
		}
		fmt.Fprintf(w, "\n")
	}

	fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorBlue, colorReset)
	fmt.Fprintf(w, "%sNAMESPACE PERMISSIONS%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorBlue, colorReset)

	namespaces := f.getSortedNamespaces(results.Permissions.Namespaces, findings)
	for _, ns := range namespaces {
		perms := results.Permissions.Namespaces[ns]
		resources := f.getSortedResources(perms.Resources, findings, ns)

		if len(resources) == 0 {
			continue
		}

		fmt.Fprintf(w, "%s┌─ Namespace: %s%s%s ───────────────────────────────────────────┐%s\n", 
			colorBold, colorBlue, ns, colorReset, colorReset)
		
		for _, res := range resources {
			verbs := perms.Resources[res]
			severity := f.getSeverity(res, verbs, ns, findings)
			verbStr := strings.Join(verbs, ",")
			
			var color string
			switch severity {
			case "critical":
				color = colorRed
			case "high":
				color = colorYellow
			case "interesting":
				color = colorYellow
			default:
				color = colorGreen
			}

			fmt.Fprintf(w, "│ %s%-20s%s %s%-30s%s │\n", 
				colorBold, res, colorReset, color, verbStr, colorReset)

			if dump, ok := perms.Dumps[res]; ok && dump != "" {
				fmt.Fprintf(w, "│ %s[DUMP AVAILABLE]%s %s%s%s                              │\n", 
					colorYellow, colorReset, colorBold, res, colorReset)
			}
		}
		fmt.Fprintf(w, "%s└────────────────────────────────────────────────────────────────┘%s\n\n", colorBold, colorReset)
	}

	if len(results.Permissions.Cluster.Resources) > 0 {
		fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorBlue, colorReset)
		fmt.Fprintf(w, "%sCLUSTER PERMISSIONS%s\n", colorBold, colorReset)
		fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorBlue, colorReset)

		resources := f.getSortedClusterResources(results.Permissions.Cluster.Resources, findings)
		for _, res := range resources {
			verbs := results.Permissions.Cluster.Resources[res]
			severity := f.getSeverity(res, verbs, "", findings)
			
			var color string
			switch severity {
			case "critical":
				color = colorRed
			case "high":
				color = colorYellow
			case "interesting":
				color = colorYellow
			default:
				color = colorGreen
			}

			fmt.Fprintf(w, "  %s%-25s%s %s%s%s\n", 
				colorBold, res, colorReset, color, strings.Join(verbs, ","), colorReset)
		}
		fmt.Fprintf(w, "\n")
	}
}

func (f *Formatter) printExtractedData(w io.Writer, results *rbac.Results) {
	if results.Extracted == nil {
		return
	}

	extracted, ok := results.Extracted.(map[string]interface{})
	if !ok || len(extracted) == 0 {
		return
	}

	fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", colorYellow, colorReset)
	fmt.Fprintf(w, "%s║%s  %s📦 EXTRACTED DATA FROM RESOURCES%s                          %s║%s\n", colorYellow, colorReset, colorBold, colorReset, colorYellow, colorReset)
	fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorYellow, colorReset)

	for key, data := range extracted {
		if ext, ok := data.(*analysis.ExtractedData); ok {
			parts := strings.Split(key, "/")
			ns := parts[0]
			resType := parts[1]
			
			fmt.Fprintf(w, "%s[%s]%s %s(%s)%s\n", colorYellow, key, colorReset, colorBlue, resType, colorReset)
			
			hasData := false
			
			if len(ext.Tokens) > 0 {
				hasData = true
				fmt.Fprintf(w, "  %s🔑 Tokens Found:%s\n", colorBold, colorReset)
				for _, token := range ext.Tokens {
					fmt.Fprintf(w, "    • Type: %s%s%s", colorBold, token.Type, colorReset)
					if token.Valid {
						fmt.Fprintf(w, " %s(Valid JWT)%s", colorGreen, colorReset)
						if sub, ok := token.Claims["sub"].(string); ok {
							fmt.Fprintf(w, " - %s", sub)
						}
					}
					fmt.Fprintf(w, "\n")
				}
			}

			if len(ext.Credentials) > 0 {
				hasData = true
				fmt.Fprintf(w, "  %s🔐 Credentials Found:%s\n", colorBold, colorReset)
				for _, cred := range ext.Credentials {
					fmt.Fprintf(w, "    • %s%s%s: %s%s%s\n", 
						colorBold, cred.Type, colorReset, 
						colorYellow, cred.Key, colorReset)
				}
			}

			if len(ext.Endpoints) > 0 {
				hasData = true
				fmt.Fprintf(w, "  %s🌐 Endpoints Found:%s\n", colorBold, colorReset)
				for _, endpoint := range ext.Endpoints {
					fmt.Fprintf(w, "    • %s%s%s\n", colorBlue, endpoint, colorReset)
				}
			}

			if len(ext.Base64Data) > 0 {
				hasData = true
				fmt.Fprintf(w, "  %s📦 Base64 Data Found:%s\n", colorBold, colorReset)
				for _, b64 := range ext.Base64Data {
					if f.full {
						fmt.Fprintf(w, "    %s%s%s:\n", colorBold, b64.Key, colorReset)
						lines := strings.Split(b64.Decoded, "\n")
						for _, line := range lines {
							fmt.Fprintf(w, "      %s%s%s\n", colorYellow, line, colorReset)
						}
						fmt.Fprintf(w, "\n")
					} else {
						preview := truncate(b64.Decoded, 80)
						fmt.Fprintf(w, "    • %s%s%s: %s%s%s\n", 
							colorBold, b64.Key, colorReset,
							colorYellow, preview, colorReset)
					}
				}
			}

			if len(ext.EnvVars) > 0 {
				hasData = true
				fmt.Fprintf(w, "  %s⚙️  Config/Env Variables Found:%s\n", colorBold, colorReset)
				count := 0
				for k, v := range ext.EnvVars {
					if f.full {
						fmt.Fprintf(w, "    %s%s%s: %s%s%s\n", 
							colorBold, k, colorReset, 
							colorYellow, v, colorReset)
					} else {
						if count < 10 {
							preview := truncate(v, 60)
							fmt.Fprintf(w, "    • %s%s%s: %s%s%s\n", 
								colorBold, k, colorReset, 
								colorYellow, preview, colorReset)
							count++
						}
					}
				}
				if !f.full && len(ext.EnvVars) > 10 {
					fmt.Fprintf(w, "    ... and %d more\n", len(ext.EnvVars)-10)
				}
			}

			if len(ext.KeyValues) > 0 {
				if !hasData {
					fmt.Fprintf(w, "  %s📋 ConfigMap Contents (%d keys):%s\n", colorBold, len(ext.KeyValues), colorReset)
					count := 0
					for k, v := range ext.KeyValues {
						if f.full {
							fmt.Fprintf(w, "    %s%s%s:\n", colorBold, k, colorReset)
							lines := strings.Split(v, "\n")
							for _, line := range lines {
								fmt.Fprintf(w, "      %s%s%s\n", colorYellow, line, colorReset)
							}
							fmt.Fprintf(w, "\n")
						} else {
							if count < 15 {
								preview := truncate(v, 80)
								fmt.Fprintf(w, "    • %s%s%s: %s%s%s\n", 
									colorBold, k, colorReset, 
									colorYellow, preview, colorReset)
								count++
							}
						}
					}
					if !f.full && len(ext.KeyValues) > 15 {
						fmt.Fprintf(w, "    ... and %d more keys\n", len(ext.KeyValues)-15)
						fmt.Fprintf(w, "  %s💡 TIP: Use --full to see all contents, or 'kubectl get configmap <name> -n %s -o yaml'%s\n", colorBlue, ns, colorReset)
					} else if !f.full {
						fmt.Fprintf(w, "  %s💡 TIP: Use --full to see full contents%s\n", colorBlue, colorReset)
					}
				} else {
					fmt.Fprintf(w, "  %s📋 All Keys (%d):%s %s%s%s\n", colorBold, len(ext.Keys), colorReset, colorYellow, strings.Join(ext.Keys, ", "), colorReset)
					if f.full {
						for k, v := range ext.KeyValues {
							fmt.Fprintf(w, "    %s%s%s:\n", colorBold, k, colorReset)
							lines := strings.Split(v, "\n")
							for _, line := range lines {
								fmt.Fprintf(w, "      %s%s%s\n", colorYellow, line, colorReset)
							}
							fmt.Fprintf(w, "\n")
						}
					}
				}
			} else if !hasData {
				fmt.Fprintf(w, "  %sNo data found (ConfigMap may be empty)%s\n", colorYellow, colorReset)
			}

			fmt.Fprintf(w, "\n")
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func (f *Formatter) printServices(w io.Writer, results *rbac.Results) {
	if results.Services == nil {
		return
	}

	services, ok := results.Services.(map[string][]discovery.ServiceInfo)
	if !ok || len(services) == 0 {
		return
	}

	fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorBlue, colorReset)
	fmt.Fprintf(w, "%sNETWORK DISCOVERY%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorBlue, colorReset)

	for ns, svcs := range services {
		fmt.Fprintf(w, "  %sNamespace: %s%s\n", colorBold, ns, colorReset)
		for _, svc := range svcs {
			ports := []string{}
			for _, p := range svc.Ports {
				ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
			}
			fmt.Fprintf(w, "    • %s%s%s (%s) - %s\n", 
				colorBold, svc.Name, colorReset, svc.Type, strings.Join(ports, ", "))
			if svc.Type == "NodePort" || svc.Type == "LoadBalancer" {
				fmt.Fprintf(w, "      %s⚠️  Exposed externally!%s\n", colorYellow, colorReset)
			}
		}
		fmt.Fprintf(w, "\n")
	}
}

func (f *Formatter) printSummary(w io.Writer, findings Findings) {
	f.printSummaryWithNamespaces(w, findings, nil, nil)
}

func (f *Formatter) printSummaryWithNamespaces(w io.Writer, findings Findings, allNamespaces []string, results *rbac.Results) {
	fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", colorBold, colorReset)
	fmt.Fprintf(w, "%s║%s  %sSUMMARY%s                                                      %s║%s\n", colorBold, colorReset, colorBold, colorReset, colorBold, colorReset)
	fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorBold, colorReset)

	if allNamespaces != nil && len(allNamespaces) > 0 {
		fmt.Fprintf(w, "%s[%d] NAMESPACES DISCOVERED%s\n", colorBlue, len(allNamespaces), colorReset)
		fmt.Fprintf(w, "    %s%s%s\n\n", colorBold, strings.Join(allNamespaces, ", "), colorReset)
	}

	totalCritical := len(findings.Critical)
	totalHigh := len(findings.High)
	totalInteresting := len(findings.Interesting)
	totalNormal := len(findings.Normal)

	if totalCritical > 0 {
		fmt.Fprintf(w, "%s[%d] CRITICAL%s - Immediate escalation paths available\n", 
			f.getColor(colorRed), totalCritical, f.getColor(colorReset))
		for _, finding := range findings.Critical {
			fmt.Fprintf(w, "    • %s%s%s in %s\n", f.getColor(colorBold), finding.Resource, f.getColor(colorReset), finding.Namespace)
		}
		fmt.Fprintf(w, "\n")
	}

	if totalHigh > 0 {
		fmt.Fprintf(w, "%s[%d] HIGH%s - Significant security risks\n", 
			f.getColor(colorYellow), totalHigh, f.getColor(colorReset))
		for _, finding := range findings.High {
			fmt.Fprintf(w, "    • %s%s%s in %s\n", f.getColor(colorBold), finding.Resource, f.getColor(colorReset), finding.Namespace)
		}
		fmt.Fprintf(w, "\n")
	}

	if totalInteresting > 0 {
		fmt.Fprintf(w, "%s[%d] INTERESTING%s - Potential data exfiltration or lateral movement\n", 
			f.getColor(colorYellow), totalInteresting, f.getColor(colorReset))
		for _, finding := range findings.Interesting {
			fmt.Fprintf(w, "    • %s%s%s in %s\n", f.getColor(colorBold), finding.Resource, f.getColor(colorReset), finding.Namespace)
		}
		fmt.Fprintf(w, "\n")
	}

	if totalNormal > 0 {
		fmt.Fprintf(w, "%s[%d] NORMAL%s - Standard permissions\n\n", 
			f.getColor(colorGreen), totalNormal, f.getColor(colorReset))
	}

	// Add event analysis summary if available
	if results != nil && results.EventAnalysis != nil {
		if eventAnalysisMap, ok := results.EventAnalysis.(map[string]interface{}); ok {
			eventSummary := f.getEventSummary(eventAnalysisMap)
			if eventSummary.TotalEvents > 0 {
				fmt.Fprintf(w, "%s[EVENT ANALYSIS]%s\n", f.getColor(colorBlue), f.getColor(colorReset))
				if eventSummary.FailedAuth > 0 {
					fmt.Fprintf(w, "    %s🔴 Failed Auth:%s %d\n", f.getColor(colorRed), f.getColor(colorReset), eventSummary.FailedAuth)
				}
				if eventSummary.RBACChanges > 0 {
					fmt.Fprintf(w, "    %s🟠 RBAC Changes:%s %d\n", f.getColor(colorYellow), f.getColor(colorReset), eventSummary.RBACChanges)
				}
				if eventSummary.SecretAccess > 0 {
					fmt.Fprintf(w, "    %s🔑 Secret Access:%s %d\n", f.getColor(colorYellow), f.getColor(colorReset), eventSummary.SecretAccess)
				}
				if eventSummary.ImagePullFailures > 0 {
					fmt.Fprintf(w, "    %s⚠️  Image Pull Failures:%s %d\n", f.getColor(colorYellow), f.getColor(colorReset), eventSummary.ImagePullFailures)
				}
				if eventSummary.PodCreations > 0 {
					fmt.Fprintf(w, "    %s📦 Pod Creations:%s %d\n", f.getColor(colorYellow), f.getColor(colorReset), eventSummary.PodCreations)
				}
				fmt.Fprintf(w, "\n")
			}
		}
	}

	if totalCritical == 0 && totalHigh == 0 && totalInteresting == 0 {
		fmt.Fprintf(w, "%s✓ No obvious escalation paths detected%s\n", f.getColor(colorGreen), f.getColor(colorReset))
		fmt.Fprintf(w, "%s  Consider using --dump to inspect readable resources%s\n\n", f.getColor(colorYellow), f.getColor(colorReset))
	} else {
		fmt.Fprintf(w, "%s💡 TIP:%s Use --dump to extract secrets/configmaps/serviceaccounts\n", f.getColor(colorYellow), f.getColor(colorReset))
		fmt.Fprintf(w, "%s💡 TIP:%s Use --explain for detailed explanations of findings\n", f.getColor(colorYellow), f.getColor(colorReset))
		if results != nil && results.EventAnalysis == nil {
			fmt.Fprintf(w, "%s💡 TIP:%s Use --events to analyze Kubernetes events\n", f.getColor(colorYellow), f.getColor(colorReset))
		}
		fmt.Fprintf(w, "\n")
	}
}

type EventSummary struct {
	TotalEvents       int
	FailedAuth        int
	RBACChanges       int
	SecretAccess      int
	ImagePullFailures int
	PodCreations      int
}

func (f *Formatter) getEventSummary(eventAnalysisMap map[string]interface{}) EventSummary {
	summary := EventSummary{}
	for _, data := range eventAnalysisMap {
		if eventAnalysis, ok := data.(*analysis.EventAnalysis); ok {
			summary.FailedAuth += len(eventAnalysis.FailedAuth)
			summary.RBACChanges += len(eventAnalysis.RBACChanges)
			summary.SecretAccess += len(eventAnalysis.SecretAccess)
			summary.ImagePullFailures += len(eventAnalysis.ImagePullFailures)
			summary.PodCreations += len(eventAnalysis.PodCreations)
		}
	}
	summary.TotalEvents = summary.FailedAuth + summary.RBACChanges + summary.SecretAccess + 
		summary.ImagePullFailures + summary.PodCreations
	return summary
}

func (f *Formatter) collectFindings(results *rbac.Results) Findings {
	findings := Findings{
		Critical:   []Finding{},
		High:       []Finding{},
		Interesting: []Finding{},
		Normal:     []Finding{},
	}

	for ns, perms := range results.Permissions.Namespaces {
		for resource, verbs := range perms.Resources {
			if len(verbs) == 0 {
				continue
			}

			severity, message, explanation := f.analyzeResource(resource, verbs)
			finding := Finding{
				Resource:    resource,
				Namespace:   ns,
				Verbs:       verbs,
				Message:     message,
				Explanation: explanation,
			}

			switch severity {
			case "critical":
				finding.Severity = "critical"
				findings.Critical = append(findings.Critical, finding)
			case "high":
				finding.Severity = "high"
				findings.High = append(findings.High, finding)
			case "interesting":
				finding.Severity = "interesting"
				findings.Interesting = append(findings.Interesting, finding)
			default:
				finding.Severity = "normal"
				findings.Normal = append(findings.Normal, finding)
			}
		}
	}

	for resource, verbs := range results.Permissions.Cluster.Resources {
		if len(verbs) == 0 {
			continue
		}

		severity, message, explanation := f.analyzeResource(resource, verbs)
		finding := Finding{
			Resource:    resource,
			Namespace:  "cluster",
			Verbs:       verbs,
			Message:     message,
			Explanation: explanation,
		}

		switch severity {
		case "critical":
			findings.Critical = append(findings.Critical, finding)
		case "high":
			findings.High = append(findings.High, finding)
		case "interesting":
			findings.Interesting = append(findings.Interesting, finding)
		default:
			findings.Normal = append(findings.Normal, finding)
		}
	}

	return findings
}

func (f *Formatter) analyzeResource(resource string, verbs []string) (severity, message, explanation string) {
	if contains(verbs, "*") {
		return "critical", "WILDCARD VERBS - Full access to all operations", "Wildcard verbs grant unrestricted access"
	}

	if resource == "secrets" && contains(verbs, "get") {
		return "critical", "Can read secrets - credential exposure risk", "Reading secrets can expose passwords, tokens, and keys for lateral movement"
	}

	if resource == "pods" && contains(verbs, "create") {
		return "critical", "Can create pods - potential node escape", "Pod creation with hostPath/privileged can lead to node compromise"
	}

	if (resource == "clusterroles" || resource == "clusterrolebindings") && contains(verbs, "create") {
		return "critical", "Can create cluster RBAC - cluster-admin path", "Creating cluster roles/bindings can grant cluster-admin privileges"
	}

	if (resource == "mutatingwebhookconfigurations" || resource == "validatingwebhookconfigurations") && contains(verbs, "create") {
		return "critical", "Can create webhook configs - cluster compromise", "Webhook configurations can intercept and modify API requests"
	}

	if resource == "serviceaccounts" && contains(verbs, "create") {
		return "high", "Can create serviceaccounts - token extraction", "Creating ServiceAccounts can lead to token extraction and privilege escalation"
	}

	if resource == "rolebindings" && contains(verbs, "create") {
		return "high", "Can create rolebindings - namespace escalation", "Creating role bindings can escalate privileges within namespace"
	}

	if resource == "customresourcedefinitions" && contains(verbs, "create") {
		return "high", "Can create CRDs - new attack surfaces", "Creating CRDs can enable new attack surfaces and resource types"
	}

	if resource == "configmaps" && (contains(verbs, "get") || contains(verbs, "list")) {
		return "interesting", "Can read configmaps - may contain secrets", "ConfigMaps may contain secrets, environment variables, or configuration data"
	}

	if resource == "serviceaccounts" && (contains(verbs, "get") || contains(verbs, "list")) {
		return "interesting", "Can read serviceaccounts - token discovery", "ServiceAccounts may have tokens or be used for impersonation"
	}

	if resource == "podtemplates" && (contains(verbs, "get") || contains(verbs, "list")) {
		return "interesting", "Can read podtemplates - may contain secrets", "PodTemplates may contain secrets, environment variables, or configuration"
	}

	if resource == "ingresses" && contains(verbs, "create") {
		return "interesting", "Can create ingresses - service exposure", "Ingress creation can expose internal services externally"
	}

	return "normal", "", ""
}

func (f *Formatter) getSeverity(resource string, verbs []string, namespace string, findings Findings) string {
	if namespace == "" {
		for _, finding := range findings.Critical {
			if finding.Resource == resource && finding.Namespace == "cluster" {
				return "critical"
			}
		}
		for _, finding := range findings.High {
			if finding.Resource == resource && finding.Namespace == "cluster" {
				return "high"
			}
		}
		for _, finding := range findings.Interesting {
			if finding.Resource == resource && finding.Namespace == "cluster" {
				return "interesting"
			}
		}
	} else {
		for _, finding := range findings.Critical {
			if finding.Resource == resource && finding.Namespace == namespace {
				return "critical"
			}
		}
		for _, finding := range findings.High {
			if finding.Resource == resource && finding.Namespace == namespace {
				return "high"
			}
		}
		for _, finding := range findings.Interesting {
			if finding.Resource == resource && finding.Namespace == namespace {
				return "interesting"
			}
		}
	}
	return "normal"
}

func (f *Formatter) getSortedNamespaces(nsPerms map[string]rbac.NamespacePermissions, findings Findings) []string {
	namespaces := []string{}
	for ns := range nsPerms {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	return namespaces
}

func (f *Formatter) getSortedResources(resources map[string][]string, findings Findings, namespace string) []string {
	type resWithSeverity struct {
		name     string
		severity int
	}

	resList := []resWithSeverity{}
	for res := range resources {
		severity := 0
		switch f.getSeverity(res, resources[res], namespace, findings) {
		case "critical":
			severity = 0
		case "high":
			severity = 1
		case "interesting":
			severity = 2
		default:
			severity = 3
		}
		resList = append(resList, resWithSeverity{res, severity})
	}

	sort.Slice(resList, func(i, j int) bool {
		if resList[i].severity != resList[j].severity {
			return resList[i].severity < resList[j].severity
		}
		return resList[i].name < resList[j].name
	})

	result := []string{}
	for _, r := range resList {
		result = append(result, r.name)
	}
	return result
}

func (f *Formatter) getSortedClusterResources(resources map[string][]string, findings Findings) []string {
	return f.getSortedResources(resources, findings, "")
}

func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}
