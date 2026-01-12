package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"

	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/rbac"
)

// filterFindings filters findings by severity
func (f *Formatter) filterFindings(findings Findings) Findings {
	filtered := Findings{
		Critical:    []Finding{},
		High:        []Finding{},
		Interesting: []Finding{},
		Normal:      []Finding{},
	}

	severityMap := make(map[string]bool)
	for _, s := range f.severityFilter {
		severityMap[s] = true
	}

	if severityMap["critical"] {
		filtered.Critical = findings.Critical
	}
	if severityMap["high"] {
		filtered.High = findings.High
	}
	if severityMap["interesting"] {
		filtered.Interesting = findings.Interesting
	}
	if severityMap["normal"] {
		filtered.Normal = findings.Normal
	}

	return filtered
}

// OutputCSV outputs results in CSV format
func (f *Formatter) OutputCSV(results *rbac.Results, w io.Writer) {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	writer.Write([]string{"Severity", "Resource", "Namespace", "Verbs", "Message"})

	findings := f.collectFindings(results)
	if len(f.severityFilter) > 0 {
		findings = f.filterFindings(findings)
	}

	// Write findings
	for _, finding := range findings.Critical {
		writer.Write([]string{
			"CRITICAL",
			finding.Resource,
			finding.Namespace,
			strings.Join(finding.Verbs, ","),
			finding.Message,
		})
	}
	for _, finding := range findings.High {
		writer.Write([]string{
			"HIGH",
			finding.Resource,
			finding.Namespace,
			strings.Join(finding.Verbs, ","),
			finding.Message,
		})
	}
	for _, finding := range findings.Interesting {
		writer.Write([]string{
			"INTERESTING",
			finding.Resource,
			finding.Namespace,
			strings.Join(finding.Verbs, ","),
			finding.Message,
		})
	}
}

// OutputMarkdown outputs results in Markdown format
func (f *Formatter) OutputMarkdown(results *rbac.Results, w io.Writer) {
	findings := f.collectFindings(results)
	if len(f.severityFilter) > 0 {
		findings = f.filterFindings(findings)
	}

	fmt.Fprintf(w, "# kubefall - Kubernetes RBAC Enumeration\n\n")

	if results.Context != nil {
		if ctx, ok := results.Context.(*context.Context); ok {
			fmt.Fprintf(w, "**Environment:** %s", ctx.Type)
			if ctx.Cloud != "" {
				fmt.Fprintf(w, " (%s)", ctx.Cloud)
			}
			fmt.Fprintf(w, "\n\n")
		}
	}

	if len(findings.Critical) > 0 {
		fmt.Fprintf(w, "## 🔴 Critical Findings\n\n")

		for _, finding := range findings.Critical {
			fmt.Fprintf(w, "### CRITICAL: %s in %s\n\n", finding.Resource, finding.Namespace)
			fmt.Fprintf(w, "- **Verbs:** %s\n", strings.Join(finding.Verbs, ", "))
			fmt.Fprintf(w, "- **Message:** %s\n", finding.Message)
			if f.explain && finding.Explanation != "" {
				fmt.Fprintf(w, "- **Explanation:** %s\n", finding.Explanation)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	if len(findings.High) > 0 {
		fmt.Fprintf(w, "## 🟠 High Severity Findings\n\n")

		for _, finding := range findings.High {
			fmt.Fprintf(w, "### HIGH: %s in %s\n\n", finding.Resource, finding.Namespace)
			fmt.Fprintf(w, "- **Verbs:** %s\n", strings.Join(finding.Verbs, ", "))
			fmt.Fprintf(w, "- **Message:** %s\n", finding.Message)
			if f.explain && finding.Explanation != "" {
				fmt.Fprintf(w, "- **Explanation:** %s\n", finding.Explanation)
			}
			fmt.Fprintf(w, "\n")
		}
	}

	if len(findings.Interesting) > 0 {
		fmt.Fprintf(w, "## ⚠️ Interesting Findings\n\n")
		for _, finding := range findings.Interesting {
			fmt.Fprintf(w, "- **%s** in %s: %s\n", finding.Resource, finding.Namespace, finding.Message)
		}
		fmt.Fprintf(w, "\n")
	}
}

// OutputHTML outputs results in HTML format
func (f *Formatter) OutputHTML(results *rbac.Results, w io.Writer) {
	findings := f.collectFindings(results)
	if len(f.severityFilter) > 0 {
		findings = f.filterFindings(findings)
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>kubefall - Kubernetes RBAC Enumeration</title>
    <style>
        body { font-family: monospace; margin: 20px; }
        .critical { color: #d32f2f; font-weight: bold; }
        .high { color: #f57c00; font-weight: bold; }
        .interesting { color: #fbc02d; }
        table { border-collapse: collapse; width: 100%%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>kubefall - Kubernetes RBAC Enumeration</h1>
`)

	if len(findings.Critical) > 0 {
		fmt.Fprintf(w, "    <h2>🔴 Critical Findings</h2>\n    <table>\n")
		fmt.Fprintf(w, "        <tr><th>Severity</th><th>Resource</th><th>Namespace</th><th>Verbs</th><th>Message</th></tr>\n")

		for _, finding := range findings.Critical {
			fmt.Fprintf(w, "        <tr class=\"critical\">\n")
			fmt.Fprintf(w, "            <td>CRITICAL</td>\n")
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Resource)
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Namespace)
			fmt.Fprintf(w, "            <td>%s</td>\n", strings.Join(finding.Verbs, ", "))
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Message)
			fmt.Fprintf(w, "        </tr>\n")
		}
		fmt.Fprintf(w, "    </table>\n")
	}

	if len(findings.High) > 0 {
		fmt.Fprintf(w, "    <h2>🟠 High Severity Findings</h2>\n    <table>\n")
		fmt.Fprintf(w, "        <tr><th>Severity</th><th>Resource</th><th>Namespace</th><th>Verbs</th><th>Message</th></tr>\n")

		for _, finding := range findings.High {
			fmt.Fprintf(w, "        <tr class=\"high\">\n")
			fmt.Fprintf(w, "            <td>HIGH</td>\n")
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Resource)
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Namespace)
			fmt.Fprintf(w, "            <td>%s</td>\n", strings.Join(finding.Verbs, ", "))
			fmt.Fprintf(w, "            <td>%s</td>\n", finding.Message)
			fmt.Fprintf(w, "        </tr>\n")
		}
		fmt.Fprintf(w, "    </table>\n")
	}

	fmt.Fprintf(w, `</body>
</html>
`)
}
