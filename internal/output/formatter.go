package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/babywyrm/kubefall/internal/context"
	"github.com/babywyrm/kubefall/internal/rbac"
)

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
	mode    Mode
	explain bool
}

func NewFormatter(mode Mode, explain bool) *Formatter {
	return &Formatter{
		mode:    mode,
		explain: explain,
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

func (f *Formatter) OutputHuman(results *rbac.Results, w io.Writer) {
	// Context information
	if results.Context != nil {
		fmt.Fprintf(w, "=== ENVIRONMENT ===\n")
		if ctx, ok := results.Context.(*context.Context); ok {
			fmt.Fprintf(w, "Type: %s\n", ctx.Type)
			if ctx.Distribution != "" {
				fmt.Fprintf(w, "Distribution: %s\n", ctx.Distribution)
			}
			if ctx.Cloud != "" {
				fmt.Fprintf(w, "Cloud: %s\n", ctx.Cloud)
			}
			if len(ctx.Metadata) > 0 {
				fmt.Fprintf(w, "Metadata:\n")
				for k, v := range ctx.Metadata {
					fmt.Fprintf(w, "  %s: %s\n", k, v)
				}
			}
		}
	}

	// ServiceAccount info
	fmt.Fprintf(w, "\n=== SERVICE ACCOUNT ===\n")
	fmt.Fprintf(w, "Current namespace: %s\n", results.Namespace)
	if results.Claims != nil {
		fmt.Fprintf(w, "Token Claims:\n")
		for k, v := range results.Claims {
			fmt.Fprintf(w, "  %s: %v\n", k, v)
		}
	}

	// Namespace resources
	fmt.Fprintf(w, "\n=== NAMESPACE RESOURCES ===\n")
	for ns, perms := range results.Permissions.Namespaces {
		fmt.Fprintf(w, "\n-- Namespace: %s --\n", ns)
		for resource, verbs := range perms.Resources {
			if len(verbs) > 0 {
				flag := f.analyzeResource(resource, verbs, f.explain)
				fmt.Fprintf(w, "%-20s -> \033[92m%s\033[0m%s\n", resource, strings.Join(verbs, ","), flag)

				// Show dumps if available
				if dump, ok := perms.Dumps[resource]; ok && dump != "" {
					fmt.Fprintf(w, "  [DUMP] %s\n", resource)
					if f.mode == ModeRed {
						// Show truncated dump in red mode
						lines := strings.Split(dump, "\n")
						if len(lines) > 10 {
							fmt.Fprintf(w, "  %s\n  ... (truncated, %d lines total)\n", strings.Join(lines[:10], "\n  "), len(lines))
						} else {
							fmt.Fprintf(w, "  %s\n", dump)
						}
					}
				}
			} else {
				fmt.Fprintf(w, "%-20s -> \033[91mNONE\033[0m\n", resource)
			}
		}
	}

	// Cluster resources
	fmt.Fprintf(w, "\n=== CLUSTER RESOURCES ===\n")
	for resource, verbs := range results.Permissions.Cluster.Resources {
		if len(verbs) > 0 {
			flag := f.analyzeResource(resource, verbs, f.explain)
			fmt.Fprintf(w, "%-20s -> \033[92m%s\033[0m%s\n", resource, strings.Join(verbs, ","), flag)
		} else {
			fmt.Fprintf(w, "%-20s -> \033[91mNONE\033[0m\n", resource)
		}
	}
}

func (f *Formatter) analyzeResource(resource string, verbs []string, explain bool) string {
	var flags []string

	// Secret access
	if resource == "secrets" && contains(verbs, "get") {
		flags = append(flags, " <<!! ESCALATION: can read secrets !!>>")
		if explain {
			flags = append(flags, "\n    [EXPLAIN] Reading secrets can expose credentials, tokens, and keys for lateral movement")
		}
	}

	// Pod creation
	if resource == "pods" && contains(verbs, "create") {
		flags = append(flags, " <<!! ESCALATION: can create pods !!>>")
		if explain {
			flags = append(flags, "\n    [EXPLAIN] Pod creation with hostPath/privileged can lead to node compromise")
		}
	}

	// Cluster RBAC
	if (resource == "clusterroles" || resource == "clusterrolebindings") && contains(verbs, "create") {
		flags = append(flags, " <<!! ESCALATION: cluster-wide RBAC !!>>")
		if explain {
			flags = append(flags, "\n    [EXPLAIN] Creating cluster roles/bindings can grant cluster-admin privileges")
		}
	}

	// Role binding
	if resource == "rolebindings" && contains(verbs, "create") {
		flags = append(flags, " <<!! ESCALATION: can create rolebindings !!>>")
		if explain {
			flags = append(flags, "\n    [EXPLAIN] Creating role bindings can escalate privileges within namespace")
		}
	}

	// Wildcard detection
	if contains(verbs, "*") {
		flags = append(flags, " <<!! WILDCARD VERBS !!>>")
	}

	return strings.Join(flags, "")
}

func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

