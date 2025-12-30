package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/babywyrm/kubefall/internal/analysis"
	"github.com/babywyrm/kubefall/internal/discovery"
	"github.com/babywyrm/kubefall/internal/rbac"
)

func (f *Formatter) printClusterInfo(w io.Writer, results *rbac.Results) {
	if results.ClusterInfo == nil {
		return
	}

	if info, ok := results.ClusterInfo.(*discovery.ClusterInfo); ok {
		fmt.Fprintf(w, "%s[CLUSTER]%s Version: %s%s%s (%s.%s)\n", 
			colorBlue, colorReset, colorBold, info.Version, colorReset, info.Major, info.Minor)
		fmt.Fprintf(w, "\n")
	}
}

func (f *Formatter) printRBACAnalysis(w io.Writer, results *rbac.Results) {
	if results.RBACAnalysis == nil {
		return
	}

	if rbacAnalysis, ok := results.RBACAnalysis.(*analysis.RBACAnalysis); ok {
		hasFindings := false

		if len(rbacAnalysis.ClusterAdminBindings) > 0 {
			hasFindings = true
			fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", colorRed, colorReset)
			fmt.Fprintf(w, "%s║%s  %s🔴 CLUSTER-ADMIN BINDINGS FOUND 🔴%s                              %s║%s\n", colorRed, colorReset, colorBold, colorReset, colorRed, colorReset)
			fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorRed, colorReset)

			for _, binding := range rbacAnalysis.ClusterAdminBindings {
				fmt.Fprintf(w, "  %sBinding:%s %s%s%s\n", colorBold, colorReset, colorRed, binding.Name, colorReset)
				fmt.Fprintf(w, "  %sRole:%s    %s%s%s\n", colorBold, colorReset, colorYellow, binding.Role, colorReset)
				fmt.Fprintf(w, "  %sSubjects:%s\n", colorBold, colorReset)
				for _, subject := range binding.Subjects {
					nsDisplay := ""
					if subject.Namespace != "" {
						nsDisplay = fmt.Sprintf(" (ns: %s)", subject.Namespace)
					}
					fmt.Fprintf(w, "    • %s%s%s: %s%s%s%s\n", 
						colorBold, subject.Kind, colorReset, 
						colorYellow, subject.Name, colorReset, nsDisplay)
				}
				fmt.Fprintf(w, "\n")
			}
		}

		if len(rbacAnalysis.WildcardClusterRoles) > 0 {
			hasFindings = true
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorYellow, colorReset)
			fmt.Fprintf(w, "%s⚠️  WILDCARD CLUSTER ROLES%s\n", colorBold, colorReset)
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorYellow, colorReset)

			for _, role := range rbacAnalysis.WildcardClusterRoles {
				fmt.Fprintf(w, "  %s%s%s\n", colorBold, role.Name, colorReset)
			}
			fmt.Fprintf(w, "\n")
		}

		if !hasFindings {
			return
		}
	}
}

func (f *Formatter) printTokenExtraction(w io.Writer, results *rbac.Results) {
	if results.TokenExtraction == nil {
		return
	}

	if tokenExt, ok := results.TokenExtraction.(*analysis.TokenExtraction); ok {
		hasFindings := false

		if len(tokenExt.ServiceAccountTokens) > 0 {
			hasFindings = true
			fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", colorRed, colorReset)
			fmt.Fprintf(w, "%s║%s  %s🔑 SERVICE ACCOUNT TOKENS FOUND 🔑%s                              %s║%s\n", colorRed, colorReset, colorBold, colorReset, colorRed, colorReset)
			fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorRed, colorReset)

			for _, token := range tokenExt.ServiceAccountTokens {
				fmt.Fprintf(w, "  %sNamespace:%s %s%s%s\n", colorBold, colorReset, colorYellow, token.Namespace, colorReset)
				fmt.Fprintf(w, "  %sServiceAccount:%s %s%s%s\n", colorBold, colorReset, colorRed, token.ServiceAccount, colorReset)
				fmt.Fprintf(w, "  %sSecret:%s %s%s%s\n", colorBold, colorReset, colorYellow, token.SecretName, colorReset)
				
				if token.Valid && token.Claims != nil {
					if sub, ok := token.Claims["sub"].(string); ok {
						fmt.Fprintf(w, "  %sSubject:%s %s%s%s\n", colorBold, colorReset, colorGreen, sub, colorReset)
					}
					if exp, ok := token.Claims["exp"].(float64); ok {
						fmt.Fprintf(w, "  %sExpires:%s %s%v%s\n", colorBold, colorReset, colorYellow, int64(exp), colorReset)
					}
				}
				tokenPreview := token.Token
				if len(tokenPreview) > 20 {
					tokenPreview = tokenPreview[:20]
				}
				fmt.Fprintf(w, "  %sToken:%s %s%s...%s (first 20 chars)\n\n", 
					colorBold, colorReset, colorYellow, tokenPreview, colorReset)
			}
		}

		if len(tokenExt.HighPrivilegeSAs) > 0 {
			hasFindings = true
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorYellow, colorReset)
			fmt.Fprintf(w, "%s⚠️  HIGH-PRIVILEGE SERVICE ACCOUNTS%s\n", colorBold, colorReset)
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorYellow, colorReset)

			for _, sa := range tokenExt.HighPrivilegeSAs {
				tokenInfo := ""
				if len(sa.Tokens) > 0 {
					tokenInfo = fmt.Sprintf(" (has %d token secret(s))", len(sa.Tokens))
				}
				fmt.Fprintf(w, "  • %s%s%s/%s%s%s%s\n", 
					colorBold, sa.Namespace, colorReset,
					colorYellow, sa.Name, colorReset, tokenInfo)
			}
			fmt.Fprintf(w, "\n")
		}

		if len(tokenExt.AllServiceAccounts) > 0 && len(tokenExt.ServiceAccountTokens) == 0 && len(tokenExt.HighPrivilegeSAs) == 0 {
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n", colorBlue, colorReset)
			fmt.Fprintf(w, "%s📋 SERVICE ACCOUNTS DISCOVERED%s\n", colorBold, colorReset)
			fmt.Fprintf(w, "%s═══════════════════════════════════════════════════════════%s\n\n", colorBlue, colorReset)
			
			nsMap := make(map[string][]string)
			for _, sa := range tokenExt.AllServiceAccounts {
				nsMap[sa.Namespace] = append(nsMap[sa.Namespace], sa.Name)
			}
			for ns, sas := range nsMap {
				fmt.Fprintf(w, "  %s[%s]%s %s%s%s\n", colorYellow, ns, colorReset, colorBold, strings.Join(sas, ", "), colorReset)
			}
			fmt.Fprintf(w, "\n")
		}

		if !hasFindings && len(tokenExt.AllServiceAccounts) == 0 {
			return
		}
	}
}

func (f *Formatter) printPodSecurity(w io.Writer, results *rbac.Results) {
	if results.PodSecurity == nil {
		return
	}

	if podSecMap, ok := results.PodSecurity.(map[string]interface{}); ok {
		hasFindings := false
		fmt.Fprintf(w, "%s╔════════════════════════════════════════════════════════════╗%s\n", colorRed, colorReset)
		fmt.Fprintf(w, "%s║%s  %s🔒 POD SECURITY ANALYSIS%s                                  %s║%s\n", colorRed, colorReset, colorBold, colorReset, colorRed, colorReset)
		fmt.Fprintf(w, "%s╚════════════════════════════════════════════════════════════╝%s\n\n", colorRed, colorReset)

		for ns, data := range podSecMap {
			if analysis, ok := data.(*analysis.PodSecurityAnalysis); ok {
				nsFindings := false

				if len(analysis.PrivilegedPods) > 0 {
					hasFindings = true
					nsFindings = true
					fmt.Fprintf(w, "  %s[%s] %s🚨 PRIVILEGED PODS:%s\n", colorRed, ns, colorBold, colorReset)
					for _, pod := range analysis.PrivilegedPods {
						fmt.Fprintf(w, "    • %s%s%s (SA: %s%s%s)\n", 
							colorBold, pod.Name, colorReset,
							colorYellow, pod.SA, colorReset)
					}
					fmt.Fprintf(w, "\n")
				}

				if len(analysis.HostNetworkPods) > 0 {
					hasFindings = true
					nsFindings = true
					fmt.Fprintf(w, "  %s[%s] %s🌐 HOST NETWORK PODS:%s\n", colorYellow, ns, colorBold, colorReset)
					for _, pod := range analysis.HostNetworkPods {
						fmt.Fprintf(w, "    • %s%s%s\n", colorBold, pod.Name, colorReset)
					}
					fmt.Fprintf(w, "\n")
				}

				if len(analysis.HostPathMounts) > 0 {
					hasFindings = true
					nsFindings = true
					fmt.Fprintf(w, "  %s[%s] %s📁 DANGEROUS HOST PATH MOUNTS:%s\n", colorYellow, ns, colorBold, colorReset)
					for _, mount := range analysis.HostPathMounts {
						fmt.Fprintf(w, "    • %s%s%s -> %s%s%s", 
							colorBold, mount.Name, colorReset,
							colorRed, mount.Path, colorReset)
						if mount.ReadOnly {
							fmt.Fprintf(w, " (read-only)")
						}
						fmt.Fprintf(w, "\n")
					}
					fmt.Fprintf(w, "\n")
				}

				if len(analysis.DangerousCaps) > 0 {
					hasFindings = true
					nsFindings = true
					fmt.Fprintf(w, "  %s[%s] %s⚡ DANGEROUS CAPABILITIES:%s\n", colorYellow, ns, colorBold, colorReset)
					for _, cap := range analysis.DangerousCaps {
						fmt.Fprintf(w, "    • %s%s%s: %s%s%s\n", 
							colorBold, cap.Name, colorReset,
							colorYellow, cap.Capability, colorReset)
					}
					fmt.Fprintf(w, "\n")
				}

				if !nsFindings {
					fmt.Fprintf(w, "  %s[%s]%s No dangerous pod configurations detected\n\n", colorGreen, ns, colorReset)
				}
			}
		}

		if !hasFindings {
			return
		}
	}
}

