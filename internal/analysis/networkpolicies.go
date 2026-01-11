package analysis

import (
	"encoding/json"
	"strings"
)

type NetworkPolicyAnalysis struct {
	NamespacesWithoutPolicies []string
	NetworkPoliciesFound      []NetworkPolicyInfo
	DenyAllPolicies           []NetworkPolicyInfo // Policies with empty rules (deny all)
}

type NetworkPolicyInfo struct {
	Name      string
	Namespace string
	PolicyTypes []string
}

func AnalyzeNetworkPolicies(allNamespaceDumps map[string]string, allNamespaces []string) *NetworkPolicyAnalysis {
	analysis := &NetworkPolicyAnalysis{
		NamespacesWithoutPolicies: []string{},
		NetworkPoliciesFound:      []NetworkPolicyInfo{},
		DenyAllPolicies:           []NetworkPolicyInfo{},
	}

	// Track namespaces that have at least one NetworkPolicy
	namespacesWithPolicies := make(map[string]bool)

	// Analyze NetworkPolicies from each namespace
	for ns, dumpData := range allNamespaceDumps {
		if dumpData == "" {
			continue
		}

		var npList struct {
			Items []struct {
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
				Spec struct {
					PodSelector struct {
						MatchLabels map[string]string `json:"matchLabels"`
					} `json:"podSelector"`
					PolicyTypes []string `json:"policyTypes"`
					Ingress     []struct {
						From []interface{} `json:"from"`
						Ports []interface{} `json:"ports"`
					} `json:"ingress"`
					Egress []struct {
						To    []interface{} `json:"to"`
						Ports []interface{} `json:"ports"`
					} `json:"egress"`
				} `json:"spec"`
			} `json:"items"`
		}

		if err := json.Unmarshal([]byte(dumpData), &npList); err != nil {
			continue
		}

		if len(npList.Items) > 0 {
			namespacesWithPolicies[ns] = true
		}

		for _, np := range npList.Items {
			npInfo := NetworkPolicyInfo{
				Name:       np.Metadata.Name,
				Namespace:  np.Metadata.Namespace,
				PolicyTypes: np.Spec.PolicyTypes,
			}

			// Track all NetworkPolicies found
			analysis.NetworkPoliciesFound = append(analysis.NetworkPoliciesFound, npInfo)

			// Check if policy types include ingress/egress
			hasIngress := false
			hasEgress := false
			for _, pt := range np.Spec.PolicyTypes {
				if strings.ToLower(pt) == "ingress" {
					hasIngress = true
				}
				if strings.ToLower(pt) == "egress" {
					hasEgress = true
				}
			}

			// Check for deny-all policies (empty rules = deny all in Kubernetes NetworkPolicy model)
			// In Kubernetes, empty ingress/egress rules mean "deny all" for that direction
			if (hasIngress && len(np.Spec.Ingress) == 0) || (hasEgress && len(np.Spec.Egress) == 0) {
				analysis.DenyAllPolicies = append(analysis.DenyAllPolicies, npInfo)
			}
		}
	}

	// Find namespaces without NetworkPolicies
	for _, ns := range allNamespaces {
		if !namespacesWithPolicies[ns] {
			// Skip system namespaces that typically don't need NetworkPolicies
			if ns != "kube-system" && ns != "kube-public" && ns != "kube-node-lease" {
				analysis.NamespacesWithoutPolicies = append(analysis.NamespacesWithoutPolicies, ns)
			}
		}
	}

	return analysis
}

