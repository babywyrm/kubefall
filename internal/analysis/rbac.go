package analysis

import (
	"encoding/json"
	"strings"
)

type RBACAnalysis struct {
	ClusterAdminBindings []ClusterAdminBinding
	WildcardRoles        []RoleInfo
	WildcardClusterRoles []RoleInfo
	SecretAccessRoles    []RoleInfo
	PodCreateRoles       []RoleInfo
}

type ClusterAdminBinding struct {
	Name       string
	Role       string
	Subjects   []Subject
}

type Subject struct {
	Kind      string
	Name      string
	Namespace string
}

type RoleInfo struct {
	Name      string
	Namespace string
	Rules     []Rule
}

type Rule struct {
	Verbs     []string
	Resources []string
	APIGroups []string
}

func AnalyzeClusterRoleBindings(bindingsData string) *RBACAnalysis {
	analysis := &RBACAnalysis{
		ClusterAdminBindings: []ClusterAdminBinding{},
		WildcardClusterRoles: []RoleInfo{},
		SecretAccessRoles:    []RoleInfo{},
		PodCreateRoles:       []RoleInfo{},
	}

	var bindingList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			RoleRef struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"roleRef"`
			Subjects []struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"subjects"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(bindingsData), &bindingList); err != nil {
		return analysis
	}

	for _, binding := range bindingList.Items {
		if binding.RoleRef.Name == "cluster-admin" || strings.Contains(strings.ToLower(binding.RoleRef.Name), "admin") {
			subjects := []Subject{}
			for _, subj := range binding.Subjects {
				subjects = append(subjects, Subject{
					Kind:      subj.Kind,
					Name:      subj.Name,
					Namespace: subj.Namespace,
				})
			}
			analysis.ClusterAdminBindings = append(analysis.ClusterAdminBindings, ClusterAdminBinding{
				Name:     binding.Metadata.Name,
				Role:     binding.RoleRef.Name,
				Subjects: subjects,
			})
		}
	}

	return analysis
}

func AnalyzeClusterRoles(rolesData string) *RBACAnalysis {
	analysis := &RBACAnalysis{
		WildcardClusterRoles: []RoleInfo{},
		SecretAccessRoles:    []RoleInfo{},
		PodCreateRoles:       []RoleInfo{},
	}

	var roleList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Rules []struct {
				Verbs     []string `json:"verbs"`
				Resources []string `json:"resources"`
				APIGroups []string `json:"apiGroups"`
			} `json:"rules"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(rolesData), &roleList); err != nil {
		return analysis
	}

	for _, role := range roleList.Items {
		roleInfo := RoleInfo{
			Name:  role.Metadata.Name,
			Rules: []Rule{},
		}

		hasWildcard := false
		hasSecretAccess := false
		hasPodCreate := false

		for _, rule := range role.Rules {
			r := Rule{
				Verbs:     rule.Verbs,
				Resources: rule.Resources,
				APIGroups: rule.APIGroups,
			}
			roleInfo.Rules = append(roleInfo.Rules, r)

			for _, verb := range rule.Verbs {
				if verb == "*" {
					hasWildcard = true
				}
			}

			for _, resource := range rule.Resources {
				if resource == "*" {
					hasWildcard = true
				}
				if resource == "secrets" || strings.HasSuffix(resource, "/secrets") {
					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "list" || verb == "*" {
							hasSecretAccess = true
						}
					}
				}
				if resource == "pods" || strings.HasSuffix(resource, "/pods") {
					for _, verb := range rule.Verbs {
						if verb == "create" || verb == "*" {
							hasPodCreate = true
						}
					}
				}
			}
		}

		if hasWildcard {
			analysis.WildcardClusterRoles = append(analysis.WildcardClusterRoles, roleInfo)
		}
		if hasSecretAccess {
			analysis.SecretAccessRoles = append(analysis.SecretAccessRoles, roleInfo)
		}
		if hasPodCreate {
			analysis.PodCreateRoles = append(analysis.PodCreateRoles, roleInfo)
		}
	}

	return analysis
}

