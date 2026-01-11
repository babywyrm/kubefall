package analysis

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

type TokenExtraction struct {
	ServiceAccountTokens []ServiceAccountToken
	HighPrivilegeSAs     []ServiceAccountInfo
	AllServiceAccounts   []ServiceAccountInfo
}

type ServiceAccountToken struct {
	Namespace     string
	ServiceAccount string
	SecretName    string
	Token         string
	Valid         bool
	Claims        map[string]interface{}
}

type ServiceAccountInfo struct {
	Namespace string
	Name      string
	Tokens    []string // Token secrets associated with this SA
}

// ExtractSATokensFromSecrets parses secrets and extracts ServiceAccount tokens
func ExtractSATokensFromSecrets(secretsData string) []ServiceAccountToken {
	tokens := []ServiceAccountToken{}

	var secretList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Type string `json:"type"`
			Data struct {
				Token string `json:"token"`
			} `json:"data"`
			Annotations struct {
				KubernetesIOServiceAccount string `json:"kubernetes.io/service-account.name"`
			} `json:"annotations"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(secretsData), &secretList); err != nil {
		return tokens
	}

	for _, secret := range secretList.Items {
		// Look for ServiceAccount token secrets
		if secret.Type == "kubernetes.io/service-account-token" {
			if secret.Data.Token != "" {
				// Decode base64 token
				decoded, err := base64.StdEncoding.DecodeString(secret.Data.Token)
				if err != nil {
					continue
				}

				token := string(decoded)
				claims := decodeJWTClaims(token)

				saName := secret.Annotations.KubernetesIOServiceAccount
				if saName == "" {
					// Try to extract from token claims
					if sub, ok := claims["sub"].(string); ok {
						// sub format: system:serviceaccount:namespace:name
						parts := strings.Split(sub, ":")
						if len(parts) >= 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
							saName = parts[3]
						}
					}
				}

				tokens = append(tokens, ServiceAccountToken{
					Namespace:      secret.Metadata.Namespace,
					ServiceAccount: saName,
					SecretName:     secret.Metadata.Name,
					Token:          token,
					Valid:          claims != nil,
					Claims:         claims,
				})
			}
		}
	}

	return tokens
}

// ExtractServiceAccountsFromPods extracts ServiceAccount names from pods
func ExtractServiceAccountsFromPods(podsData string) []ServiceAccountInfo {
	saMap := make(map[string]*ServiceAccountInfo)

	var podList struct {
		Items []struct {
			Metadata struct {
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				ServiceAccountName string `json:"serviceAccountName"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(podsData), &podList); err != nil {
		return []ServiceAccountInfo{}
	}

	for _, pod := range podList.Items {
		saName := pod.Spec.ServiceAccountName
		if saName == "" {
			saName = "default"
		}

		key := pod.Metadata.Namespace + ":" + saName
		if _, exists := saMap[key]; !exists {
			saMap[key] = &ServiceAccountInfo{
				Namespace: pod.Metadata.Namespace,
				Name:      saName,
				Tokens:    []string{},
			}
		}
	}

	result := []ServiceAccountInfo{}
	for _, sa := range saMap {
		result = append(result, *sa)
	}

	return result
}

// ExtractServiceAccountsFromSAList extracts ServiceAccounts from ServiceAccount list
func ExtractServiceAccountsFromSAList(saData string) []ServiceAccountInfo {
	sas := []ServiceAccountInfo{}

	var saList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Secrets []struct {
				Name string `json:"name"`
			} `json:"secrets"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(saData), &saList); err != nil {
		return sas
	}

	for _, item := range saList.Items {
		tokenSecrets := []string{}
		for _, secret := range item.Secrets {
			tokenSecrets = append(tokenSecrets, secret.Name)
		}

		sas = append(sas, ServiceAccountInfo{
			Namespace: item.Metadata.Namespace,
			Name:      item.Metadata.Name,
			Tokens:    tokenSecrets,
		})
	}

	return sas
}

// decodeJWTClaims decodes JWT token and returns claims
func decodeJWTClaims(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	return claims
}

// IsHighPrivilegeSA checks if a ServiceAccount name suggests high privilege
func IsHighPrivilegeSA(saName string) bool {
	highPrivilegePatterns := []string{
		"admin",
		"cluster-admin",
		"system:",
		"service-account",
		"controller",
		"operator",
		"kube-",
	}

	lowerName := strings.ToLower(saName)
	for _, pattern := range highPrivilegePatterns {
		if strings.Contains(lowerName, strings.ToLower(pattern)) {
			return true
		}
	}

	return false
}


