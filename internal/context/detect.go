package context

import (
	"io/ioutil"
	"os"
	"strings"
)

// Context represents the detected Kubernetes environment
type Context struct {
	Type        string            // k3s, eks, gke, aks, vanilla
	Distribution string           // k3s, k8s, etc.
	Cloud       string            // aws, gcp, azure, none
	Metadata    map[string]string // Additional metadata
}

// Detect attempts to identify the Kubernetes environment
func Detect() (*Context, error) {
	ctx := &Context{
		Type:     "unknown",
		Metadata: make(map[string]string),
	}

	// Check for k3s
	if isK3s() {
		ctx.Type = "k3s"
		ctx.Distribution = "k3s"
		return ctx, nil
	}

	// Check for EKS
	if isEKS() {
		ctx.Type = "eks"
		ctx.Distribution = "k8s"
		ctx.Cloud = "aws"
		return ctx, nil
	}

	// Check for GKE
	if isGKE() {
		ctx.Type = "gke"
		ctx.Distribution = "k8s"
		ctx.Cloud = "gcp"
		return ctx, nil
	}

	// Check for AKS
	if isAKS() {
		ctx.Type = "aks"
		ctx.Distribution = "k8s"
		ctx.Cloud = "azure"
		return ctx, nil
	}

	// Default to vanilla k8s
	ctx.Type = "vanilla"
	ctx.Distribution = "k8s"
	return ctx, nil
}

func isK3s() bool {
	// Check for k3s-specific files
	paths := []string{
		"/etc/rancher/k3s/k3s.yaml",
		"/var/lib/rancher/k3s",
		"/usr/local/bin/k3s",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check for k3s in node labels (if we can read them)
	// This would require API access, so we'll skip for now

	return false
}

func isEKS() bool {
	// Check for EKS-specific environment variables
	if region := os.Getenv("AWS_REGION"); region != "" {
		// Check if IMDS is accessible (EKS nodes have IMDS)
		// We can't make HTTP calls here without more context, so we'll check JWT issuer
		// This will be enhanced when we have token access
		return true
	}

	// Check for EKS node labels (would require API access)
	return false
}

func isGKE() bool {
	// Check for GKE-specific environment variables
	if project := os.Getenv("GKE_PROJECT"); project != "" {
		return true
	}

	// Check for GKE metadata server
	if _, err := os.Stat("/var/run/secrets/kubernetes.io/serviceaccount/gke-metadata-server"); err == nil {
		return true
	}

	return false
}

func isAKS() bool {
	// Check for AKS-specific environment variables
	if tenantID := os.Getenv("AZURE_TENANT_ID"); tenantID != "" {
		return true
	}

	// Check for AKS federated token file
	if _, err := os.Stat("/var/run/secrets/azure/tokens/azure-identity-token"); err == nil {
		return true
	}

	return false
}

// DetectFromToken analyzes JWT token claims to identify environment
func DetectFromToken(claims map[string]interface{}) (*Context, error) {
	ctx, err := Detect()
	if err != nil {
		ctx = &Context{Metadata: make(map[string]string)}
	}

	// Check audience for k3s (k3s includes "k3s" in token audience)
	if aud, ok := claims["aud"]; ok {
		switch v := aud.(type) {
		case []interface{}:
			for _, a := range v {
				if str, ok := a.(string); ok && str == "k3s" {
					ctx.Type = "k3s"
					ctx.Distribution = "k3s"
					ctx.Metadata["detected_via"] = "token_audience"
				}
			}
		case string:
			if v == "k3s" {
				ctx.Type = "k3s"
				ctx.Distribution = "k3s"
				ctx.Metadata["detected_via"] = "token_audience"
			}
		}
	}

	// Extract issuer from claims
	if iss, ok := claims["iss"].(string); ok {
		ctx.Metadata["issuer"] = iss

		// Only override if we haven't detected k3s yet
		if ctx.Type != "k3s" {
			// EKS uses OIDC issuer pattern
			if strings.Contains(iss, "oidc.eks") || strings.Contains(iss, "eks.amazonaws.com") {
				ctx.Type = "eks"
				ctx.Cloud = "aws"
				ctx.Distribution = "k8s"
			}

			// GKE uses GCP OIDC
			if strings.Contains(iss, "gke") || strings.Contains(iss, "googleapis.com") {
				ctx.Type = "gke"
				ctx.Cloud = "gcp"
				ctx.Distribution = "k8s"
			}

			// AKS uses Azure AD
			if strings.Contains(iss, "azure") || strings.Contains(iss, "microsoftonline.com") {
				ctx.Type = "aks"
				ctx.Cloud = "azure"
				ctx.Distribution = "k8s"
			}
		}
	}

	// Extract service account name
	if sub, ok := claims["sub"].(string); ok {
		ctx.Metadata["serviceaccount"] = sub
	}

	return ctx, nil
}

// CheckInCluster determines if we're running in-cluster
func CheckInCluster() bool {
	// Standard in-cluster indicators
	indicators := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/namespace",
		"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
	}

	for _, indicator := range indicators {
		if _, err := os.Stat(indicator); err != nil {
			return false
		}
	}

	return true
}

// CheckHost determines if we're on a host (not in container)
func CheckHost() bool {
	// Check for container indicators
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return false
	}

	// Check cgroup
	if data, err := ioutil.ReadFile("/proc/self/cgroup"); err == nil {
		if strings.Contains(string(data), "docker") || strings.Contains(string(data), "containerd") {
			return false
		}
	}

	return true
}

