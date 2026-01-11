package rbac

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	apiServer = "https://kubernetes.default.svc"
	caCert    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	nsFile    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var verbs = []string{"get", "list", "create", "update", "delete", "patch"}

// Namespace-scoped resources (comprehensive list)
var nsResources = []string{
	// Core resources
	"configmaps", "secrets", "pods", "services", "endpoints", "events",
	// Workloads
	"deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs",
	// Workload templates
	"podtemplates",
	// RBAC
	"roles", "rolebindings", "serviceaccounts",
	// Networking
	"ingresses", "networkpolicies",
	// Storage
	"persistentvolumeclaims",
	// Config
	"limitranges", "resourcequotas",
	// Autoscaling
	"horizontalpodautoscalers",
	// Availability
	"poddisruptionbudgets",
}

// Cluster-scoped resources
var clusterResources = []string{
	// Core
	"nodes", "namespaces", "persistentvolumes",
	// RBAC
	"clusterroles", "clusterrolebindings",
	// Storage
	"storageclasses", "volumeattachments",
	// Scheduling
	"priorityclasses", "runtimeclasses",
	// Extensions
	"customresourcedefinitions", "apiservices",
	// Webhooks (can be used for privilege escalation)
	"mutatingwebhookconfigurations", "validatingwebhookconfigurations",
	// Security
	"podsecuritypolicies", // Deprecated but still exists in older clusters
}

type Enumerator struct {
	client    *http.Client
	token     string
	namespace string
	claims    map[string]interface{}
	verbose   bool
	consecutiveFailures int // Track consecutive failures for early bailout
	maxConsecutiveFailures int
}

type Results struct {
	Namespace     string
	Claims        map[string]interface{}
	Permissions   Permissions
	Context       interface{} `json:"context,omitempty"`
	Services      interface{} `json:"services,omitempty"`
	Extracted     interface{} `json:"extracted,omitempty"`
	ClusterInfo   interface{} `json:"clusterinfo,omitempty"`
	PodSecurity   interface{} `json:"podsecurity,omitempty"`
	RBACAnalysis  interface{} `json:"rbacanalysis,omitempty"`
	TokenExtraction interface{} `json:"tokenextraction,omitempty"`
	EventAnalysis interface{} `json:"eventanalysis,omitempty"`
	NetworkPolicyAnalysis interface{} `json:"networkpolicyanalysis,omitempty"`
}

type Permissions struct {
	Namespaces map[string]NamespacePermissions
	Cluster    ClusterPermissions
}

type NamespacePermissions struct {
	Resources map[string][]string
	Dumps     map[string]string // Resource dumps when --dump is used
}

type ClusterPermissions struct {
	Resources map[string][]string
}

type ssarSpec struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Spec       struct {
		ResourceAttributes struct {
			Verb      string `json:"verb"`
			Resource  string `json:"resource"`
			Namespace string `json:"namespace,omitempty"`
		} `json:"resourceAttributes"`
	} `json:"spec"`
}

type ssarResponse struct {
	Status struct {
		Allowed bool `json:"allowed"`
	} `json:"status"`
}

type namespaceList struct {
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

func NewEnumerator(verbose bool) (*Enumerator, error) {
	token, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read token: %w", err)
	}

	namespace, _ := ioutil.ReadFile(nsFile)
	caCertData, err := ioutil.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caCertData)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool},
		ResponseHeaderTimeout: 10 * time.Second,
	}
	client := &http.Client{
		Transport: tr,
		Timeout: 10 * time.Second,
	}

	claims := decodeJWT(strings.TrimSpace(string(token)))

	return &Enumerator{
		client:    client,
		token:     strings.TrimSpace(string(token)),
		namespace: strings.TrimSpace(string(namespace)),
		claims:    claims,
		verbose:   verbose,
		consecutiveFailures: 0,
		maxConsecutiveFailures: 10, // Bail out after 10 consecutive failures
	}, nil
}

func (e *Enumerator) GetClient() *http.Client {
	return e.client
}

func (e *Enumerator) GetToken() string {
	return e.token
}

func (e *Enumerator) DumpClusterResource(resource string) string {
	url := fmt.Sprintf("%s/api/v1/%s", apiServer, resource)
	if resource == "clusterroles" || resource == "clusterrolebindings" {
		url = fmt.Sprintf("%s/apis/rbac.authorization.k8s.io/v1/%s", apiServer, resource)
	} else if resource == "customresourcedefinitions" {
		url = fmt.Sprintf("%s/apis/apiextensions.k8s.io/v1/%s", apiServer, resource)
	}
	
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return ""
	}
	
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func (e *Enumerator) Enumerate(dump bool, events bool) (*Results, error) {
	if e.verbose {
		fmt.Fprintf(os.Stderr, "[*] Starting enumeration...\n")
		fmt.Fprintf(os.Stderr, "[*] Checking %d namespace resources across all namespaces\n", len(nsResources))
		fmt.Fprintf(os.Stderr, "[*] Checking %d cluster resources\n", len(clusterResources))
	}

	namespaces := e.getNamespaces()
	if e.verbose {
		fmt.Fprintf(os.Stderr, "[*] Discovered %d namespace(s): %s\n", len(namespaces), strings.Join(namespaces, ", "))
	}
	
	// Check if we already hit the failure threshold from getNamespaces
	if e.consecutiveFailures >= e.maxConsecutiveFailures {
		return nil, fmt.Errorf("API server appears unresponsive (%d consecutive failures). Check cluster health", e.maxConsecutiveFailures)
	}

	results := &Results{
		Namespace: e.namespace,
		Claims:    e.claims,
		Permissions: Permissions{
			Namespaces: make(map[string]NamespacePermissions),
			Cluster: ClusterPermissions{
				Resources: make(map[string][]string),
			},
		},
	}

	// Enumerate namespace resources
	if e.verbose {
		fmt.Fprintf(os.Stderr, "\n[*] Enumerating namespace resources...\n")
	}
	for _, ns := range namespaces {
		if e.verbose {
			fmt.Fprintf(os.Stderr, "[*] Checking namespace: %s\n", ns)
		}
		nsPerms := NamespacePermissions{
			Resources: make(map[string][]string),
			Dumps:     make(map[string]string),
		}

		for _, r := range nsResources {
			// Check for early bailout
			if e.consecutiveFailures >= e.maxConsecutiveFailures {
				if e.verbose {
					fmt.Fprintf(os.Stderr, "\n[!] ERROR: Too many consecutive API failures (%d)\n", e.consecutiveFailures)
					fmt.Fprintf(os.Stderr, "[!] API server appears unresponsive. Aborting enumeration.\n")
					fmt.Fprintf(os.Stderr, "[!] Check cluster health: 'kubectl get nodes' and 'systemctl status k3s'\n")
				}
				return nil, fmt.Errorf("API server unresponsive: %d consecutive failures detected", e.consecutiveFailures)
			}
			
			if e.verbose {
				fmt.Fprintf(os.Stderr, "  [*] Checking resource: %s\n", r)
			}
			allowed := []string{}
			for _, v := range verbs {
				if e.checkAccess(r, v, ns) {
					allowed = append(allowed, v)
					if e.verbose {
						fmt.Fprintf(os.Stderr, "    [+] %s/%s: ALLOWED\n", r, v)
					}
				}
			}
			if e.verbose && len(allowed) == 0 {
				fmt.Fprintf(os.Stderr, "    [-] No permissions\n")
			} else if e.verbose && len(allowed) > 0 && len(allowed) < len(verbs) {
				denied := []string{}
				for _, v := range verbs {
					if !contains(allowed, v) {
						denied = append(denied, v)
					}
				}
				if len(denied) > 0 {
					fmt.Fprintf(os.Stderr, "    [-] Denied: %s\n", strings.Join(denied, ", "))
				}
			}
			if len(allowed) > 0 {
				nsPerms.Resources[r] = allowed

				// Dump resources if requested and readable
				shouldDump := false
				if dump && contains([]string{"secrets", "configmaps", "pods", "services", "serviceaccounts"}, r) {
					shouldDump = true
				}
				if events && r == "events" {
					shouldDump = true
				}
				if shouldDump {
					if contains(allowed, "get") || contains(allowed, "list") {
						if e.verbose {
							fmt.Fprintf(os.Stderr, "    [*] Dumping %s...\n", r)
						}
						dumpData := e.dumpResource(ns, r)
						if dumpData != "" {
							nsPerms.Dumps[r] = dumpData
							if e.verbose && r == "events" {
								// Debug: check if events dump has content
								if len(dumpData) > 100 {
									fmt.Fprintf(os.Stderr, "      [+] Events dump: %d bytes\n", len(dumpData))
								} else {
									fmt.Fprintf(os.Stderr, "      [-] Events dump: empty or small (%d bytes)\n", len(dumpData))
								}
							}
						} else if e.verbose && r == "events" {
							fmt.Fprintf(os.Stderr, "      [-] Events dump failed (empty response)\n")
						}
					}
				}
			}
		}

		results.Permissions.Namespaces[ns] = nsPerms
	}

	// Enumerate cluster resources
	if e.verbose {
		fmt.Fprintf(os.Stderr, "\n[*] Enumerating cluster resources...\n")
	}
		for _, r := range clusterResources {
			// Check for early bailout
			if e.consecutiveFailures >= e.maxConsecutiveFailures {
				if e.verbose {
					fmt.Fprintf(os.Stderr, "\n[!] ERROR: Too many consecutive API failures (%d)\n", e.consecutiveFailures)
					fmt.Fprintf(os.Stderr, "[!] API server appears unresponsive. Aborting enumeration.\n")
					fmt.Fprintf(os.Stderr, "[!] Check cluster health: 'kubectl get nodes' and 'systemctl status k3s'\n")
				}
				return nil, fmt.Errorf("API server unresponsive: %d consecutive failures detected", e.consecutiveFailures)
			}
			
			if e.verbose {
				fmt.Fprintf(os.Stderr, "  [*] Checking resource: %s\n", r)
			}
			allowed := []string{}
			for _, v := range verbs {
				if e.checkAccess(r, v, "") {
					allowed = append(allowed, v)
					if e.verbose {
						fmt.Fprintf(os.Stderr, "    [+] %s/%s: ALLOWED\n", r, v)
					}
				}
			}
			if e.verbose && len(allowed) == 0 {
				fmt.Fprintf(os.Stderr, "    [-] No permissions\n")
			} else if e.verbose && len(allowed) > 0 && len(allowed) < len(verbs) {
				denied := []string{}
				for _, v := range verbs {
					if !contains(allowed, v) {
						denied = append(denied, v)
					}
				}
				if len(denied) > 0 {
					fmt.Fprintf(os.Stderr, "    [-] Denied: %s\n", strings.Join(denied, ", "))
				}
			}
		if len(allowed) > 0 {
			results.Permissions.Cluster.Resources[r] = allowed
		}
	}

	if e.verbose {
		fmt.Fprintf(os.Stderr, "\n[*] Enumeration complete\n\n")
	}

	return results, nil
}

// doHTTPRequestWithRetry performs an HTTP request with exponential backoff retry
func (e *Enumerator) doHTTPRequestWithRetry(method, url string, body []byte, headers map[string]string, maxRetries int) (*http.Response, error) {
	var lastErr error
	baseDelay := 100 * time.Millisecond
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
			delay := baseDelay * time.Duration(1<<uint(attempt-1))
			if delay > 2*time.Second {
				delay = 2 * time.Second
			}
			time.Sleep(delay)
		}
		
		// Create a new request for each retry attempt
		var reqBody io.Reader
		if len(body) > 0 {
			reqBody = bytes.NewBuffer(body)
		}
		req, err := http.NewRequest(method, url, reqBody)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Set headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		
		resp, err := e.client.Do(req)
		if err == nil && resp.StatusCode < 500 {
			e.consecutiveFailures = 0 // Reset on success
			return resp, nil
		}
		
		if err != nil {
			lastErr = err
		} else {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		
		e.consecutiveFailures++
		
		// Check if we should bail out early
		if e.consecutiveFailures >= e.maxConsecutiveFailures {
			return nil, fmt.Errorf("too many consecutive failures (%d): API server appears unresponsive: %w", e.consecutiveFailures, lastErr)
		}
	}
	
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries, lastErr)
}

func (e *Enumerator) checkAccess(resource, verb, namespace string) bool {
	// Check if we've hit the failure threshold
	if e.consecutiveFailures >= e.maxConsecutiveFailures {
		return false
	}
	
	payload := ssarSpec{
		Kind:       "SelfSubjectAccessReview",
		APIVersion: "authorization.k8s.io/v1",
	}
	payload.Spec.ResourceAttributes.Verb = verb
	payload.Spec.ResourceAttributes.Resource = resource
	if namespace != "" {
		payload.Spec.ResourceAttributes.Namespace = namespace
	}

	data, _ := json.Marshal(payload)
	headers := map[string]string{
		"Authorization": "Bearer " + e.token,
		"Content-Type":  "application/json",
	}
	
	resp, err := e.doHTTPRequestWithRetry("POST", apiServer+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", data, headers, 3)
	if err != nil {
		if e.verbose && e.consecutiveFailures >= e.maxConsecutiveFailures {
			fmt.Fprintf(os.Stderr, "[!] ERROR: %v\n", err)
			fmt.Fprintf(os.Stderr, "[!] Bailing out due to API server issues\n")
		}
		return false
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return false
	}
	
	body, _ := ioutil.ReadAll(resp.Body)

	var out ssarResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return false
	}
	return out.Status.Allowed
}

func (e *Enumerator) getNamespaces() []string {
	if !e.checkAccess("namespaces", "list", "") {
		return []string{e.namespace}
	}

	headers := map[string]string{
		"Authorization": "Bearer " + e.token,
	}
	resp, err := e.doHTTPRequestWithRetry("GET", apiServer+"/api/v1/namespaces", nil, headers, 3)
	if err != nil {
		return []string{e.namespace}
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	var nsList namespaceList
	if err := json.Unmarshal(body, &nsList); err != nil {
		return []string{e.namespace}
	}

	namespaces := []string{}
	for _, item := range nsList.Items {
		namespaces = append(namespaces, item.Metadata.Name)
	}
	return namespaces
}

func (e *Enumerator) dumpResource(ns, resource string) string {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/%s", apiServer, ns, resource)
	// Handle different API groups
	if contains([]string{"deployments", "daemonsets", "statefulsets", "replicasets"}, resource) {
		url = fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "jobs" {
		url = fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "cronjobs" {
		url = fmt.Sprintf("%s/apis/batch/v1/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "horizontalpodautoscalers" {
		url = fmt.Sprintf("%s/apis/autoscaling/v2/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "ingresses" {
		url = fmt.Sprintf("%s/apis/networking.k8s.io/v1/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "networkpolicies" {
		url = fmt.Sprintf("%s/apis/networking.k8s.io/v1/namespaces/%s/%s", apiServer, ns, resource)
	} else if resource == "poddisruptionbudgets" {
		url = fmt.Sprintf("%s/apis/policy/v1/namespaces/%s/%s", apiServer, ns, resource)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return ""
	}
	
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func contains(slice []string, val string) bool {
	for _, v := range slice {
		if v == val {
			return true
		}
	}
	return false
}

// Decode JWT payload (2nd part of token)
func decodeJWT(token string) map[string]interface{} {
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

