package rbac

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	apiServer = "https://kubernetes.default.svc"
	caCert    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	tokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	nsFile    = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var verbs = []string{"get", "list", "create", "update", "delete", "patch"}
var nsResources = []string{"configmaps", "secrets", "pods", "services", "deployments", "daemonsets", "statefulsets", "roles", "rolebindings"}
var clusterResources = []string{"nodes", "namespaces", "clusterroles", "clusterrolebindings"}

type Enumerator struct {
	client    *http.Client
	token     string
	namespace string
	claims    map[string]interface{}
}

type Results struct {
	Namespace   string
	Claims      map[string]interface{}
	Permissions Permissions
	Context     interface{} `json:"context,omitempty"` // Context from context package
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

func NewEnumerator() (*Enumerator, error) {
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
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPool}}
	client := &http.Client{Transport: tr}

	claims := decodeJWT(strings.TrimSpace(string(token)))

	return &Enumerator{
		client:    client,
		token:     strings.TrimSpace(string(token)),
		namespace: strings.TrimSpace(string(namespace)),
		claims:    claims,
	}, nil
}

func (e *Enumerator) Enumerate(dump bool) (*Results, error) {
	namespaces := e.getNamespaces()

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
	for _, ns := range namespaces {
		nsPerms := NamespacePermissions{
			Resources: make(map[string][]string),
			Dumps:     make(map[string]string),
		}

		for _, r := range nsResources {
			allowed := []string{}
			for _, v := range verbs {
				if e.checkAccess(r, v, ns) {
					allowed = append(allowed, v)
				}
			}
			if len(allowed) > 0 {
				nsPerms.Resources[r] = allowed

				// Dump resources if requested and readable
				if dump && contains([]string{"secrets", "configmaps", "pods", "services"}, r) {
					if contains(allowed, "get") || contains(allowed, "list") {
						dumpData := e.dumpResource(ns, r)
						nsPerms.Dumps[r] = dumpData
					}
				}
			}
		}

		results.Permissions.Namespaces[ns] = nsPerms
	}

	// Enumerate cluster resources
	for _, r := range clusterResources {
		allowed := []string{}
		for _, v := range verbs {
			if e.checkAccess(r, v, "") {
				allowed = append(allowed, v)
			}
		}
		if len(allowed) > 0 {
			results.Permissions.Cluster.Resources[r] = allowed
		}
	}

	return results, nil
}

func (e *Enumerator) checkAccess(resource, verb, namespace string) bool {
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
	req, _ := http.NewRequest("POST", apiServer+"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", bytes.NewBuffer(data))
	req.Header.Set("Authorization", "Bearer "+e.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
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

	req, _ := http.NewRequest("GET", apiServer+"/api/v1/namespaces", nil)
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
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
	if resource == "deployments" || resource == "daemonsets" || resource == "statefulsets" {
		url = fmt.Sprintf("%s/apis/apps/v1/namespaces/%s/%s", apiServer, ns, resource)
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+e.token)

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Sprintf("error: %v", err)
	}
	defer resp.Body.Close()
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

