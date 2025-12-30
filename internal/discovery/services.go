package discovery

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const apiServer = "https://kubernetes.default.svc"

type ServiceInfo struct {
	Name      string
	Namespace string
	Type      string
	Ports     []ServicePort
	ClusterIP string
}

type ServicePort struct {
	Port     int
	Protocol string
	Name     string
}

func DiscoverServices(client *http.Client, token string, namespaces []string) map[string][]ServiceInfo {
	services := make(map[string][]ServiceInfo)

	for _, ns := range namespaces {
		url := fmt.Sprintf("%s/api/v1/namespaces/%s/services", apiServer, ns)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, _ := ioutil.ReadAll(resp.Body)
		var svcList struct {
			Items []struct {
				Metadata struct {
					Name string `json:"name"`
				} `json:"metadata"`
				Spec struct {
					Type      string `json:"type"`
					ClusterIP string `json:"clusterIP"`
					Ports     []struct {
						Port     int    `json:"port"`
						Protocol string `json:"protocol"`
						Name     string `json:"name"`
					} `json:"ports"`
				} `json:"spec"`
			} `json:"items"`
		}

		if err := json.Unmarshal(body, &svcList); err != nil {
			continue
		}

		for _, item := range svcList.Items {
			ports := []ServicePort{}
			for _, p := range item.Spec.Ports {
				ports = append(ports, ServicePort{
					Port:     p.Port,
					Protocol: p.Protocol,
					Name:     p.Name,
				})
			}

			services[ns] = append(services[ns], ServiceInfo{
				Name:      item.Metadata.Name,
				Namespace: ns,
				Type:      item.Spec.Type,
				Ports:     ports,
				ClusterIP: item.Spec.ClusterIP,
			})
		}
	}

	return services
}

func FormatServiceAccess(services map[string][]ServiceInfo) string {
	if len(services) == 0 {
		return ""
	}

	var output []string
	output = append(output, "\n[NETWORK] Discovered Services:")
	
	for ns, svcs := range services {
		output = append(output, fmt.Sprintf("  Namespace: %s", ns))
		for _, svc := range svcs {
			portStrs := []string{}
			for _, p := range svc.Ports {
				portStrs = append(portStrs, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
			}
			output = append(output, fmt.Sprintf("    • %s (%s) - %s", svc.Name, svc.Type, strings.Join(portStrs, ", ")))
			if svc.Type == "NodePort" || svc.Type == "LoadBalancer" {
				output = append(output, fmt.Sprintf("      %s⚠️  Exposed externally!%s", "\033[93m", "\033[0m"))
			}
		}
	}

	return strings.Join(output, "\n")
}

