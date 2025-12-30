package discovery

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

const apiServerCluster = "https://kubernetes.default.svc"

type ClusterInfo struct {
	Version string
	Major   string
	Minor   string
	Git     string
	Platform string
}

type NodeInfo struct {
	Name           string
	KubeletVersion string
	OSImage        string
	Architecture   string
	ContainerRuntime string
}

func DiscoverClusterVersion(client *http.Client, token string) (*ClusterInfo, error) {
	url := fmt.Sprintf("%s/version", apiServerCluster)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get version: %d", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	var version struct {
		Major      string `json:"major"`
		Minor      string `json:"minor"`
		GitVersion string `json:"gitVersion"`
		Platform   string `json:"platform"`
	}

	if err := json.Unmarshal(body, &version); err != nil {
		return nil, err
	}

	return &ClusterInfo{
		Version:  version.GitVersion,
		Major:    version.Major,
		Minor:    version.Minor,
		Git:      version.GitVersion,
		Platform: version.Platform,
	}, nil
}

func DiscoverNodes(client *http.Client, token string) ([]NodeInfo, error) {
	url := fmt.Sprintf("%s/api/v1/nodes", apiServerCluster)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("failed to get nodes: %d", resp.StatusCode)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	var nodeList struct {
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Status struct {
				NodeInfo struct {
					KubeletVersion     string `json:"kubeletVersion"`
					OSImage            string `json:"osImage"`
					Architecture       string `json:"architecture"`
					ContainerRuntimeVersion string `json:"containerRuntimeVersion"`
				} `json:"nodeInfo"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &nodeList); err != nil {
		return nil, err
	}

	nodes := []NodeInfo{}
	for _, item := range nodeList.Items {
		nodes = append(nodes, NodeInfo{
			Name:             item.Metadata.Name,
			KubeletVersion:   item.Status.NodeInfo.KubeletVersion,
			OSImage:          item.Status.NodeInfo.OSImage,
			Architecture:     item.Status.NodeInfo.Architecture,
			ContainerRuntime: item.Status.NodeInfo.ContainerRuntimeVersion,
		})
	}

	return nodes, nil
}

