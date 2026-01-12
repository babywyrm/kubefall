package analysis

import (
	"encoding/json"
	"strings"
)

type PodSecurityAnalysis struct {
	PrivilegedPods  []PodInfo
	HostNetworkPods []PodInfo
	HostPIDPods     []PodInfo
	HostIPCPods     []PodInfo
	HostPathMounts  []PodHostPath
	DangerousCaps   []PodCapability
	RunAsRoot       []PodInfo
	AllowEscalation []PodInfo
}

type PodInfo struct {
	Name      string
	Namespace string
	Image     string
	SA        string
}

type PodHostPath struct {
	PodInfo
	Path     string
	ReadOnly bool
}

type PodCapability struct {
	PodInfo
	Capability string
}

func AnalyzePodSecurity(podsData string) *PodSecurityAnalysis {
	analysis := &PodSecurityAnalysis{
		PrivilegedPods:  []PodInfo{},
		HostNetworkPods: []PodInfo{},
		HostPIDPods:     []PodInfo{},
		HostIPCPods:     []PodInfo{},
		HostPathMounts:  []PodHostPath{},
		DangerousCaps:   []PodCapability{},
		RunAsRoot:       []PodInfo{},
		AllowEscalation: []PodInfo{},
	}

	var podList struct {
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Spec struct {
				ServiceAccountName string `json:"serviceAccountName"`
				HostNetwork        bool   `json:"hostNetwork"`
				HostPID            bool   `json:"hostPID"`
				HostIPC            bool   `json:"hostIPC"`
				Containers         []struct {
					Image           string `json:"image"`
					SecurityContext struct {
						Privileged               *bool  `json:"privileged"`
						RunAsUser                *int64 `json:"runAsUser"`
						AllowPrivilegeEscalation *bool  `json:"allowPrivilegeEscalation"`
						Capabilities             struct {
							Add []string `json:"add"`
						} `json:"capabilities"`
					} `json:"securityContext"`
				} `json:"containers"`
				Volumes []struct {
					HostPath struct {
						Path string `json:"path"`
						Type string `json:"type"`
					} `json:"hostPath"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(podsData), &podList); err != nil {
		return analysis
	}

	dangerousCaps := []string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE"}

	for _, pod := range podList.Items {
		podInfo := PodInfo{
			Name:      pod.Metadata.Name,
			Namespace: pod.Metadata.Namespace,
			SA:        pod.Spec.ServiceAccountName,
		}

		if pod.Spec.HostNetwork {
			analysis.HostNetworkPods = append(analysis.HostNetworkPods, podInfo)
		}

		if pod.Spec.HostPID {
			analysis.HostPIDPods = append(analysis.HostPIDPods, podInfo)
		}

		if pod.Spec.HostIPC {
			analysis.HostIPCPods = append(analysis.HostIPCPods, podInfo)
		}

		for _, vol := range pod.Spec.Volumes {
			if vol.HostPath.Path != "" {
				dangerousPaths := []string{"/", "/var/lib/kubelet", "/etc/kubernetes", "/var/lib/docker", "/run"}
				for _, dangerous := range dangerousPaths {
					if vol.HostPath.Path == dangerous || strings.HasPrefix(vol.HostPath.Path, dangerous+"/") {
						analysis.HostPathMounts = append(analysis.HostPathMounts, PodHostPath{
							PodInfo:  podInfo,
							Path:     vol.HostPath.Path,
							ReadOnly: vol.HostPath.Type == "FileOrCreate",
						})
						break
					}
				}
			}
		}

		for i, container := range pod.Spec.Containers {
			if i == 0 && container.Image != "" {
				podInfo.Image = container.Image
			}

			if container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged {
				analysis.PrivilegedPods = append(analysis.PrivilegedPods, podInfo)
			}

			if container.SecurityContext.RunAsUser != nil && *container.SecurityContext.RunAsUser == 0 {
				analysis.RunAsRoot = append(analysis.RunAsRoot, podInfo)
			}

			if container.SecurityContext.AllowPrivilegeEscalation != nil && *container.SecurityContext.AllowPrivilegeEscalation {
				analysis.AllowEscalation = append(analysis.AllowEscalation, podInfo)
			}

			for _, cap := range container.SecurityContext.Capabilities.Add {
				for _, dangerous := range dangerousCaps {
					if cap == dangerous {
						analysis.DangerousCaps = append(analysis.DangerousCaps, PodCapability{
							PodInfo:    podInfo,
							Capability: cap,
						})
						break
					}
				}
			}
		}
	}

	return analysis
}
