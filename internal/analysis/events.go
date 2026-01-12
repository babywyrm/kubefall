package analysis

import (
	"encoding/json"
	"strings"
	"time"
)

// EventAnalysis contains security-relevant findings from Kubernetes events
type EventAnalysis struct {
	FailedAuth        []SecurityEvent
	SecretAccess      []SecurityEvent
	PodCreations      []SecurityEvent
	RBACChanges       []SecurityEvent
	ImagePullFailures []SecurityEvent
	NetworkViolations []SecurityEvent
	RecentEvents      []SecurityEvent
}

// SecurityEvent represents a security-relevant Kubernetes event
type SecurityEvent struct {
	Namespace    string
	Name         string
	Type         string // Normal, Warning
	Reason       string
	Message      string
	InvolvedKind string
	InvolvedName string
	FirstSeen    time.Time
	LastSeen     time.Time
	Count        int
}

// AnalyzeEvents parses Kubernetes events JSON and extracts security-relevant patterns
// If sinceDuration > 0, only events from the last sinceDuration are included
func AnalyzeEvents(eventsData string, sinceDuration time.Duration) *EventAnalysis {
	analysis := &EventAnalysis{
		FailedAuth:        []SecurityEvent{},
		SecretAccess:      []SecurityEvent{},
		PodCreations:      []SecurityEvent{},
		RBACChanges:       []SecurityEvent{},
		ImagePullFailures: []SecurityEvent{},
		NetworkViolations: []SecurityEvent{},
		RecentEvents:      []SecurityEvent{},
	}

	if eventsData == "" {
		return analysis
	}

	var eventList struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Type           string `json:"type"` // Normal or Warning
			Reason         string `json:"reason"`
			Message        string `json:"message"`
			InvolvedObject struct {
				Kind      string `json:"kind"`
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"involvedObject"`
			FirstTimestamp string `json:"firstTimestamp"`
			LastTimestamp  string `json:"lastTimestamp"`
			Count          int    `json:"count"`
		} `json:"items"`
	}

	if err := json.Unmarshal([]byte(eventsData), &eventList); err != nil {
		return analysis
	}

	now := time.Now()
	recentThreshold := 24 * time.Hour // Events from last 24 hours

	for _, event := range eventList.Items {
		// Skip events older than sinceDuration if specified
		if sinceDuration > 0 {
			var eventTime time.Time
			hasTime := false
			// Try LastTimestamp first, then FirstTimestamp
			if event.LastTimestamp != "" {
				if t, err := time.Parse(time.RFC3339, event.LastTimestamp); err == nil {
					eventTime = t
					hasTime = true
				} else if t, err := time.Parse(time.RFC3339Nano, event.LastTimestamp); err == nil {
					eventTime = t
					hasTime = true
				}
			}
			if !hasTime && event.FirstTimestamp != "" {
				if t, err := time.Parse(time.RFC3339, event.FirstTimestamp); err == nil {
					eventTime = t
					hasTime = true
				} else if t, err := time.Parse(time.RFC3339Nano, event.FirstTimestamp); err == nil {
					eventTime = t
					hasTime = true
				}
			}
			if hasTime && now.Sub(eventTime) > sinceDuration {
				continue // Skip events older than sinceDuration
			}
		}
		securityEvent := SecurityEvent{
			Namespace:    event.Metadata.Namespace,
			Name:         event.Metadata.Name,
			Type:         event.Type,
			Reason:       event.Reason,
			Message:      event.Message,
			InvolvedKind: event.InvolvedObject.Kind,
			InvolvedName: event.InvolvedObject.Name,
			Count:        event.Count,
		}

		// Parse timestamps (handle multiple formats)
		if event.FirstTimestamp != "" {
			// Try RFC3339 first (standard Kubernetes format)
			if t, err := time.Parse(time.RFC3339, event.FirstTimestamp); err == nil {
				securityEvent.FirstSeen = t
			} else {
				// Try RFC3339Nano
				if t, err := time.Parse(time.RFC3339Nano, event.FirstTimestamp); err == nil {
					securityEvent.FirstSeen = t
				}
			}
		}
		if event.LastTimestamp != "" {
			// Try RFC3339 first (standard Kubernetes format)
			if t, err := time.Parse(time.RFC3339, event.LastTimestamp); err == nil {
				securityEvent.LastSeen = t
			} else {
				// Try RFC3339Nano
				if t, err := time.Parse(time.RFC3339Nano, event.LastTimestamp); err == nil {
					securityEvent.LastSeen = t
				}
			}
		}

		// Categorize security-relevant events
		reasonLower := strings.ToLower(event.Reason)
		messageLower := strings.ToLower(event.Message)

		// Failed authentication attempts
		if strings.Contains(reasonLower, "unauthorized") ||
			strings.Contains(reasonLower, "forbidden") ||
			strings.Contains(messageLower, "authentication failed") ||
			strings.Contains(messageLower, "unauthorized") ||
			strings.Contains(messageLower, "forbidden") {
			analysis.FailedAuth = append(analysis.FailedAuth, securityEvent)
		}

		// Secret access patterns
		if event.InvolvedObject.Kind == "Secret" &&
			(strings.Contains(reasonLower, "get") ||
				strings.Contains(reasonLower, "list") ||
				strings.Contains(messageLower, "secret")) {
			analysis.SecretAccess = append(analysis.SecretAccess, securityEvent)
		}

		// Pod creation events (reconnaissance/lateral movement indicator)
		if event.InvolvedObject.Kind == "Pod" &&
			(strings.Contains(reasonLower, "created") ||
				strings.Contains(reasonLower, "scheduled") ||
				strings.Contains(reasonLower, "started")) {
			analysis.PodCreations = append(analysis.PodCreations, securityEvent)
		}

		// RBAC changes (privilege escalation indicators)
		if (event.InvolvedObject.Kind == "Role" ||
			event.InvolvedObject.Kind == "RoleBinding" ||
			event.InvolvedObject.Kind == "ClusterRole" ||
			event.InvolvedObject.Kind == "ClusterRoleBinding") &&
			(strings.Contains(reasonLower, "created") ||
				strings.Contains(reasonLower, "updated") ||
				strings.Contains(reasonLower, "deleted")) {
			analysis.RBACChanges = append(analysis.RBACChanges, securityEvent)
		}

		// Image pull failures (could indicate image registry issues or malicious images)
		if strings.Contains(reasonLower, "failedpull") ||
			strings.Contains(reasonLower, "errimagepull") ||
			strings.Contains(messageLower, "failed to pull image") ||
			strings.Contains(messageLower, "pull image") {
			analysis.ImagePullFailures = append(analysis.ImagePullFailures, securityEvent)
		}

		// Network policy violations (missing segmentation)
		if strings.Contains(reasonLower, "network") ||
			strings.Contains(messageLower, "networkpolicy") ||
			strings.Contains(messageLower, "ingress") ||
			strings.Contains(messageLower, "egress") {
			analysis.NetworkViolations = append(analysis.NetworkViolations, securityEvent)
		}

		// Recent events (within last 24 hours)
		if !securityEvent.LastSeen.IsZero() && now.Sub(securityEvent.LastSeen) < recentThreshold {
			analysis.RecentEvents = append(analysis.RecentEvents, securityEvent)
		}
	}

	return analysis
}
