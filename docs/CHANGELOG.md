# Changelog

All notable changes to kubefall will be documented in this file.

## [Unreleased]

### Added
- **HostIPC detection** - Detects pods with `hostIPC: true` (data leakage risk through shared memory/IPC)
- **HostPID display fix** - HostPID pods were detected but not displayed; now properly shown in output
- **HTTP timeouts and retry logic** - Prevents hangs on slow/unresponsive API servers (10-second timeouts, exponential backoff)
- **Early bailout mechanism** - Stops after 10 consecutive API failures with clear error messages instead of hanging indefinitely
- **Comprehensive detection documentation** (`docs/DETECTIONS.md`) - Explains what each finding means and real-world security impact
- **Reference documentation** (`docs/REFERENCES.md`) - Links to external research and resources (Bishop Fox Bad Pods, etc.)
- **Changelog** (`docs/CHANGELOG.md`) - This file, tracking all changes

### Changed
- **NetworkPolicy analysis now optional** - Disabled by default for performance, use `--network-policies` flag to enable
- **Event analysis now optional** - Disabled by default, use `--events` flag to enable
- **Event analysis flags** - Added `--events-since <duration>` and `--events-limit <number>` for filtering and limiting event output
- **Documentation consolidation** - Removed redundant docs (ENHANCEMENT_PLAN, NEXT_STEPS, ENHANCEMENTS_ADDED), consolidated into ROADMAP

### Fixed
- **Performance regression** - NetworkPolicy analysis was causing slowdowns; made opt-in to restore performance
- **Tool hanging indefinitely** - Added timeouts and retry logic to handle unresponsive clusters gracefully
- **HostPID not displayed** - HostPID pods were detected but missing from output; now fixed

## [Previous Weeks]

### Added - Output Formats & Options
- **Multiple output formats** - JSON, CSV, HTML, Markdown export (`--format`)
- **File export** - Write results to files (`--output <file>`)
- **Severity filtering** - Filter by severity levels (`--severity critical,high,interesting,normal`)
- **Summary-only mode** - Condensed output showing only summary section (`--summary-only`)
- **No-color mode** - Disable ANSI color codes for scripts and logs (`--no-color`)
- **Separated severity sections** - Critical findings and High findings now displayed in separate banner sections

### Added - Event Analysis
- **Event enumeration and analysis** - Analyzes Kubernetes events for security-relevant patterns
- **Event categories** - Failed authentication attempts, RBAC changes, secret access, pod creations, image pull failures, network violations
- **Event filtering** - `--events-since <duration>` (e.g., 24h, 1h) and `--events-limit <number>` for custom filtering
- **Event output formatting** - Events displayed in categorized sections with timestamps and details

### Added - NetworkPolicy Analysis
- **NetworkPolicy enumeration** - Identifies namespaces without NetworkPolicies (permissive by default)
- **Deny-all policy detection** - Finds NetworkPolicies with empty rules (block all traffic)
- **NetworkPolicy listing** - Lists all NetworkPolicies found in each namespace
- **Optional feature** - Disabled by default (use `--network-policies` flag)

### Added - Service Account Token Extraction
- **Token discovery** - Extracts ServiceAccount tokens from secrets (type: `kubernetes.io/service-account-token`)
- **Token validation** - Decodes JWT claims and validates tokens
- **High-privilege SA detection** - Identifies ServiceAccounts with potentially dangerous names (e.g., `*-admin`, `*-operator`)
- **SA enumeration** - Lists all ServiceAccounts from pods and ServiceAccount resources

### Added - Pod Security Context Analysis
- **Privileged pod detection** - Detects pods with `securityContext.privileged: true` (critical - container escape)
- **HostNetwork pod detection** - Detects pods with `spec.hostNetwork: true` (warning - network bypass)
- **HostPID pod detection** - Detects pods with `spec.hostPID: true` (warning - process visibility)
- **HostPath mount detection** - Identifies dangerous hostPath mounts (/, /var/lib/kubelet, /etc/kubernetes, etc.)
- **Dangerous capabilities detection** - Finds pods with SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE, DAC_OVERRIDE
- **RunAsRoot detection** - Identifies pods running as root (UID 0)
- **AllowPrivilegeEscalation detection** - Detects pods that can escalate privileges

### Added - RBAC Analysis
- **Cluster-admin binding discovery** - Finds all subjects bound to cluster-admin or admin roles
- **Wildcard role detection** - Identifies roles with wildcard permissions
- **Secret access role detection** - Finds roles that can read secrets
- **Pod creation role detection** - Identifies roles that can create pods

### Added - Cluster Discovery
- **Cluster version discovery** - Detects Kubernetes version (for CVE hunting)
- **Node information** - Kubelet version, OS image, architecture, container runtime
- **Environment detection** - Automatically detects k3s, EKS, GKE, AKS, vanilla k8s

### Added - Service Discovery
- **Network service discovery** - Analyzes service exposure and network policies
- **Service enumeration** - Lists services across namespaces

### Changed
- **Output structure** - Separated Critical and High findings into distinct sections with banner headers
- **Output ordering** - Event analysis moved to end of output, NetworkPolicy analysis added
- **Flag descriptions** - Updated to reflect all new options and features

### Documentation
- **README updates** - Added all new features, flags, and output formats
- **DETECTIONS.md** - Comprehensive guide explaining what each finding means and real-world impact
- **ROADMAP.md** - Updated to reflect completed phases (1, 2, 3) and planned phases
- **REFERENCES.md** - External research and resources (Bishop Fox Bad Pods article)
- **CHANGELOG.md** - This file, tracking all changes over time

## [Earlier Versions]

### Core Features
- RBAC enumeration using SelfSubjectAccessReview (SSAR)
- Comprehensive resource coverage (23+ namespace, 14+ cluster resources)
- Environment detection (k3s, EKS, GKE, AKS, vanilla k8s)
- Verbose mode for debugging
- Resource dumping (`--dump` flag)
- Structured data extraction from ConfigMaps/Secrets

See `docs/ROADMAP.md` for completed phases and planned features.
