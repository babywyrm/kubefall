# Enhancement Plan - Comprehensive Kubernetes Enumeration

Based on research findings, here are the key enhancements to make kubefall more comprehensive:

## Priority 1: Critical Escalation Paths

### 1. Pod Security Context Analysis
- Detect privileged pods
- Find hostNetwork/hostPID pods
- Identify hostPath mounts (especially dangerous paths like /, /var/lib/kubelet)
- Check for dangerous capabilities (SYS_ADMIN, NET_ADMIN, etc.)
- Security context misconfigurations

### 2. Enhanced RBAC Enumeration
- List and analyze Roles/ClusterRoles (not just permissions)
- Find cluster-admin bindings
- Map ServiceAccount → Role → Permissions
- Identify wildcard permissions
- Show actual role rules, not just SSAR results

### 3. Service Account Token Extraction
- Extract tokens from pods
- List service accounts across namespaces
- Identify high-privilege service accounts

## Priority 2: Discovery & Intelligence

### 4. Dynamic API Discovery
- Discover all API groups (/apis)
- Find CRDs automatically
- Test SSAR against discovered resources
- Support custom resources (cert-manager, Istio, etc.)

### 5. Cluster Information
- Cluster version (for CVE hunting)
- Node enumeration (OS, kubelet version)
- API server capabilities

### 6. Event Enumeration
- Recent events (security-related)
- Failed auth attempts
- Pod creation/deletion events

## Priority 3: Data Extraction

### 7. Advanced Secret/ConfigMap Analysis
- Pattern matching (password, token, key, secret)
- TLS certificate extraction
- Service account token secrets
- Base64 decoding and validation

### 8. Network Topology
- Ingress enumeration with TLS config
- NetworkPolicy analysis (or lack thereof)
- Service endpoints mapping
- NodePort/LoadBalancer detection

## Priority 4: Workload Analysis

### 9. Deployment/DaemonSet/StatefulSet Analysis
- Security contexts in workloads
- Image analysis
- Volume mounts
- Environment variable extraction

### 10. Persistent Volume Analysis
- PVC enumeration
- Storage class discovery
- Volume attachment details

## Implementation Strategy

1. Add new modules incrementally
2. Keep output organized by category
3. Maintain backward compatibility
4. Add flags to enable/disable features
5. Keep it fast and portable


