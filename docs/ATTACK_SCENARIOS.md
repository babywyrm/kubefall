# Attack Scenarios & Enumeration Modes

## Current State: In-Cluster ServiceAccount Enumeration ✅

**What we have:**
- Pod with ServiceAccount token mounted
- In-cluster API access via `kubernetes.default.svc`
- SSAR-based permission enumeration

**Limitation:** Only works when you're already in a pod with a ServiceAccount.

## Additional Attack Scenarios (For Future Phases)

### 1. 🔴 Out-of-Cluster Enumeration (kubeconfig-based)

**Scenario:** Red teamer has compromised a developer's machine, CI/CD system, or backup with kubeconfig files.

**What to check:**
- Parse `~/.kube/config` or custom kubeconfig paths
- Extract contexts, users, clusters
- Test each context's permissions
- Check for embedded certificates/tokens
- Detect cloud provider auth (gcloud, aws-iam-authenticator, azure)

**Why this matters:**
- Developers often have kubeconfigs with elevated permissions
- CI/CD systems have cluster-admin access
- Backup files contain old kubeconfigs with valid creds

**Implementation:**
```go
// internal/auth/kubeconfig.go
type KubeconfigAuth struct {
    configPath string
    context    string
    // Support multiple auth methods:
    // - client-certificate
    // - token
    // - exec (gcloud, aws-iam-authenticator)
    // - azure
}
```

**Use cases:**
- `kubeenum --kubeconfig ~/.kube/config`
- `kubeenum --kubeconfig /backup/kubeconfig.yaml --context prod`

---

### 2. 🔴 Node-Level Access (Container Escape → Node Enumeration)

**Scenario:** Escaped container to node, now have shell on kubelet node.

**What to check:**
- **k3s-specific:**
  - `/etc/rancher/k3s/k3s.yaml` (admin kubeconfig)
  - `/var/lib/rancher/k3s/server/node-token` (node token)
  - `/var/lib/rancher/k3s/server/token` (server token)
  - `/var/lib/rancher/k3s/server/db/state.db` (embedded etcd)
  
- **Generic k8s:**
  - `/var/lib/kubelet/pods/*/volumes/*/token` (stolen ServiceAccount tokens)
  - `/etc/kubernetes/*.conf` (kubeconfig files)
  - `/var/lib/kubelet/config.yaml` (kubelet config)
  - `/root/.kube/config` (root's kubeconfig)
  - `/home/*/.kube/config` (user kubeconfigs)

**Why this matters:**
- Container escape is common (privileged pods, hostPath mounts)
- Nodes often have admin kubeconfigs
- k3s stores everything on disk (very CTF-friendly)

**Implementation:**
```go
// internal/auth/node.go
func DiscoverNodeTokens() []TokenSource {
    // Scan filesystem for tokens/kubeconfigs
    // Return list of usable credentials
}
```

**Use cases:**
- `kubeenum --node` (auto-detect node context)
- `kubeenum --token-file /etc/rancher/k3s/k3s.yaml`

---

### 3. 🔴 Cloud Metadata Abuse (IMDS / Metadata Servers)

**Scenario:** Pod has access to cloud metadata (IMDSv1/v2, GCP metadata, Azure identity).

**What to check:**
- **EKS:**
  - IMDS access (`169.254.169.254`)
  - IAM role attached to node/pod
  - `aws eks get-token` with node role
  - Pod service account with IRSA (IAM Roles for Service Accounts)
  
- **GKE:**
  - GCP metadata server access
  - Workload Identity (GSA → KSA mapping)
  - `gcloud container clusters get-credentials`
  
- **AKS:**
  - Azure Instance Metadata Service
  - Pod Identity / Workload Identity
  - `az aks get-credentials`

**Why this matters:**
- Cloud metadata often has cluster admin permissions
- Pods with cloud access can assume IAM roles
- Workload Identity links cloud IAM to K8s ServiceAccounts

**Implementation:**
```go
// internal/auth/cloud.go
type CloudAuth struct {
    provider string // aws, gcp, azure
    // Test IMDS access
    // Extract IAM role
    // Generate k8s token via cloud provider
}
```

**Use cases:**
- `kubeenum --cloud aws` (auto-detect and use IMDS)
- `kubeenum --cloud gcp --workload-identity`

---

### 4. 🔴 Token Theft & Reuse

**Scenario:** Found tokens in logs, environment variables, mounted volumes, or other pods.

**What to check:**
- **Token discovery:**
  - Environment variables (`KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT`)
  - Log files (application logs, kubelet logs)
  - Mounted volumes (shared storage, hostPath)
  - Other pods' ServiceAccount tokens (if hostPath mounted)
  - ConfigMaps/Secrets containing tokens
  - CI/CD artifacts (GitLab CI, GitHub Actions, Jenkins)
  
- **Token validation:**
  - Test if token is still valid
  - Extract ServiceAccount from token
  - Check token expiration
  - Test permissions with SSAR

**Why this matters:**
- Tokens leak everywhere (logs, env vars, backups)
- Old tokens might still be valid
- CI/CD systems embed tokens in artifacts

**Implementation:**
```go
// internal/auth/token.go
func DiscoverTokens() []string {
    // Scan environment
    // Parse logs
    // Check mounted volumes
    // Return list of candidate tokens
}

func ValidateToken(token string) (*TokenInfo, error) {
    // Decode JWT
    // Test API access
    // Return token metadata
}
```

**Use cases:**
- `kubeenum --token $(cat /var/log/app.log | grep -o 'eyJ.*')`
- `kubeenum --scan-tokens` (auto-discover from common locations)

---

### 5. 🔴 Certificate-Based Authentication

**Scenario:** Found client certificates (`client-certificate-data` in kubeconfig or `.crt` files).

**What to check:**
- Parse client certificates
- Extract CN (Common Name) → maps to user
- Extract O (Organization) → maps to groups
- Test certificate validity
- Check certificate expiration
- Test permissions with cert-based auth

**Why this matters:**
- Older clusters use certificate auth
- Certificates don't expire as quickly as tokens
- Found in backups, old kubeconfigs

**Implementation:**
```go
// internal/auth/certificate.go
type CertificateAuth struct {
    certPath string
    keyPath  string
    caPath   string
}
```

**Use cases:**
- `kubeenum --cert /path/to/client.crt --key /path/to/client.key`
- Auto-detect from kubeconfig

---

### 6. 🔴 Impersonation Abuse

**Scenario:** Current ServiceAccount has `impersonate` permissions (can act as other users).

**What to check:**
- Test if current SA can impersonate:
  - `system:serviceaccount:*:*` (any ServiceAccount)
  - `system:admin` (cluster admin)
  - `system:masters` (admin group)
  - Specific users/ServiceAccounts
- Enumerate impersonatable users
- Escalate via impersonation

**Why this matters:**
- Impersonation is a powerful escalation path
- Often granted to CI/CD systems
- Can bypass RBAC restrictions

**Implementation:**
```go
// internal/rbac/impersonation.go
func CheckImpersonation(client *http.Client, token string, target string) bool {
    // Test impersonation headers
    // Impersonate-User, Impersonate-Group, Impersonate-Extra
}
```

**Use cases:**
- `kubeenum --check-impersonation`
- Auto-detect and test if impersonation is possible

---

### 7. 🔴 Static Token Files (k3s-Specific)

**Scenario:** On k3s node, found static token files.

**What to check:**
- `/var/lib/rancher/k3s/server/node-token` (node token)
- `/var/lib/rancher/k3s/server/token` (server/bootstrap token)
- `/var/lib/rancher/k3s/server/cred/passwd` (static password file)
- Test token validity
- Extract permissions from token

**Why this matters:**
- k3s uses static tokens for node/server auth
- These tokens have high privileges
- Very common in CTFs

**Implementation:**
```go
// internal/auth/k3s.go
func DiscoverK3sTokens() []string {
    // Check k3s-specific paths
    // Return usable tokens
}
```

**Use cases:**
- `kubeenum --k3s-token /var/lib/rancher/k3s/server/node-token`

---

### 8. 🔴 Bootstrap Token Abuse

**Scenario:** Found bootstrap token (used for node joining, but might have lingering permissions).

**What to check:**
- Parse bootstrap token format (`[a-z0-9]{6}\.[a-z0-9]{16}`)
- Test token validity
- Check token permissions
- Check if token is expired

**Why this matters:**
- Bootstrap tokens sometimes have admin permissions
- Found in documentation, scripts, logs

**Implementation:**
```go
// internal/auth/bootstrap.go
func ValidateBootstrapToken(token string) bool {
    // Test bootstrap token format
    // Test API access
}
```

---

### 9. 🔴 Service Account Token Projection Abuse

**Scenario:** Pod uses projected ServiceAccount tokens (bound to specific audiences, expirations).

**What to check:**
- Detect if using projected tokens
- Check token audience restrictions
- Check token expiration
- Test if token can be used for different audiences

**Why this matters:**
- Projected tokens are more secure (shorter-lived, audience-bound)
- But might have different permissions than standard tokens

---

### 10. 🔴 Anonymous Access

**Scenario:** Cluster allows anonymous access (rare, but happens).

**What to check:**
- Test unauthenticated API access
- Check what anonymous user can do
- Test SSAR without token

**Why this matters:**
- Misconfigured clusters allow anonymous access
- Can enumerate without any credentials

---

## Implementation Priority

### Phase 2 (High Priority)
1. **Out-of-cluster kubeconfig support** - Most common scenario
2. **Node-level token discovery** - Critical for container escape
3. **Cloud metadata abuse** - Very common in cloud environments

### Phase 3 (Medium Priority)
4. **Token theft & reuse** - Common in real-world scenarios
5. **Impersonation abuse** - Powerful escalation path
6. **k3s static tokens** - CTF-friendly

### Phase 4 (Lower Priority)
7. **Certificate-based auth** - Less common (older clusters)
8. **Bootstrap tokens** - Niche scenario
9. **Anonymous access** - Rare but should be checked

---

## Unified Interface

The tool should support multiple auth methods:

```bash
# In-cluster (current)
kubeenum

# Out-of-cluster
kubeenum --kubeconfig ~/.kube/config
kubeenum --kubeconfig /path/to/config --context prod

# Node-level
kubeenum --node
kubeenum --token-file /etc/rancher/k3s/k3s.yaml

# Cloud metadata
kubeenum --cloud aws
kubeenum --cloud gcp

# Direct token
kubeenum --token eyJhbGciOiJSUzI1NiIs...

# Certificate
kubeenum --cert client.crt --key client.key --ca ca.crt

# Auto-discovery
kubeenum --auto-discover  # Try all methods
```

---

## Questions to Answer

1. **Should we support all auth methods or focus on most common?**
   - Recommendation: Start with kubeconfig + node-level + cloud metadata

2. **How do we handle multiple credentials?**
   - Test each and report findings
   - Allow user to specify which to use

3. **Should we auto-discover credentials?**
   - Yes, but make it opt-in (`--auto-discover`)
   - Don't be too noisy

4. **How do we handle credential storage?**
   - Never log full tokens/certs
   - Redact sensitive data in output


