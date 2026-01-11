# Detection Coverage & Security Implications

This document provides detailed explanations of what kubefall detects, why each finding matters, and the real-world security impact.

## Pod Security Context Analysis

> **Severity Classification:** Pod security findings are displayed in the "🔒 POD SECURITY ANALYSIS" section. The severity is indicated by color: **🔴 Red (Critical)** for privileged pods, **🟡 Yellow (Warning)** for hostNetwork/hostPID/hostIPC. These are separate from RBAC severity classifications (critical/high/interesting/normal).

### Privileged Pods 🔴 **CRITICAL**
**What it detects:** Pods with `securityContext.privileged: true`

**Severity:** 🔴 **Critical** - Direct privilege escalation path to host root access

**Real-world impact:**
- **Container escape** - Privileged containers can escape container boundaries and gain root access to the host node
- **Node compromise** - Attackers can access host filesystems, processes, and network interfaces
- **Cluster-wide access** - Once on a node, attackers can steal ServiceAccount tokens from other pods, access kubelet credentials, or mount host filesystems containing cluster secrets

**Attack scenario:** An attacker with permission to create pods can deploy a privileged pod, escape to the host, and steal cluster credentials or pivot to other nodes.

**Reference:** [Bishop Fox Bad Pods #1](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### HostNetwork Pods 🟡 **WARNING**
**What it detects:** Pods with `spec.hostNetwork: true`

**Severity:** 🟡 **Warning/High** - Security risk but not direct privilege escalation

**Real-world impact:**
- **Network bypass** - Pods share the host's network namespace, bypassing NetworkPolicy restrictions
- **Traffic interception** - Can sniff network traffic on host interfaces (potential credential theft)
- **Localhost service access** - Can access services bound only to localhost/127.0.0.1
- **Port conflicts** - Can cause port conflicts with host services

**Attack scenario:** An attacker creates a hostNetwork pod to bypass network policies, intercept traffic, or access services only listening on localhost.

**Reference:** [Bishop Fox Bad Pods #6](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### HostPID Pods 🟡 **WARNING**
**What it detects:** Pods with `spec.hostPID: true`

**Severity:** 🟡 **Warning/High** - Security risk but not direct privilege escalation

**Real-world impact:**
- **Process visibility** - Can see all processes running on the host node, including processes in other pods
- **Credential discovery** - May find credentials, tokens, or secrets visible in process environments
- **Process manipulation** - Can kill or signal processes on the host (DoS risk)
- **Information leakage** - Can observe application behavior, command-line arguments, environment variables

**Attack scenario:** An attacker uses hostPID to inspect processes, steal ServiceAccount tokens from other pods' process environments, or identify high-value targets.

**Reference:** [Bishop Fox Bad Pods #5](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### HostIPC Pods 🟡 **WARNING**
**What it detects:** Pods with `spec.hostIPC: true`

**Severity:** 🟡 **Warning/High** - Data leakage risk, not direct privilege escalation

**Real-world impact:**
- **Shared memory access** - Can access shared memory segments (`/dev/shm`) and IPC facilities (message queues, semaphores)
- **Inter-process communication** - Can read/write to IPC mechanisms used by host processes or other pods
- **Data leakage** - Applications using shared memory may leak sensitive data accessible to hostIPC pods

**Why it's warning, not critical:** Unlike privileged pods (which can escape to host root) or hostNetwork/hostPID (which enable credential theft), hostIPC primarily enables information disclosure through shared memory. It's a data leakage risk, not a direct privilege escalation path.

**Attack scenario:** An attacker uses hostIPC to access shared memory containing sensitive data, intercept IPC messages, or interfere with host process communication.

**Reference:** [Bishop Fox Bad Pods #7](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### HostPath Mounts
**What it detects:** Pods with `volumes[].hostPath.path` pointing to dangerous host directories

**Dangerous paths detected:**
- `/` - Root filesystem (full host access)
- `/var/lib/kubelet` - Kubelet data directory (contains pod volumes, credentials)
- `/etc/kubernetes` - Kubernetes configuration files (may contain cluster secrets)
- `/var/lib/docker` - Docker data directory (can access container filesystems)
- `/run` - Runtime data (can access socket files, credentials)

**Real-world impact:**
- **Host filesystem access** - Can read/write host files, potentially accessing cluster secrets, kubelet credentials, or other sensitive data
- **Credential theft** - Can access ServiceAccount tokens, kubeconfig files, or cloud provider credentials stored on the host
- **Persistent backdoor** - Can modify host files to maintain persistence or install backdoors

**Attack scenario:** An attacker mounts `/var/lib/kubelet` to steal ServiceAccount tokens from all pods, or mounts `/etc/kubernetes` to access cluster-admin credentials.

**Reference:** [Bishop Fox Bad Pods #4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### Dangerous Capabilities
**What it detects:** Pods with dangerous Linux capabilities in `securityContext.capabilities.add`

**Dangerous capabilities detected:**
- `SYS_ADMIN` / `CAP_SYS_ADMIN` - Can mount filesystems, perform administrative tasks
- `NET_ADMIN` / `CAP_NET_ADMIN` - Can modify network configuration, create interfaces
- `SYS_PTRACE` / `CAP_SYS_PTRACE` - Can attach to and debug other processes
- `SYS_MODULE` / `CAP_SYS_MODULE` - Can load/unload kernel modules
- `DAC_OVERRIDE` / `CAP_DAC_OVERRIDE` - Can bypass file permission checks

**Real-world impact:**
- `SYS_ADMIN` - Similar to privileged mode; can mount filesystems, escape containers
- `NET_ADMIN` - Can intercept traffic, bypass network policies, modify routing
- `SYS_PTRACE` - Can inspect and manipulate other processes, steal credentials from process memory
- `SYS_MODULE` - Can load malicious kernel modules for persistence or privilege escalation
- `DAC_OVERRIDE` - Can bypass file permissions to access protected files

**Attack scenario:** An attacker uses `SYS_PTRACE` to attach to processes and steal credentials, or `NET_ADMIN` to intercept network traffic.

**Reference:** [Bishop Fox Bad Pods #3](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)

---

### RunAsRoot Pods
**What it detects:** Pods with `securityContext.runAsUser: 0` (root user)

**Real-world impact:**
- **Increased attack surface** - Running as root increases the impact of vulnerabilities
- **File permission bypass** - Can access files that non-root processes cannot
- **Process manipulation** - Can kill or signal processes owned by other users
- **Container escape risk** - If combined with other misconfigurations, root access increases escape risk

**Best practice:** Containers should run as non-root users whenever possible.

---

### AllowPrivilegeEscalation Pods
**What it detects:** Pods with `securityContext.allowPrivilegeEscalation: true`

**Real-world impact:**
- **Capability escalation** - Processes can gain additional capabilities (e.g., via `setuid` binaries)
- **Privilege escalation path** - Combined with other misconfigurations, can lead to full privilege escalation
- **Security boundary weakening** - Reduces effectiveness of capability-based security model

**Best practice:** Should be set to `false` unless absolutely necessary.

---

## RBAC Analysis

### Cluster-Admin Bindings
**What it detects:** ClusterRoleBindings or RoleBindings that grant cluster-admin or admin-level permissions

**Real-world impact:**
- **Full cluster control** - Subjects (users, ServiceAccounts, groups) have complete control over the cluster
- **Credential theft** - Can read all secrets, access all namespaces, impersonate any user
- **Persistence** - Can create new ServiceAccounts, roles, or backdoors
- **Lateral movement** - Can access any resource in the cluster

**Attack scenario:** An attacker who compromises a ServiceAccount bound to cluster-admin gains full cluster control.

---

### Wildcard Roles
**What it detects:** Roles or ClusterRoles with wildcard permissions (`resources: ["*"]`, `verbs: ["*"]`)

**Real-world impact:**
- **Overprivileged access** - Grants more permissions than necessary
- **Violation of least privilege** - Subjects can perform actions beyond their intended scope
- **Increased attack surface** - More permissions = more potential for abuse

**Best practice:** Roles should grant only the minimum permissions required for specific resources and verbs.

---

## Service Account Token Extraction

**What it detects:** ServiceAccount tokens stored in secrets (type: `kubernetes.io/service-account-token`)

**Real-world impact:**
- **Credential discovery** - Finds ServiceAccount tokens that can be used for API authentication
- **Lateral movement** - Tokens from higher-privileged ServiceAccounts can enable privilege escalation
- **Token reuse** - Extracted tokens can be used outside the cluster if not properly secured
- **High-privilege SA detection** - Identifies ServiceAccounts with potentially dangerous names (e.g., `*-admin`, `*-operator`)

**Attack scenario:** An attacker extracts a ServiceAccount token with cluster-admin permissions and uses it to gain full cluster control.

---

## Network Policy Analysis

**What it detects:** Namespaces without NetworkPolicies or overly permissive NetworkPolicies

**Real-world impact:**
- **No network segmentation** - By default, Kubernetes allows all traffic between pods
- **Lateral movement** - Attackers can reach any pod from any pod without restrictions
- **Attack surface expansion** - Vulnerable services are accessible from anywhere in the cluster
- **Compliance violations** - Many security frameworks require network segmentation

**Attack scenario:** An attacker compromises one pod and can immediately communicate with all other pods in the cluster, including those in sensitive namespaces like `kube-system`.

**Note:** NetworkPolicy analysis is optional and disabled by default (use `--network-policies` flag).

---

## Event Analysis

**What it detects:** Security-relevant Kubernetes events including:
- Failed authentication attempts
- RBAC changes (Role/RoleBinding creation/modification)
- Secret access patterns
- Pod creations
- Image pull failures
- Network policy violations

**Real-world impact:**
- **Attack detection** - Failed auth attempts may indicate brute force or credential stuffing
- **Privilege escalation attempts** - RBAC changes may indicate attackers creating backdoors
- **Anomaly detection** - Unusual patterns (many pod creations, secret accesses) may indicate compromise
- **Compliance monitoring** - Event analysis helps meet audit and compliance requirements

**Note:** Event analysis is optional (use `--events` flag).

---

## Reliability Features

### HTTP Timeouts & Retries
**What it does:** All API requests have 10-second timeouts and automatic retry with exponential backoff

**Real-world impact:**
- **Prevents hangs** - Tool won't hang indefinitely if API server is slow or unresponsive
- **Handles transient failures** - Automatic retries handle temporary network issues
- **Fails fast** - After 10 consecutive failures, tool bails out with clear error message

**Why it matters:** In unstable clusters or during incidents, the tool remains usable and provides actionable error messages instead of hanging.

---

## References

- [Bishop Fox: Bad Pods - Kubernetes Pod Privilege Escalation](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CNCF Security Technical Advisory Group](https://github.com/cncf/tag-security)

