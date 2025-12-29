# kubefall

A practical, operator-focused Kubernetes enumeration framework that works across all Kubernetes distributions (k3s, EKS, GKE, AKS, vanilla k8s).

## 🎯 Goals

- **🔴 Red team / CTFs** – privilege escalation, lateral movement, data exfil paths
- **🔵 Blue team** – detection, misconfig discovery, blast-radius analysis  
- **🟣 Purple team** – mapping findings → MITRE / OWASP / hardening guidance

Think "linpeas + kube-hunter + custom k3s weirdness", but readable and hackable.

## 🚀 Quick Start

### Build

```bash
# Build for current platform
make build

# Build for Linux (containers/CTFs)
make build-linux
```

### Usage

```bash
# Basic enumeration
./bin/kubeenum

# Dump readable resources (secrets, configmaps, pods, services)
./bin/kubeenum --dump

# JSON output for automation
./bin/kubeenum --json

# Blue team mode (detection-focused)
./bin/kubeenum --mode blue --explain

# Audit mode (compliance-focused)
./bin/kubeenum --mode audit

# Verbose mode (see what's being checked)
./bin/kubeenum --verbose
```

## 🔧 How It Works

### Core Principle: SelfSubjectAccessReview (SSAR)

Unlike most enum tools that require RBAC read permissions, `kubefall` uses the Kubernetes authorization API directly. This means:

- ✅ Works without `kubectl`
- ✅ Works without RBAC read permissions
- ✅ Uses the authoritative authorization path
- ✅ Survives hardened clusters

### Environment Detection

Automatically detects:
- **k3s**: Token audience contains "k3s", `/etc/rancher/k3s/k3s.yaml`
- **EKS**: AWS_REGION, OIDC issuer patterns (`oidc.eks.*`)
- **GKE**: GKE_PROJECT, GKE metadata server
- **AKS**: AZURE_TENANT_ID, federated token files
- **Vanilla k8s**: Default fallback

### What It Checks

**Namespace Resources (20+):**
- Core: secrets, configmaps, pods, services, endpoints, events
- Workloads: deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs
- RBAC: roles, rolebindings, serviceaccounts
- Networking: ingresses, networkpolicies
- Storage: persistentvolumeclaims
- Config: limitranges, resourcequotas
- Autoscaling: horizontalpodautoscalers

**Cluster Resources (10+):**
- Core: nodes, namespaces, persistentvolumes
- RBAC: clusterroles, clusterrolebindings
- Storage: storageclasses, volumeattachments
- Extensions: customresourcedefinitions, apiservices
- Webhooks: mutatingwebhookconfigurations, validatingwebhookconfigurations
- Security: podsecuritypolicies (deprecated)

**Escalation Detection:**
- 🔴 **Critical**: secrets (read), pods (create), clusterroles/clusterrolebindings (create), webhook configs (create)
- 🟠 **High**: serviceaccounts (create), rolebindings (create), customresourcedefinitions (create)
- 🟡 **Interesting**: configmaps (read), serviceaccounts (read), ingresses (create), networkpolicies (create)

## 📖 Example Output

```
=== ENVIRONMENT ===
Type: k3s
Distribution: k3s
Metadata:
  issuer: https://kubernetes.default.svc.cluster.local
  serviceaccount: system:serviceaccount:internal:flask-rage-sa

=== SERVICE ACCOUNT ===
Current namespace: internal
Token Claims:
  sub: system:serviceaccount:internal:flask-rage-sa
  aud: [https://kubernetes.default.svc.cluster.local k3s]

=== NAMESPACE RESOURCES ===
-- Namespace: dev-internal --
configmaps           -> get,list <<! INTERESTING: can read configmaps !>>

-- Namespace: internal --
configmaps           -> get,list <<! INTERESTING: can read configmaps !>>

=== CLUSTER RESOURCES ===
namespaces           -> get,list

=== SUMMARY ===
✓ No obvious escalation paths detected
```

### Verbose Mode

```bash
$ ./bin/kubeenum --verbose
[*] Starting enumeration...
[*] Checking 20 namespace resources across all namespaces
[*] Checking 11 cluster resources
[*] Discovered 8 namespace(s): default, dev-internal, internal, kube-public, kube-system, wordpress, gatekeeper-system, kube-node-lease

[*] Enumerating namespace resources...
[*] Checking namespace: dev-internal
  [*] Checking resource: configmaps
    [-] configmaps/get: denied
    [+] configmaps/list: ALLOWED
    [-] configmaps/create: denied
    ...
```

Verbose mode shows:
- What resources are being checked
- Each SSAR call (allowed/denied)
- Which namespaces are being enumerated
- Progress through the enumeration

## 🏗️ Architecture

```
kubefall/
├── cmd/kubeenum/          # Main CLI entrypoint
├── internal/
│   ├── rbac/              # RBAC enumeration engine (SSAR-based)
│   ├── context/           # Environment detection
│   └── output/            # Output formatters (red/blue/audit modes)
├── Makefile               # Build automation
└── README.md              # This file
```

## 🛠️ Development

### Project Structure

- `cmd/kubeenum/` - Main CLI application
- `internal/rbac/` - RBAC enumeration engine
- `internal/context/` - Environment detection
- `internal/output/` - Output formatters

### Adding New Checks

1. Add resource to `internal/rbac/enumerator.go` (nsResources or clusterResources)
2. Add escalation rule to `internal/output/formatter.go` (analyzeResource function)
3. Update output formatter if needed

## 🧪 Testing

### Local Testing with kind

```bash
# Create cluster
kind create cluster

# Create test ServiceAccount
kubectl create serviceaccount test-sa -n default

# Create pod with ServiceAccount
kubectl run test-pod --image=busybox --serviceaccount=test-sa -- sleep 3600

# Copy binary into pod
kubectl cp bin/kubeenum default/test-pod:/kubeenum

# Execute
kubectl exec -it test-pod -- /kubeenum
```

### Testing on k3s

```bash
# Install k3s
curl -sfL https://get.k3s.io | sh -

# Create test ServiceAccount and pod
kubectl create serviceaccount test-sa -n default
kubectl run test-pod --image=busybox --serviceaccount=test-sa -- sleep 3600

# Copy and run
kubectl cp bin/kubeenum-linux default/test-pod:/kubeenum
kubectl exec -it test-pod -- /kubeenum
```

## 🐛 Troubleshooting

**"Error: Failed to initialize RBAC enumerator"**
- Ensure you're running inside a pod with ServiceAccount mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`

**"Warning: Could not fully detect context"**
- This is a warning, not an error. Enumeration will still work.

**No permissions shown**
- This is expected! The tool shows what you CAN do, not what you can't.

## 📋 Roadmap

### Phase 1 ✅ (Complete)
- SSAR-based RBAC enumeration
- JWT token introspection
- Environment detection (k3s, EKS, GKE, AKS)
- Multi-mode output (red/blue/audit)
- Escalation heuristics

### Phase 2 🚧 (Next)
- Dynamic API discovery (CRDs, aggregated APIs)
- ConfigMap/Secret content analysis
- Capability mapping & attack paths
- Token reuse detection

### Phase 3 📋 (Planned)
- Network & service discovery
- Pod & workload abuse paths
- Node & runtime enumeration (k3s-specific)
- MITRE ATT&CK mapping

## 📝 License

MIT

## 🤝 Contributing

This is a work in progress. Contributions welcome!

## 🙏 Acknowledgments

Inspired by:
- [linpeas](https://github.com/carlospolop/PEASS-ng)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [rbac-police](https://github.com/PaloAltoNetworks/rbac-police)
