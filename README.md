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

# Dump readable resources (secrets, configmaps, pods, services, serviceaccounts)
./bin/kubeenum --dump

# Full dump with complete resource contents (no truncation)
./bin/kubeenum --dump --full

# JSON output for automation
./bin/kubeenum --format json

# Export to file
./bin/kubeenum --dump --output results.json

# Filter by severity (critical, high, interesting, normal)
./bin/kubeenum --severity critical,high

# Summary only (condensed output)
./bin/kubeenum --summary-only

# Export to CSV for spreadsheet analysis
./bin/kubeenum --dump --format csv --output findings.csv

# Generate HTML report
./bin/kubeenum --dump --format html --output report.html

# Blue team mode (detection-focused)
./bin/kubeenum --mode blue --explain

# Audit mode (compliance-focused)
./bin/kubeenum --mode audit

# Verbose mode (see what's being checked)
./bin/kubeenum --verbose

# No color output (for scripts/logs)
./bin/kubeenum --no-color
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

**Namespace Resources (23):**
- Core: secrets, configmaps, pods, services, endpoints, events
- Workloads: deployments, daemonsets, statefulsets, replicasets, jobs, cronjobs
- Templates: podtemplates
- RBAC: roles, rolebindings, serviceaccounts
- Networking: ingresses, networkpolicies
- Storage: persistentvolumeclaims
- Config: limitranges, resourcequotas
- Autoscaling: horizontalpodautoscalers
- Availability: poddisruptionbudgets

**Cluster Resources (13):**
- Core: nodes, namespaces, persistentvolumes
- RBAC: clusterroles, clusterrolebindings
- Storage: storageclasses, volumeattachments
- Scheduling: priorityclasses, runtimeclasses
- Extensions: customresourcedefinitions, apiservices
- Webhooks: mutatingwebhookconfigurations, validatingwebhookconfigurations
- Security: podsecuritypolicies (deprecated)

**Escalation Detection:**
- 🔴 **Critical**: secrets (read), pods (create), clusterroles/clusterrolebindings (create), webhook configs (create)
- 🟠 **High**: serviceaccounts (create), rolebindings (create), customresourcedefinitions (create)
- 🟡 **Interesting**: configmaps (read), serviceaccounts (read), ingresses (create), networkpolicies (create)

**Additional Analysis:**
- **Pod security context analysis** - Detects privileged, hostNetwork, hostPID, hostIPC, dangerous hostPath mounts, dangerous capabilities, runAsRoot, and allowPrivilegeEscalation pods
- **Service Account token extraction** - Extracts and validates SA tokens from secrets
- **High-privilege ServiceAccount detection** - Identifies potentially dangerous ServiceAccount names
- **RBAC analysis** - Finds cluster-admin bindings and wildcard roles
- **Network service discovery** - Analyzes service exposure and network policies
- **Event analysis** (optional, `--events`) - Analyzes security-relevant Kubernetes events
- **NetworkPolicy analysis** (optional, `--network-policies`) - Identifies missing or misconfigured NetworkPolicies

**See [docs/DETECTIONS.md](docs/DETECTIONS.md) for detailed explanations of what each detection means and real-world security impact.**

### Output Formats

kubefall supports multiple output formats for different use cases:

- **Text** (default): Human-readable, color-coded output with severity-based sections
- **JSON**: Machine-readable for automation and integration
- **CSV**: Spreadsheet-friendly for analysis and filtering
- **HTML**: Visual reports with tables and styling
- **Markdown**: Documentation-friendly format

### Output Options

- `--output <file>`: Write results to a file instead of stdout
- `--format <format>`: Choose output format (text, json, csv, html, markdown)
- `--severity <levels>`: Filter by severity (critical,high,interesting,normal, comma-separated)
- `--summary-only`: Show only the summary section (condensed output)
- `--no-color`: Disable ANSI color codes (for scripts and logs)
- `--full`: Print complete resource contents without truncation (use with `--dump`)

## 📖 Example Output

```
=== ENVIRONMENT ===
Type: k3s
Distribution: k3s
Metadata:
  issuer: https://kubernetes.default.svc.cluster.local
  serviceaccount: system:serviceaccount:app-namespace:web-app-sa

=== SERVICE ACCOUNT ===
Current namespace: app-namespace
Token Claims:
  sub: system:serviceaccount:app-namespace:web-app-sa
  aud: [https://kubernetes.default.svc.cluster.local k3s]

=== NAMESPACE RESOURCES ===
-- Namespace: dev-namespace --
configmaps           -> get,list <<! INTERESTING: can read configmaps !>>

-- Namespace: app-namespace --
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
[*] Discovered 8 namespace(s): default, dev-namespace, app-namespace, kube-public, kube-system, web-app, security-system, kube-node-lease

[*] Enumerating namespace resources...
[*] Checking namespace: dev-namespace
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
│   ├── output/            # Output formatters (red/blue/audit modes, export formats)
│   ├── analysis/          # Data extraction and analysis (tokens, pods, RBAC)
│   └── discovery/         # Service and cluster discovery
├── Makefile               # Build automation
└── README.md              # This file
```

## 🛠️ Development

### Project Structure

- `cmd/kubeenum/` - Main CLI application
- `internal/rbac/` - RBAC enumeration engine (SSAR-based)
- `internal/context/` - Environment detection (k3s, EKS, GKE, AKS)
- `internal/output/` - Output formatters (text, JSON, CSV, HTML, Markdown)
- `internal/analysis/` - Data extraction and analysis (tokens, pods, RBAC)
- `internal/discovery/` - Service and cluster discovery

### Adding New Checks

1. Add resource to `internal/rbac/enumerator.go` (nsResources or clusterResources)
2. Add escalation rule to `internal/output/formatter.go` (analyzeResource function)
3. Add extraction logic to `internal/analysis/` if resource contains extractable data
4. Update output formatter if needed

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
- Verbose mode

### Phase 2 ✅ (Complete)
- Resource dumping (`--dump`)
- ConfigMap/Secret content analysis
- Pod security context analysis
- RBAC analysis (cluster-admin bindings, wildcard roles)
- Service Account token extraction
- High-privilege ServiceAccount detection
- Service discovery
- Cluster version discovery

### Phase 3 ✅ (Complete)
- Multiple output formats (JSON, CSV, HTML, Markdown)
- File export (`--output`)
- Severity filtering (`--severity`)
- Summary-only mode (`--summary-only`)
- No-color mode (`--no-color`)
- Separated severity sections (Critical vs High)

### Phase 4 📋 (Planned)
- Dynamic API discovery (CRDs, aggregated APIs)
- Custom resource enumeration
- Event enumeration and analysis
- Network policy analysis
- Ingress TLS certificate extraction
- Persistent volume analysis

### Phase 5 📋 (Planned)
- Capability mapping & attack paths
- Token reuse detection and validation
- ServiceAccount impersonation testing
- Pod escape path detection
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
