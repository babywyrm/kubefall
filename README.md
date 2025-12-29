# kubefall

A practical, operator-focused Kubernetes enumeration framework that works across all Kubernetes distributions (k3s, EKS, GKE, AKS, vanilla k8s).

## 🎯 Goals

- **🔴 Red team / CTFs** – privilege escalation, lateral movement, data exfil paths
- **🔵 Blue team** – detection, misconfig discovery, blast-radius analysis  
- **🟣 Purple team** – mapping findings → MITRE / OWASP / hardening guidance

Think "linpeas + kube-hunter + custom k3s weirdness", but readable and hackable.

## 🏗️ Architecture

```
kubefall/
├── cmd/kubeenum/          # Main CLI entrypoint
├── internal/
│   ├── rbac/              # RBAC enumeration engine (SSAR-based)
│   ├── context/           # Environment detection (k3s, EKS, GKE, AKS)
│   ├── discovery/         # Dynamic API discovery (CRDs, aggregated APIs)
│   ├── analysis/          # Capability mapping & escalation paths
│   ├── dump/              # Structured resource extraction
│   └── output/            # Output formatters (red/blue/audit modes)
├── rules/                 # Escalation rules & MITRE mappings
└── docs/                  # Attack paths & detection guidance
```

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

# Dump readable resources
./bin/kubeenum --dump

# JSON output
./bin/kubeenum --json

# Blue team mode (detection-focused)
./bin/kubeenum --mode blue --explain

# Audit mode (compliance-focused)
./bin/kubeenum --mode audit
```

## 🔧 Features

### ✅ Phase 1 (Current)

- [x] SSAR-based RBAC enumeration (works without kubectl)
- [x] JWT token introspection
- [x] Namespace discovery with graceful fallback
- [x] Environment detection (k3s, EKS, GKE, AKS)
- [x] Multi-mode output (red/blue/audit)
- [x] Escalation heuristics (secrets, clusterroles, pods)

### 🚧 Phase 2 (In Progress)

- [ ] Dynamic API discovery (CRDs, aggregated APIs)
- [ ] Capability mapping & escalation path analysis
- [ ] Structured resource extraction (secrets, configmaps)
- [ ] Token reuse detection
- [ ] Network & service discovery

### 📋 Phase 3 (Planned)

- [ ] Pod & workload abuse path detection
- [ ] Node & runtime enumeration (k3s-specific)
- [ ] MITRE ATT&CK mapping
- [ ] Falco rule generation
- [ ] CI/CD integration (SARIF output)

## 🧭 How It Works

### Core Principle: SelfSubjectAccessReview (SSAR)

Unlike most enum tools that require RBAC read permissions, `kubefall` uses the Kubernetes authorization API directly. This means:

- ✅ Works without `kubectl`
- ✅ Works without RBAC read permissions
- ✅ Uses the authoritative authorization path
- ✅ Survives hardened clusters

### Environment Detection

The tool automatically detects:
- **k3s**: `/etc/rancher/k3s/k3s.yaml`, embedded etcd
- **EKS**: AWS_REGION, OIDC issuer patterns
- **GKE**: GKE_PROJECT, GKE metadata server
- **AKS**: AZURE_TENANT_ID, federated token files
- **Vanilla k8s**: Default fallback

## 📖 Examples

### Red Team Mode (Default)

```bash
$ ./bin/kubeenum
=== SERVICE ACCOUNT ===
Current namespace: default
Token Claims:
  sub: system:serviceaccount:default:my-sa
  iss: https://kubernetes.default.svc.cluster.local

=== NAMESPACE RESOURCES ===
-- Namespace: default --
secrets              -> get,list <<!! ESCALATION: can read secrets !!>>
pods                 -> create <<!! ESCALATION: can create pods !!>>
```

### Blue Team Mode

```bash
$ ./bin/kubeenum --mode blue --explain
[INFO] Detected environment: EKS
[WARNING] ServiceAccount can read secrets
  [EXPLAIN] Reading secrets can expose credentials, tokens, and keys for lateral movement
[CRITICAL] ServiceAccount can create pods
  [EXPLAIN] Pod creation with hostPath/privileged can lead to node compromise
```

## 🛠️ Development

### Project Structure

- `cmd/kubeenum/` - Main CLI application
- `internal/rbac/` - RBAC enumeration engine
- `internal/context/` - Environment detection
- `internal/output/` - Output formatters

### Adding New Checks

1. Add resource to `internal/rbac/enumerator.go`
2. Add escalation rule to `internal/analysis/`
3. Update output formatter if needed

## 📝 License

MIT

## 🤝 Contributing

This is a work in progress. Contributions welcome!

## 🙏 Acknowledgments

Inspired by:
- [linpeas](https://github.com/carlospolop/PEASS-ng)
- [kube-hunter](https://github.com/aquasecurity/kube-hunter)
- [rbac-police](https://github.com/PaloAltoNetworks/rbac-police)
