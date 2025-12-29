# Roadmap

## Phase 1 ✅ Complete

- SSAR-based RBAC enumeration
- JWT token introspection  
- Environment detection (k3s, EKS, GKE, AKS)
- Multi-mode output (red/blue/audit)
- Escalation heuristics
- ConfigMap analysis

## Phase 2 🚧 Next

**Dynamic API Discovery**
- Discover CRDs automatically
- Find aggregated APIs (service meshes, operators)
- Test SSAR against discovered resources

**Structured Resource Extraction**
- Parse ConfigMap/Secret contents
- Extract credentials, tokens, env vars
- Token reuse detection

**Capability Mapping**
- Map permissions → capabilities → impact
- Generate attack paths
- Confidence scoring

## Phase 3 📋 Planned

- Network & service discovery
- Pod & workload abuse paths
- Node & runtime enumeration (k3s-specific)
- MITRE ATT&CK mapping
- Falco rule generation
