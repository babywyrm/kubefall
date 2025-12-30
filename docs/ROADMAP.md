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

## Phase 3 📋 Planned - Additional Auth Methods

**Out-of-Cluster Enumeration**
- kubeconfig parsing and support
- Multiple context testing
- Cloud provider auth (gcloud, aws-iam-authenticator, azure)

**Node-Level Access**
- k3s token discovery (`/etc/rancher/k3s/k3s.yaml`, node-token, server-token)
- Generic k8s kubeconfig discovery on nodes
- Stolen ServiceAccount token extraction from volumes

**Cloud Metadata Abuse**
- EKS IMDS access and IRSA
- GKE Workload Identity
- AKS Pod Identity

**Token Theft & Reuse**
- Environment variable scanning
- Log file parsing
- Mounted volume token discovery
- CI/CD artifact analysis

## Phase 4 📋 Future

- Impersonation abuse detection
- Certificate-based authentication
- Bootstrap token validation
- Anonymous access testing
- Network & service discovery
- Pod & workload abuse paths
- MITRE ATT&CK mapping
- Falco rule generation

See `docs/ATTACK_SCENARIOS.md` for detailed attack scenario breakdown.
