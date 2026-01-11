# kubefall Development Roadmap

## ✅ Phase 1: Core Enumeration (Complete)
- [x] RBAC permission enumeration using SSAR
- [x] Comprehensive resource coverage (23+ namespace, 14+ cluster resources)
- [x] Environment detection (k3s, EKS, GKE, AKS, vanilla k8s)
- [x] Service discovery
- [x] Cluster version discovery
- [x] Verbose mode for debugging

## ✅ Phase 2: Data Extraction & Analysis (Complete)
- [x] Resource dumping (`--dump`)
- [x] Structured data extraction from ConfigMaps/Secrets
- [x] Pod security context analysis
- [x] RBAC analysis (cluster-admin bindings, wildcard roles)
- [x] Service Account token extraction
- [x] High-privilege ServiceAccount detection

## ✅ Phase 3: Output & Reporting (Complete)
- [x] Multiple output formats (text, JSON, CSV, HTML, Markdown)
- [x] File export (`--output`)
- [x] Severity filtering (`--severity`)
- [x] Summary-only mode (`--summary-only`)
- [x] No-color mode (`--no-color`)
- [x] Separated severity sections (Critical vs High)

## Phase 4: Advanced Enumeration (Planned)
- [ ] Dynamic API discovery (CRDs, aggregated APIs)
- [ ] Custom resource enumeration
- [ ] Event enumeration and analysis
- [ ] Network policy analysis
- [ ] Ingress TLS certificate extraction
- [ ] Persistent volume analysis

## Phase 5: Attack Path Analysis (Planned)
- [ ] Capability mapping (permissions → capabilities)
- [ ] Attack path generation with confidence scoring
- [ ] Token reuse detection and validation
- [ ] ServiceAccount impersonation testing
- [ ] Pod escape path detection

## Phase 6: Detection & Compliance (Planned)
- [ ] MITRE ATT&CK mapping
- [ ] Falco rule generation
- [ ] Compliance check (CIS, NSA, etc.)
- [ ] Baseline comparison
- [ ] Change detection

## Phase 7: Multi-Context Support (Planned)
- [ ] Out-of-cluster enumeration (kubeconfig-based)
- [ ] Node-level enumeration (container escape scenarios)
- [ ] Cloud metadata abuse (IMDS, Workload Identity)
- [ ] Certificate-based authentication
- [ ] Token discovery from various sources

## Implementation Notes

### Completed Features
- All core enumeration features are production-ready
- Output formats support both human-readable and machine-readable formats
- Severity-based filtering allows focused analysis
- Token extraction works with ServiceAccount token secrets
- Pod security analysis (privileged, hostNetwork, hostPID, hostIPC, hostPath, capabilities)
- Event analysis (optional, `--events` flag)
- NetworkPolicy analysis (optional, `--network-policies` flag)
- Reliability features (HTTP timeouts, retry logic, early bailout)

### Next Priorities
1. **Dynamic API Discovery**: Automatically discover CRDs and test permissions
2. **Attack Path Generation**: Map permissions to actual attack capabilities
3. **Cloud Metadata Abuse**: IMDS, Workload Identity enumeration
4. **Out-of-cluster Support**: kubeconfig-based enumeration

### Architecture Decisions
- Modular design allows easy extension
- SSAR-based enumeration is stealthy and doesn't require RBAC read permissions
- Severity levels are clearly separated for future extensibility
- Export formats support integration with other tools
- Optional features (events, network-policies) disabled by default for performance
