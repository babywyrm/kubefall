# kubefall Roadmap

## Phase 1: Foundation ✅ (COMPLETE)

**Status**: Complete

**What we built**:
- ✅ Modular Go architecture (cmd/, internal/)
- ✅ SSAR-based RBAC enumeration engine
- ✅ JWT token introspection
- ✅ Basic environment detection (k3s, EKS, GKE, AKS)
- ✅ Multi-mode output (red/blue/audit)
- ✅ Escalation heuristics (secrets, clusterroles, pods)
- ✅ Resource dumping capability

**Key Files**:
- `cmd/kubeenum/main.go` - CLI entrypoint
- `internal/rbac/enumerator.go` - Core enumeration engine
- `internal/context/detect.go` - Environment detection
- `internal/output/formatter.go` - Output formatting

## Phase 2: Enhanced Context Detection 🚧 (IN PROGRESS)

**Goal**: Make environment detection more robust and informative

**Tasks**:
- [ ] Enhance token-based detection (JWT issuer analysis)
- [ ] Add node label detection (requires API access)
- [ ] Detect runtime (containerd, runc, docker)
- [ ] Detect privilege level (UID, capabilities, writable paths)
- [ ] Add in-cluster vs host vs container detection
- [ ] Cloud-specific metadata extraction (IMDS, metadata servers)

**Why this matters**: Better context = better escalation paths. EKS escalation differs from k3s.

## Phase 3: Dynamic API Discovery 🔜 (NEXT)

**Goal**: Discover all available APIs, not just hardcoded resources

**Tasks**:
- [ ] Implement `/api` and `/apis` discovery
- [ ] Parse API groups, versions, resources
- [ ] Detect namespaced vs cluster-scoped resources
- [ ] Test SSAR against discovered resources
- [ ] Handle CRDs (Custom Resource Definitions)
- [ ] Handle aggregated APIs (service meshes, operators)

**Why this matters**: CRDs and cloud-specific resources are invisible with static lists. This unlocks:
- Service mesh permissions (Istio, Linkerd)
- Operator permissions (ArgoCD, Flux)
- Cloud-specific resources (EKS addons, GKE features)

**Implementation**:
```go
// internal/discovery/api.go
type APIGroup struct {
    Name     string
    Versions []APIVersion
}

type APIVersion struct {
    Version   string
    Resources []Resource
}

type Resource struct {
    Name         string
    Namespaced   bool
    Verbs        []string
}
```

## Phase 4: Capability Mapping & Escalation Analysis 🔜

**Goal**: Answer "What can I do with these permissions?" not just "What permissions do I have?"

**Tasks**:
- [ ] Define escalation rules (YAML-based)
- [ ] Implement rule engine
- [ ] Map permissions → capabilities → impact
- [ ] Generate attack paths
- [ ] Confidence scoring (high/medium/low)

**Example Rule**:
```yaml
- name: PodCreateEscalation
  if:
    resource: pods
    verbs: [create]
  then:
    impact: node-compromise
    confidence: high
    path:
      - "Create privileged pod"
      - "Mount hostPath /"
      - "Escape to node"
```

**Why this matters**: Operators need to know "can I become cluster-admin?" not just "I can create pods."

## Phase 5: Structured Resource Extraction 🔜

**Goal**: Extract actionable intelligence from resources, not just dump JSON

**Tasks**:
- [ ] Parse secrets (extract keys, detect types)
- [ ] Parse configmaps (extract env vars, configs)
- [ ] Parse pods (extract images, security contexts, mounts)
- [ ] Token reuse detection (JWT analysis)
- [ ] Credential extraction (DB passwords, API keys)
- [ ] Image analysis (privileged, hostPath, capabilities)

**Why this matters**: Raw JSON dumps are noisy. Structured extraction finds:
- Reusable tokens
- Database credentials
- Cloud IAM roles
- Registry auth

## Phase 6: Network & Service Discovery 🔜

**Goal**: Map east-west movement paths and exposed services

**Tasks**:
- [ ] Enumerate services (ClusterIP, NodePort, LoadBalancer)
- [ ] Detect internal dashboards (Prometheus, Grafana)
- [ ] Check kubelet access (10250)
- [ ] Map service-to-service paths
- [ ] Detect unauthenticated services

**Why this matters**: Lateral movement requires network access. This maps the attack surface.

## Phase 7: Pod & Workload Abuse Paths 🔜

**Goal**: Detect misconfigurations that enable pod-based escalation

**Tasks**:
- [ ] Check for privileged pod creation
- [ ] Detect hostPath mount abuse
- [ ] Analyze securityContext misconfigs
- [ ] Check for writable kubelet paths
- [ ] Detect service account token mounting

**Why this matters**: Pod creation + misconfig = node escape. This finds those paths.

## Phase 8: Node & Runtime Enumeration (k3s-Specific) 🔜

**Goal**: Exploit k3s-specific shortcuts and configurations

**Tasks**:
- [ ] Check `/etc/rancher/k3s/` for kubeconfigs
- [ ] Access embedded etcd (`/var/lib/rancher/k3s/server/db/state.db`)
- [ ] Check for token reuse (node-token, server-token)
- [ ] Detect k3s-specific RBAC bypasses

**Why this matters**: k3s has unique attack surfaces. CTF-friendly findings.

## Phase 9: Detection-Aware Mode (Blue Team) 🔜

**Goal**: Generate detection signals and Falco rules

**Tasks**:
- [ ] Emit detection signals (kubectl auth can-i spam)
- [ ] Generate Falco rules for detected abuse paths
- [ ] Risk scoring (Low/Medium/High/Game Over)
- [ ] Compliance checks (least privilege violations)

**Why this matters**: Blue teams need actionable detection guidance, not just findings.

## Phase 10: MITRE ATT&CK Mapping 🔜

**Goal**: Map findings to MITRE ATT&CK for Kubernetes

**Tasks**:
- [ ] Create MITRE technique mappings
- [ ] Generate ATT&CK navigator layers
- [ ] Map to OWASP Top 10 for Kubernetes
- [ ] Generate compliance reports

**Why this matters**: Standardized threat modeling and compliance reporting.

## Implementation Strategy

### Incremental Development
1. Build working version for each phase
2. Test in real environments (k3s, EKS, GKE)
3. Iterate based on findings
4. Document attack paths

### Testing Strategy
- Unit tests for each module
- Integration tests with kind/minikube
- Real-world testing on EKS/GKE/k3s
- CTF scenario validation

### Documentation
- Attack path documentation
- Detection guidance
- Cloud-specific notes (EKS.md, GKE.md, k3s.md)

## Questions to Answer

1. **Should we support out-of-cluster enumeration?**
   - Requires kubeconfig parsing
   - Different auth mechanisms
   - Lower priority (in-cluster is primary use case)

2. **How do we handle rate limiting?**
   - SSAR calls can be rate-limited
   - Need exponential backoff
   - Batch requests where possible

3. **What about stealth?**
   - SSAR is logged by default
   - Can we reduce noise?
   - Should we have a "stealth mode"?

4. **CI/CD Integration?**
   - SARIF output for GitHub Security
   - JSON for automation
   - Exit codes for CI pipelines

