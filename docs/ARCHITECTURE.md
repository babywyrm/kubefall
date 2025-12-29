# kubefall Architecture

## Design Principles

1. **Control-plane agnostic**: Works on any Kubernetes distribution
2. **Environment-aware**: Detects and adapts to k3s, EKS, GKE, AKS
3. **Zero dependencies**: Single binary, no kubectl required
4. **SSAR-based**: Uses SelfSubjectAccessReview (authoritative auth path)
5. **Modular**: Easy to extend with new checks

## Core Components

### 1. RBAC Enumerator (`internal/rbac/`)

**Purpose**: Enumerate permissions using SelfSubjectAccessReview

**Key Functions**:
- `NewEnumerator()` - Initialize with in-cluster credentials
- `Enumerate()` - Run full enumeration
- `checkAccess()` - Test single permission via SSAR
- `getNamespaces()` - Discover accessible namespaces

**Why SSAR?**:
- Works without RBAC read permissions
- Authoritative (uses same path as API server)
- Stealthy (no kubectl required)
- Works on hardened clusters

### 2. Context Detection (`internal/context/`)

**Purpose**: Identify Kubernetes environment and distribution

**Detection Methods**:
1. **File-based**: Check for k3s-specific files
2. **Environment variables**: AWS_REGION, GKE_PROJECT, etc.
3. **JWT analysis**: Parse issuer from token claims
4. **Metadata servers**: IMDS, GKE metadata, Azure identity

**Output**:
```go
type Context struct {
    Type         string            // k3s, eks, gke, aks, vanilla
    Distribution string            // k3s, k8s
    Cloud        string            // aws, gcp, azure, none
    Metadata     map[string]string // Additional context
}
```

### 3. Output Formatter (`internal/output/`)

**Purpose**: Format results for different audiences

**Modes**:
- **Red**: Exploit-focused, highlights escalation paths
- **Blue**: Detection-focused, emphasizes security implications
- **Audit**: Compliance-focused, least-privilege violations

**Features**:
- Color-coded output (green=allowed, red=denied)
- Escalation flags (<<!! ESCALATION !!>>)
- Explanation mode (`--explain`)
- JSON output for automation

### 4. API Discovery (`internal/discovery/` - Phase 3)

**Purpose**: Dynamically discover available APIs

**Process**:
1. GET `/api` - Core APIs
2. GET `/apis` - API groups
3. Parse group versions
4. GET `/apis/{group}/{version}` - Resources
5. Test SSAR against discovered resources

**Benefits**:
- Discovers CRDs automatically
- Finds aggregated APIs
- Works with service meshes
- Cloud-specific resources

### 5. Capability Analysis (`internal/analysis/` - Phase 4)

**Purpose**: Map permissions to capabilities to impact

**Rule Engine**:
```yaml
rules:
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

**Output**:
- Attack paths
- Impact assessment
- Confidence scores
- MITRE technique mapping

## Data Flow

```
┌─────────────┐
│   main.go   │
└──────┬──────┘
       │
       ├──> context.Detect()
       │    └──> Returns: k3s, EKS, GKE, AKS, vanilla
       │
       ├──> rbac.NewEnumerator()
       │    └──> Reads: token, namespace, CA cert
       │
       ├──> enumerator.Enumerate()
       │    ├──> getNamespaces()
       │    ├──> checkAccess() for each resource
       │    └──> dumpResource() if --dump
       │
       └──> formatter.OutputHuman() or OutputJSON()
            └──> analyzeResource() for escalation flags
```

## Extension Points

### Adding New Resources

1. Add to `nsResources` or `clusterResources` in `enumerator.go`
2. Add escalation rule in `formatter.go` or `analysis/`
3. Update output formatter if needed

### Adding New Environment Detection

1. Add detection function in `context/detect.go`
2. Update `Detect()` to call new function
3. Add metadata extraction if needed

### Adding New Escalation Rules

1. Create rule YAML in `rules/escalation.yaml`
2. Implement rule engine in `internal/analysis/`
3. Update formatter to use rules

## Security Considerations

### Stealth
- SSAR calls are logged by audit logs
- Consider rate limiting
- Batch requests where possible

### Error Handling
- Graceful degradation (fallback to current namespace)
- Don't leak sensitive info in errors
- Handle network failures gracefully

### Token Handling
- Never log full tokens
- Redact sensitive data in dumps
- Handle token expiration

## Performance

### Optimization Opportunities
1. **Parallel SSAR checks**: Test multiple resources concurrently
2. **Caching**: Cache namespace list, API discovery
3. **Batching**: Batch SSAR requests where possible
4. **Early exit**: Stop on first critical finding (optional flag)

### Current Limitations
- Sequential SSAR checks (slow for many resources)
- No caching (redundant API calls)
- Full enumeration always (no early exit)

## Testing Strategy

### Unit Tests
- Mock HTTP client for SSAR responses
- Test context detection logic
- Test output formatting

### Integration Tests
- kind/minikube clusters
- Test with different RBAC configurations
- Test environment detection

### Real-World Testing
- EKS clusters
- GKE clusters
- k3s clusters
- Hardened clusters

## Future Enhancements

1. **Out-of-cluster support**: Parse kubeconfig, use different auth
2. **Stealth mode**: Reduce audit log noise
3. **CI/CD integration**: SARIF output, exit codes
4. **Web UI**: Visualize attack paths
5. **API mode**: REST API for automation

