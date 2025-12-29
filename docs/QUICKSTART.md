# Quick Start Guide

## Building

```bash
# Build for current platform
make build

# Build for Linux (containers/CTFs)
make build-linux
```

Binary will be at `bin/kubeenum` (or `bin/kubeenum-linux`).

## Usage

### Basic Enumeration

```bash
./bin/kubeenum
```

Output:
- Current namespace
- ServiceAccount token claims
- Permissions per namespace
- Cluster-wide permissions
- Escalation flags

### Dump Resources

```bash
./bin/kubeenum --dump
```

Dumps readable resources:
- Secrets
- ConfigMaps
- Pods
- Services

### JSON Output

```bash
./bin/kubeenum --json
```

Machine-readable output for automation.

### Blue Team Mode

```bash
./bin/kubeenum --mode blue --explain
```

Detection-focused output with explanations.

### Audit Mode

```bash
./bin/kubeenum --mode audit
```

Compliance-focused output.

## Testing Locally

### Option 1: kind (Kubernetes in Docker)

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

### Option 2: k3s

```bash
# Install k3s
curl -sfL https://get.k3s.io | sh -

# Create test ServiceAccount
kubectl create serviceaccount test-sa -n default

# Create pod with ServiceAccount
kubectl run test-pod --image=busybox --serviceaccount=test-sa -- sleep 3600

# Copy binary into pod
kubectl cp bin/kubeenum default/test-pod:/kubeenum

# Execute
kubectl exec -it test-pod -- /kubeenum
```

### Option 3: Docker-in-Docker (for testing)

```bash
# Build container image
cat > Dockerfile <<EOF
FROM alpine:latest
COPY bin/kubeenum-linux /kubeenum
RUN chmod +x /kubeenum
ENTRYPOINT ["/kubeenum"]
EOF

docker build -t kubeenum .

# Run in cluster (requires ServiceAccount mounted)
kubectl run kubeenum --image=kubeenum --serviceaccount=test-sa --restart=Never
kubectl logs kubeenum
```

## Expected Output

### Red Mode (Default)

```
=== ENVIRONMENT ===
Type: k3s
Distribution: k3s

=== SERVICE ACCOUNT ===
Current namespace: default
Token Claims:
  sub: system:serviceaccount:default:test-sa
  iss: https://kubernetes.default.svc.cluster.local

=== NAMESPACE RESOURCES ===
-- Namespace: default --
secrets              -> get,list <<!! ESCALATION: can read secrets !!>>
pods                 -> create <<!! ESCALATION: can create pods !!>>
configmaps           -> get,list
services             -> get,list

=== CLUSTER RESOURCES ===
namespaces           -> list
```

### Blue Mode with Explain

```
[WARNING] ServiceAccount can read secrets
  [EXPLAIN] Reading secrets can expose credentials, tokens, and keys for lateral movement
[CRITICAL] ServiceAccount can create pods
  [EXPLAIN] Pod creation with hostPath/privileged can lead to node compromise
```

## Troubleshooting

### "Error: Failed to initialize RBAC enumerator"

**Cause**: Not running in-cluster or missing ServiceAccount tokens.

**Fix**: Ensure you're running inside a pod with ServiceAccount mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`.

### "Warning: Could not fully detect context"

**Cause**: Environment detection failed (not critical).

**Fix**: This is a warning, not an error. Enumeration will still work.

### No permissions shown

**Cause**: ServiceAccount has no permissions.

**Fix**: This is expected! The tool shows what you CAN do, not what you can't.

## Next Steps

1. Test with different ServiceAccounts (low-privilege, high-privilege)
2. Test on different environments (k3s, EKS, GKE)
3. Try `--dump` to see resource contents
4. Try `--json` for automation
5. Review `docs/ROADMAP.md` for upcoming features

