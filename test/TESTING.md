# Testing kubefall with KubeGoat

## Option 1: Enhanced Test Pod (Recommended)

Has read/list permissions on all resources + useful tools (curl, jq):

```bash
# From your host, in kubefall directory
bash test-pod-enhanced.sh

# Exec into pod
kubectl exec -it kubefall-test -n default -- /bin/bash

# Run kubefall
/mnt/kubefall/kubefall/bin/kubeenum-linux --dump
```

**What it has:**
- ✅ Read/list permissions on all resources (pods, secrets, serviceaccounts, etc.)
- ✅ curl, jq, ca-certificates
- ✅ ServiceAccount with proper RBAC
- ✅ HostPath mount to kubefall directory

## Option 2: Cluster-Admin Pod (Maximum Testing)

For testing everything including cluster-admin detection:

```bash
kubectl apply -f test-pod-cluster-admin.yaml
kubectl wait --for=condition=Ready pod/kubefall-test-admin -n default
kubectl exec -it kubefall-test-admin -n default -- /bin/bash
```

**Warning:** This gives cluster-admin access - use only in test clusters!

## What to Test

With proper permissions, kubefall should detect:

1. **Pod Security Issues:**
   - Privileged pods
   - HostNetwork pods
   - Dangerous hostPath mounts
   - Dangerous capabilities

2. **Token Extraction:**
   - ServiceAccount tokens from secrets
   - High-privilege ServiceAccounts
   - Token validation

3. **RBAC Analysis:**
   - Cluster-admin bindings
   - Wildcard roles
   - Overprivileged ServiceAccounts

4. **Secret/ConfigMap Data:**
   - Credentials
   - JWTs
   - Base64 encoded data
   - Environment variables

5. **Network Discovery:**
   - Services
   - Ingresses
   - NodePort/LoadBalancer services

## Quick Test Commands

```bash
# Basic enumeration
./kubeenum-linux --dump

# With verbose output (slower)
./kubeenum-linux --dump --verbose

# Full data extraction
./kubeenum-linux --dump --full

# JSON output
./kubeenum-linux --dump --json > results.json

# Test API connectivity
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/pods | jq '.items[].metadata.name'
```

## Iteration Workflow

1. **On host:** Make changes and rebuild
   ```bash
   cd /root/GOAT/kubefall
   make build-linux
   ```

2. **In pod:** Test immediately
   ```bash
   /mnt/kubefall/kubefall/bin/kubeenum-linux --dump
   ```

The binary is shared via hostPath, so rebuilding on host updates it in the pod instantly!

