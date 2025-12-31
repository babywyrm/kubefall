# Test Pod Setup

Simple setup for testing kubefall in a pod.

## Usage

```bash
# On your host, create the test pod (adjust path as needed)
bash sigh.sh /root/GOAT/kubefall

# Exec into the pod
kubectl exec -it kubefall-test -n default -- /bin/bash

# Run kubefall
/mnt/kubefall/bin/kubeenum-linux --dump
```

## What it provides

- ServiceAccount with read/list permissions on all resources
- Pod with devcontainer base image (has curl and jq pre-installed)
- HostPath mount to kubefall directory for easy iteration

## Iteration Workflow

1. On host: Make changes and rebuild
   ```bash
   cd /root/GOAT/kubefall
   make build-linux
   ```

2. In pod: Test immediately
   ```bash
   /mnt/kubefall/bin/kubeenum-linux --dump
   ```

The binary is shared via hostPath, so rebuilding on host updates it in the pod instantly!
