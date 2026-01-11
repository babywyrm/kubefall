#!/bin/bash
# Simple test pod setup - no hostPath, uses kubectl cp instead

echo "🚀 Creating simple test pod (no hostPath mount)..."
echo ""

# Delete existing
kubectl delete pod kubefall-test -n default 2>/dev/null
kubectl delete clusterrolebinding kubefall-test-binding 2>/dev/null
kubectl delete clusterrole kubefall-test-role 2>/dev/null
kubectl delete serviceaccount kubefall-test-sa -n default 2>/dev/null

# Create RBAC
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubefall-test-sa
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubefall-test-role
rules:
- apiGroups: [""]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["*"]
  verbs: ["get", "list"]
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubefall-test-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubefall-test-role
subjects:
- kind: ServiceAccount
  name: kubefall-test-sa
  namespace: default
---
apiVersion: v1
kind: Pod
metadata:
  name: kubefall-test
  namespace: default
spec:
  serviceAccountName: kubefall-test-sa
  containers:
  - name: test
    image: ubuntu:22.04
    command: ["/bin/bash", "-c", "sleep infinity"]
  restartPolicy: Never
EOF

echo "⏳ Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/kubefall-test -n default --timeout=60s

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Pod is ready!"
    echo ""
    echo "📋 Next steps:"
    echo ""
    echo "1. Copy kubefall binary (adjust path as needed):"
    echo "   kubectl cp /path/to/kubefall/bin/kubeenum-linux default/kubefall-test:/tmp/kubeenum-linux"
    echo ""
    echo "2. Exec into pod:"
    echo "   kubectl exec -it kubefall-test -n default -- /bin/bash"
    echo ""
    echo "3. Inside pod, install tools:"
    echo "   apt-get update && apt-get install -y curl jq"
    echo ""
    echo "4. Run kubefall:"
    echo "   /tmp/kubeenum-linux --dump"
    echo ""
    echo "💡 Tip: After rebuilding on host, copy again:"
    echo "   kubectl cp /path/to/kubefall/bin/kubeenum-linux default/kubefall-test:/tmp/kubeenum-linux"
else
    echo "❌ Pod failed. Check logs:"
    kubectl logs kubefall-test -n default
fi


