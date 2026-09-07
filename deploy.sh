#!/bin/bash
# Deploy (or refresh) the Certificate Roadmap Console on the cluster you are logged into.
# Requires cluster-admin: creates a ClusterRole and ClusterRoleBinding.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
NS=cert-discovery-app

if ! command -v oc >/dev/null 2>&1; then
  echo "oc is required. Install the OpenShift CLI and try again."
  exit 1
fi

if ! oc whoami >/dev/null 2>&1; then
  echo "Not logged in. Run: oc login --server=<api> --token=<token>"
  echo "Then re-run: ./deploy.sh"
  exit 1
fi

if ! oc auth can-i create clusterroles >/dev/null 2>&1; then
  echo "This deploy needs cluster-admin (it creates a ClusterRole)."
  echo "Logged in as: $(oc whoami)"
  exit 1
fi

echo "==> Cluster: $(oc whoami --show-server 2>/dev/null || echo unknown)"
echo "==> User:    $(oc whoami)"
echo "==> Namespace $NS"

echo "==> Creating namespace..."
oc create namespace "$NS" --dry-run=client -o yaml | oc apply -f -

echo "==> Loading app code into ConfigMap cert-discovery-app-code..."
oc create configmap cert-discovery-app-code \
  --from-file=app.py="$ROOT/Container/app.py" \
  --from-file=requirements.txt="$ROOT/Container/requirements.txt" \
  -n "$NS" \
  --dry-run=client -o yaml | oc apply -f -

echo "==> Applying RBAC, Deployment, Service, Route..."
if ! apply_out=$(oc apply -f "$ROOT/Container/deploy.yaml" 2>&1); then
  echo "$apply_out"
  if echo "$apply_out" | grep -q 'spec is immutable' && \
     oc get pvc cert-discovery-data -n "$NS" >/dev/null 2>&1; then
    echo "==> Existing PVC spec is immutable; continuing."
  else
    exit 1
  fi
else
  echo "$apply_out"
fi

echo "==> Restarting deployment so the pod picks up the ConfigMap..."
oc rollout restart deployment/cert-discovery-app -n "$NS"

echo "==> Waiting for rollout (first start may take a few minutes while pip installs)..."
oc rollout status deployment/cert-discovery-app -n "$NS" --timeout=8m

HOST=$(oc get route cert-discovery-route -n "$NS" -o jsonpath='{.spec.host}')
echo ""
echo "Ready. Open:"
echo "  http://${HOST}/"
echo "  http://${HOST}/healthz"
echo "  http://${HOST}/api/workboard"
echo ""
echo "Use http:// if your browser does not trust the cluster's default router certificate."
echo "To remove the app later: ./undeploy.sh"
