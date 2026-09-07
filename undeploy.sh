#!/bin/bash
# Remove the Certificate Roadmap Console from the cluster you are logged into.

set -euo pipefail
NS=cert-discovery-app

if ! command -v oc >/dev/null 2>&1; then
  echo "oc is required."
  exit 1
fi

if ! oc whoami >/dev/null 2>&1; then
  echo "Not logged in. Run oc login first."
  exit 1
fi

echo "==> Deleting namespace $NS (Deployment, Route, PVC, ConfigMap)..."
oc delete namespace "$NS" --ignore-not-found

echo "==> Deleting cluster-scoped RBAC..."
oc delete clusterrolebinding cert-discovery-binding --ignore-not-found
oc delete clusterrole cert-discovery-role --ignore-not-found

echo "==> Removed."
