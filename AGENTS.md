# Certificate Roadmap Console

PM/engineering view of HPSTRAT-99 Features against live cluster certificates.

| Component | Path | Purpose |
|-----------|------|---------|
| Container app | `Container/app.py` | Flask UI + `/api/workboard` |
| Deployment | `Container/deploy.yaml` | Namespace **`cert-roadmap-console`**, RBAC, Route |

This repo must not deploy `cert-discovery-app` (openshift-certificate-analyzer) or `cert-missing-owners`.

## Common tasks

```bash
./deploy.sh
oc get route cert-roadmap-console-route -n cert-roadmap-console -o jsonpath='http://{.spec.host}'
```

`./deploy.sh` deploys **cert-roadmap-console** only.

User-facing copy: **OpenShift**, never Origin. Do not mention NEC in the UI.

License: Apache-2.0.
