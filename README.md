# Certificate Roadmap Console

This app is for **OpenShift product managers and the engineers they work with**.

It answers two questions on a live cluster:

1. **Why is this on the roadmap?** Each [HPSTRAT-99](https://issues.redhat.com/browse/HPSTRAT-99) Feature (10-year signers, validity caps, RSA 4096, external CA, rotation visibility) is grouped with the certificates on *this* API that still show the gap.
2. **How does that look to users today?** The same page is the inventory: what OpenShift rotates, what it will not, lifetime, issuer, and owning component.

It is not the original [openshift-certificate-analyzer](https://github.com/racedo/openshift-certificate-analyzer) inventory app, and it is not the [missing-owners](https://github.com/racedo/openshift-missing-owners) collector check. Deploy it to its own namespace; it does not replace `cert-discovery-app`.

## Deploy on OpenShift

You need:

- `oc` on your PATH
- Login as **cluster-admin** (the app creates a ClusterRole so it can list secrets and configmaps cluster-wide)
- Network access to pull `registry.redhat.io/ubi9/python-311:latest`

```bash
git clone https://github.com/racedo/openshift-cert-roadmap-console.git
cd openshift-cert-roadmap-console

oc login --server=<api-url> --token=<token>   # or: export KUBECONFIG=/path/to/kubeconfig

./deploy.sh
```

The script prints a URL when the pod is ready. Open it in a browser.

```text
http://cert-roadmap-console-route-cert-roadmap-console.apps.<cluster>/
```

Use **http://** if HTTPS fails certificate verification against the cluster’s default router cert.

First start can take a few minutes: the pod installs Python packages onto a PVC, then serves the UI. Later deploys reuse that install.

Refresh after you edit `Container/app.py`:

```bash
./deploy.sh
```

Remove it (`cert-discovery-app` is left in place):

```bash
./undeploy.sh
```

### What gets created

| Resource | Name |
| --- | --- |
| Namespace | `cert-roadmap-console` |
| Deployment | `cert-roadmap-console` |
| ConfigMap (live Python) | `cert-roadmap-console-code` |
| ClusterRole / Binding | `cert-roadmap-console-role` / `cert-roadmap-console-binding` |
| Route | `cert-roadmap-console-route` |

There is **no image build**. `./deploy.sh` loads `Container/app.py` into a ConfigMap and runs it on UBI Python 3.11.

### Endpoints

| Path | Purpose |
| --- | --- |
| `/` | UI (HPSTRAT-99 table, What to fix, inventory) |
| `/healthz` | Probe |
| `/api/workboard` | JSON of Features vs live examples |
| `/api/certificates` | Full inventory JSON |
| `/api/uncovered` | Missing-owner JSON (the grouped-by-component analogue is on [openshift-missing-owners](https://github.com/racedo/openshift-missing-owners)) |

## What the console maps

Live artifacts on this API are grouped under the [HPSTRAT-99](https://issues.redhat.com/browse/HPSTRAT-99) Features they motivate, including:

- [OCPSTRAT-1826](https://issues.redhat.com/browse/OCPSTRAT-1826) — 10-year / foreverPeriod signers that will not auto-rotate
- [OCPSTRAT-2272](https://issues.redhat.com/browse/OCPSTRAT-2272) / [OCPSTRAT-2273](https://issues.redhat.com/browse/OCPSTRAT-2273) — platform validity still over 5 years, then over 2 years
- [OCPSTRAT-2271](https://issues.redhat.com/browse/OCPSTRAT-2271) / [OCPSTRAT-3050](https://issues.redhat.com/browse/OCPSTRAT-3050) — RSA root CAs still below 4096 bits
- [OCPSTRAT-2029](https://issues.redhat.com/browse/OCPSTRAT-2029) — external CA for platform certificates (capability; not a PEM list)
- [OCPSTRAT-1990](https://issues.redhat.com/browse/OCPSTRAT-1990) — rotation information (items already past predicted rotate-at)

Platform TLS collector rules: [OpenShift TLS registry](https://github.com/openshift/origin/blob/main/tls/README.md).

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `This deploy needs cluster-admin` | Re-login as a user that can create ClusterRoles |
| `ImagePullBackOff` | The node must pull `registry.redhat.io/ubi9/python-311:latest` (cluster pull secret) |
| Pod stuck, PVC already exists | Harmless if you see `spec is immutable`; `./deploy.sh` continues |
| Browser TLS error on the Route | Use the `http://` URL the script prints |
| First rollout timeout | Watch `oc logs -n cert-roadmap-console deploy/cert-roadmap-console` — pip may still be installing |

## License

Apache-2.0
