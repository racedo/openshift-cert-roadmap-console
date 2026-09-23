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

- [OCPSTRAT-1826](https://issues.redhat.com/browse/OCPSTRAT-1826) — verified create-once HyperShift CAs and static installer trust certificates
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

## Rotation classification

Ten-year validity does not imply that a certificate never rotates. Kube-apiserver
`foreverPeriod` signers and the recovery serving certificate renew at about eight
years; static-pod revisions are historical copies. MCS and CNO also use automatic
renewal. For library-go signers, the predicted age trigger is the earlier of 80%
of validity and the configured refresh period (including CNO's nine-year refresh).

The non-rotating inventory requires an approximately ten-year CA plus an established
create-once controller: HyperShift ownership metadata and a known CA resource name,
or one of the two dedicated installer trust ConfigMaps in its expected namespace.
CAPI webhook and ignition CAs are included. Secret key detection includes `ca.key`
and checks that the private key matches the selected certificate. Unique CA counts
inherit these object verdicts by fingerprint; embedded CAs never inherit a leaf key.

Other long-lived keyed CAs are labelled **rotation unverified**, excluded from the
confirmed non-rotating count, and given no predicted renewal date. In particular,
local cluster-proxy source retains its existing CA, but its deployed MCE source
revision has not been verified. The API exposes these rows as `rotation_unverified`.
No automatic date is assigned to create-once CAs or historical revisions either.
The legacy `/api/certificates` field `ocpstrat_1826` remains a reference inventory of
the five kube-apiserver names, explicitly marked `rotation_policy: automatic-8y`;
use `will_not_auto_rotate` and `unique_non_rotating_cas` for the actual non-rotating set.

Source evidence:

- [Released kube-apiserver rotation controller](https://github.com/openshift/cluster-kube-apiserver-operator/blob/fb68eab51544f9dffac9916796723f6cee4faf3c/pkg/operator/certrotationcontroller/certrotationcontroller.go)
- [HyperShift create-once CA helper](https://github.com/openshift/hypershift/blob/b6019f3b0bded95641d4f9c15a6253ffc36e2b04/support/certs/tls.go#L448)
- [HyperShift CAPI certificate guard](https://github.com/openshift/hypershift/blob/b6019f3b0bded95641d4f9c15a6253ffc36e2b04/control-plane-operator/controllers/hostedcontrolplane/v2/capi_manager/secret.go)
- [HyperShift ignition CA](https://github.com/openshift/hypershift/blob/b6019f3b0bded95641d4f9c15a6253ffc36e2b04/control-plane-operator/controllers/hostedcontrolplane/v2/ignitionserver/pki.go)
- [CNO library-go 80% trigger](https://github.com/openshift/cluster-network-operator/blob/e20b9cb9a0b3bc293e622ef1caf70a813710ffa8/vendor/github.com/openshift/library-go/pkg/operator/certrotation/signer.go#L168)

Run regression tests without a cluster (after installing `Container/requirements.txt`):

```bash
python -m unittest discover -s tests -v
```
