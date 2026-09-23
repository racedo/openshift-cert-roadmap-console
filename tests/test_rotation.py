"""Regression tests for certificate lifecycle policies (no cluster required)."""
import base64
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from kubernetes import client

os.environ['CERT_DISCOVERY_NO_START'] = '1'
spec = importlib.util.spec_from_file_location('console', Path(__file__).parents[1] / 'Container/app.py')
console = importlib.util.module_from_spec(spec)
with patch('kubernetes.config.load_incluster_config'), patch('kubernetes.config.load_kube_config'):
    spec.loader.exec_module(console)


def cert(subject='root-ca', ca=True, days=3650, key=None):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    dn = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime(2025, 1, 1, tzinfo=timezone.utc)
    crt = (x509.CertificateBuilder().subject_name(dn).issuer_name(dn)
           .public_key(key.public_key()).serial_number(x509.random_serial_number())
           .not_valid_before(now).not_valid_after(now + timedelta(days=days))
           .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
           .sign(key, hashes.SHA256()))
    pem = crt.public_bytes(serialization.Encoding.PEM).decode()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return pem, base64.b64encode(private).decode()


def resource(name, namespace='hcp-example', cn='root-ca', ca=True, days=3650,
             owned=True, field='tls.crt', key_field='tls.key', include_key=True):
    pem, key = cert(cn, ca, days)
    refs = [client.V1OwnerReference(api_version='hypershift.openshift.io/v1beta1',
            kind='HostedControlPlane', name='example', uid='test')] if owned else []
    data = {field: base64.b64encode(pem.encode()).decode()}
    if include_key:
        data[key_field] = key
    obj = client.V1Secret(metadata=client.V1ObjectMeta(name=name, namespace=namespace,
                          owner_references=refs), data=data)
    return obj, pem


def process(obj):
    pem, key, fields = console.listed_cert_pem('secret', obj)
    row = console.process_resource_obj('secret', obj, pem, key, fields)
    assert row is not None
    return row


class RotationTests(unittest.TestCase):
    def test_kube_apiserver_signers_and_recovery_rotate(self):
        for name in console.KUBE_APISERVER_LONG_CYCLE:
            with self.subTest(name=name):
                ns = 'openshift-kube-apiserver' if name.endswith('certkey') else 'openshift-kube-apiserver-operator'
                obj, _ = resource(name, namespace=ns, ca=not name.endswith('certkey'), owned=False)
                row = process(obj)
                self.assertFalse(row['will_not_auto_rotate'])
                self.assertFalse(row['rotation_unverified'])
                self.assertIsNotNone(row['rotate_at'])
                self.assertFalse(console.apply_inventory_filter_flags(row)['filter_1826'])

    def test_recovery_revision_has_no_predicted_date(self):
        obj, _ = resource('localhost-recovery-serving-certkey-235', namespace='openshift-kube-apiserver', ca=False, owned=False)
        row = process(obj)
        self.assertTrue(row['historical_revision'])
        self.assertFalse(row['will_not_auto_rotate'])
        self.assertIsNone(row['rotate_at'])
        self.assertFalse(console.apply_inventory_filter_flags(row)['filter_1990'])

    def test_hypershift_create_once_including_omissions(self):
        for name in ['root-ca', 'etcd-signer', 'cluster-signer-ca', 'system-admin-signer',
                     'capi-webhooks-tls', 'ignition-server-ca-cert']:
            with self.subTest(name=name):
                obj, _ = resource(name)
                if name == 'capi-webhooks-tls':
                    obj.metadata.owner_references = []
                    obj.metadata.annotations = {'hypershift.openshift.io/cluster': 'clusters/example'}
                row = process(obj)
                self.assertTrue(row['will_not_auto_rotate'])
                self.assertEqual(row['no_rotate_reason'], 'hypershift-10y')
                self.assertIsNone(row['rotate_at'])
                self.assertTrue(console.apply_inventory_filter_flags(row)['filter_1826'])

    def test_names_require_provenance_and_ten_year_ca(self):
        for kwargs in [dict(owned=False), dict(ca=False), dict(days=365), dict(include_key=False)]:
            with self.subTest(kwargs=kwargs):
                obj, _ = resource('root-ca', **kwargs)
                self.assertFalse(process(obj)['will_not_auto_rotate'])

    def test_installer_trust_requires_namespace_and_identity(self):
        for ns, name, cn in [('openshift-config', 'admin-kubeconfig-client-ca', 'admin-kubeconfig-signer'),
                             ('openshift-config-managed', 'kubelet-bootstrap-kubeconfig', 'kubelet-bootstrap-kubeconfig-signer')]:
            pem, _ = cert(cn)
            obj = client.V1ConfigMap(metadata=client.V1ObjectMeta(name=name, namespace=ns), data={'ca-bundle.crt': pem})
            fields = ['ca-bundle.crt']
            row = console.process_resource_obj('configmap', obj, pem, False, fields)
            self.assertTrue(row['will_not_auto_rotate'])
            self.assertEqual(row['no_rotate_reason'], 'installer-10y-keyless')
            self.assertIsNone(row['rotate_at'])
            obj.metadata.namespace = 'unrelated'
            row = console.process_resource_obj('configmap', obj, pem, False, fields)
            self.assertFalse(row['will_not_auto_rotate'])

    def test_ca_key_detected_and_proxy_policy_unverified(self):
        obj, _ = resource('cluster-proxy-signer', namespace='multicluster-engine',
                          cn='open-cluster-management:cluster-proxy', owned=False,
                          field='ca.crt', key_field='ca.key')
        row = process(obj)
        self.assertTrue(row['has_private_key'])
        self.assertEqual(row['cert_role'], 'signer')
        self.assertTrue(row['rotation_unverified'])
        self.assertFalse(row['will_not_auto_rotate'])
        self.assertIsNone(row['rotate_at'])
        self.assertNotIn('Auto-Rotated', row['managed_status'])

    def test_mismatched_private_key_does_not_claim_signer(self):
        obj, _ = resource('root-ca')
        _, other_key = cert('other')
        obj.data['tls.key'] = other_key
        row = process(obj)
        self.assertFalse(row['has_private_key'])
        self.assertFalse(row['will_not_auto_rotate'])

    def test_key_match_selects_correct_certificate_in_chain(self):
        obj, pem = resource('root-ca')
        parsed = console.parse_certificate(pem)
        self.assertTrue(console.private_key_matches(parsed, obj.data))
        other, _ = cert('other')
        self.assertFalse(console.private_key_matches(console.parse_certificate(other), obj.data))

    def test_unique_view_joins_only_anchored_fingerprints(self):
        obj, _ = resource('root-ca')
        row = process(obj)
        copy = dict(row, name='copy', has_private_key=False, will_not_auto_rotate=False)
        # A rotating MCS root named root-ca must not acquire a HyperShift verdict.
        mcs, _ = resource('machine-config-server-ca', namespace='openshift-machine-config-operator', owned=False)
        mcs_row = process(mcs)
        mcs_copy = dict(mcs_row, name='root-ca', namespace='kube-system', has_private_key=False)
        leaf, _ = resource('leaf', ca=False)
        leaf_row = process(leaf)
        leaf_row['will_not_auto_rotate'] = True  # Defensive: never count leaves as CAs.
        rows = console.unique_non_rotating_cas([row, copy, mcs_row, mcs_copy, leaf_row])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['fingerprint'], row['fingerprint'])
        self.assertEqual(rows[0]['copy_count'], 2)

    def test_embedded_ca_does_not_inherit_leaf_private_key(self):
        obj, _ = resource('root-ca', include_key=False)
        ca = process(obj)
        ca['will_not_auto_rotate'] = True
        ca['no_rotate_reason'] = 'installer-10y-keyless'
        leaf, _ = resource('leaf', ca=False)
        leaf_row = process(leaf)
        leaf_row['bundle_certs'] += ca['bundle_certs']
        rows = console.unique_non_rotating_cas([ca, leaf_row])
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]['has_private_key'])

    def test_earliest_library_go_trigger(self):
        pem, _ = cert()
        parsed = console.parse_certificate(pem)
        for years, expected in [(9, 8), (7, 7)]:
            row = console.compute_rotate_at(parsed, {'certificates.openshift.io/refresh-period': f'{years}y'}, False)
            self.assertEqual(datetime.fromisoformat(row['rotate_at_iso']), parsed['not_before'] + timedelta(days=expected*365))
        for name in ['ovn-ca', 'signer-ca']:
            row = console.compute_rotate_at(parsed, {}, False, name)
            self.assertEqual(datetime.fromisoformat(row['rotate_at_iso']), parsed['not_before'] + timedelta(days=8*365))

    def test_ten_year_label_is_bounded(self):
        for days in [3649, 3650, 3652]:
            self.assertTrue(console.is_ten_year_lifetime(days))
        for days in [3285, 7300]:
            self.assertFalse(console.is_ten_year_lifetime(days))
        self.assertEqual(console.validity_label(7300), '20y')

    def test_api_and_html_share_verdicts(self):
        obj, _ = resource('ignition-server-ca-cert')
        rows = [process(obj)]
        obj, _ = resource('cluster-proxy-signer', namespace='multicluster-engine',
                          cn='open-cluster-management:cluster-proxy', owned=False,
                          field='ca.crt', key_field='ca.key')
        rows.append(process(obj))
        with patch.object(console.cert_cache, 'get_data', return_value=(rows, 'test-cluster', datetime.now(timezone.utc))):
            c = console.app.test_client()
            response = c.get('/api/certificates')
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertEqual(payload['summary']['will_not_auto_rotate'], 1)
            self.assertEqual(payload['summary']['rotation_unverified'], 1)
            self.assertEqual(len(payload['unique_non_rotating_cas']), 1)
            self.assertEqual(len(payload['rotation_unverified']), 1)
            self.assertEqual(c.get('/api/workboard').status_code, 200)
            html = c.get('/')
            self.assertEqual(html.status_code, 200)
            self.assertIn(b'CA renewal policies unverified', html.data)
            self.assertNotIn(b'no supported rotation', html.data)


if __name__ == '__main__':
    unittest.main()
