#!/usr/bin/env python3
"""
Certificate Roadmap Console

Live cluster evidence for the OpenShift platform certificate roadmap
(HPSTRAT-99 and child OCPSTRAT Features): why those items exist, and how
the gaps currently show to users on this API.
"""

import os
import base64
import hashlib
import json
import re
import time
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from threading import Thread, Lock
from flask import Flask, render_template_string, jsonify
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
try:
    import yaml
except ImportError:
    yaml = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database path (on persistent volume)
DB_PATH = '/data/certificates.db'

# Try to load in-cluster config, fallback to kubeconfig
try:
    config.load_incluster_config()
    logger.info("Loaded in-cluster Kubernetes config")
except:
    try:
        config.load_kube_config()
        logger.info("Loaded kubeconfig from file")
    except:
        logger.warning("Failed to load Kubernetes config")
        pass

# Certificate cache with thread-safe access
class CertificateCache:
    """Thread-safe cache for certificate data with background refresh."""

    def __init__(self, refresh_interval=300):
        self.data = None
        self.cluster_name = 'unknown-cluster'
        self.control_plane_topology = ''
        self.last_update = None
        self.lock = Lock()
        self.refresh_interval = refresh_interval
        self.refresh_thread = None
        logger.info(f"Initialized CertificateCache with {refresh_interval}s refresh interval")

    def start_background_refresh(self):
        """Start background thread to refresh certificate data."""
        def refresh_loop():
            while True:
                try:
                    logger.info("Starting certificate discovery...")
                    start_time = time.time()
                    certificates = discover_certificates()
                    info = self._get_cluster_info()
                    with self.lock:
                        self.data = certificates
                        self.cluster_name = info['name']
                        self.control_plane_topology = info['topology']
                        self.last_update = datetime.now(timezone.utc)

                    elapsed = time.time() - start_time
                    logger.info(f"Certificate discovery completed: {len(certificates)} certificates found in {elapsed:.2f}s")

                    # Save to database if available
                    save_discovery_to_db(certificates, info['name'], elapsed)
                except Exception as e:
                    logger.error(f"Error in background refresh: {e}", exc_info=True)

                time.sleep(self.refresh_interval)

        self.refresh_thread = Thread(target=refresh_loop, daemon=True)
        self.refresh_thread.start()
        logger.info("Background refresh thread started")

    def _get_cluster_info(self):
        """Infrastructure name and control-plane topology (External = hosted guest)."""
        try:
            custom_api = client.CustomObjectsApi()
            infra = custom_api.get_cluster_custom_object('config.openshift.io', 'v1', 'infrastructures', 'cluster')
            status = infra.get('status') or {}
            return {
                'name': status.get('infrastructureName', 'unknown-cluster'),
                'topology': status.get('controlPlaneTopology') or '',
            }
        except Exception as e:
            logger.warning(f"Error getting cluster info: {e}")
            return {'name': 'unknown-cluster', 'topology': ''}

    def _get_cluster_name(self):
        return self._get_cluster_info()['name']

    def get_data(self):
        """Get cached certificate data. Triggers immediate refresh if no data available."""
        with self.lock:
            if self.data is None:
                logger.info("Cache empty, triggering immediate refresh")
                # Release lock during discovery to avoid blocking
                pass

        # If cache is empty, do an immediate refresh (outside lock)
        if self.data is None:
            try:
                logger.info("Performing initial certificate discovery...")
                start_time = time.time()
                certificates = discover_certificates()
                info = self._get_cluster_info()

                with self.lock:
                    self.data = certificates
                    self.cluster_name = info['name']
                    self.control_plane_topology = info['topology']
                    self.last_update = datetime.now(timezone.utc)

                elapsed = time.time() - start_time
                logger.info(f"Initial discovery completed: {len(certificates)} certificates in {elapsed:.2f}s")

                # Save to database if available
                save_discovery_to_db(certificates, info['name'], elapsed)
            except Exception as e:
                logger.error(f"Error during initial refresh: {e}", exc_info=True)
                return [], 'unknown-cluster', None

        with self.lock:
            return self.data, self.cluster_name, self.last_update

# Global cache instance (will be started after functions are defined)
cert_cache = CertificateCache(refresh_interval=14400)  # 4 hours

def init_database():
    """Initialize SQLite database with certificate tracking tables."""
    try:
        # Check if /data directory exists (PV mounted)
        data_dir = os.path.dirname(DB_PATH)
        if not os.path.exists(data_dir):
            logger.warning(f"Data directory {data_dir} does not exist - PV may not be mounted. Database will not be available.")
            return False

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Create certificate_discoveries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificate_discoveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cluster_name TEXT,
                total_certificates INTEGER,
                platform_managed INTEGER,
                user_managed INTEGER,
                auto_rotated INTEGER,
                discovery_duration_seconds REAL
            )
        ''')

        # Create certificates table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS certificates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                discovery_id INTEGER,
                namespace TEXT,
                name TEXT,
                resource_type TEXT,
                fingerprint TEXT,
                issuer TEXT,
                expiry TEXT,
                validity_years INTEGER,
                managed_status TEXT,
                ca_category TEXT,
                FOREIGN KEY (discovery_id) REFERENCES certificate_discoveries(id)
            )
        ''')

        # Create indexes for fast queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_fingerprint ON certificates(fingerprint)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_discovery_id ON certificates(discovery_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_expiry ON certificates(expiry)')

        # Phase 1 columns (existing DBs created before this schema)
        cursor.execute("PRAGMA table_info(certificates)")
        existing_cols = {row[1] for row in cursor.fetchall()}
        for column, typedef in (
            ('cert_role', 'TEXT'),
            ('key_type', 'TEXT'),
            ('key_size', 'INTEGER'),
            ('issuer_origin', 'TEXT'),
            ('tls_registry_status', 'TEXT'),
            ('rotate_at', 'TEXT'),
            ('rotate_at_source', 'TEXT'),
            ('owning_component', 'TEXT'),
        ):
            if column not in existing_cols:
                cursor.execute(f'ALTER TABLE certificates ADD COLUMN {column} {typedef}')

        conn.commit()
        conn.close()

        logger.info(f"Database initialized successfully at {DB_PATH}")
        return True
    except Exception as e:
        logger.error(f"Error initializing database: {e}", exc_info=True)
        return False

def cleanup_old_discoveries(retention_days=30):
    """Delete discovery runs older than retention_days."""
    try:
        if not os.path.exists(DB_PATH):
            return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Calculate cutoff date
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        cutoff_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')

        # Get IDs of discoveries to delete
        cursor.execute('''
            SELECT id FROM certificate_discoveries
            WHERE timestamp < ?
        ''', (cutoff_str,))

        old_discovery_ids = [row[0] for row in cursor.fetchall()]

        if old_discovery_ids:
            # Delete associated certificates first (foreign key constraint)
            cursor.execute(f'''
                DELETE FROM certificates
                WHERE discovery_id IN ({','.join('?' * len(old_discovery_ids))})
            ''', old_discovery_ids)

            deleted_certs = cursor.rowcount

            # Delete old discoveries
            cursor.execute(f'''
                DELETE FROM certificate_discoveries
                WHERE id IN ({','.join('?' * len(old_discovery_ids))})
            ''', old_discovery_ids)

            deleted_discoveries = cursor.rowcount

            conn.commit()
            logger.info(f"Cleaned up {deleted_discoveries} old discoveries (>{retention_days} days) and {deleted_certs} certificate records")

        conn.close()
    except Exception as e:
        logger.error(f"Error cleaning up old discoveries: {e}", exc_info=True)

def save_discovery_to_db(certificates, cluster_name, duration):
    """Save discovery results to database."""
    try:
        # Check if database is available
        if not os.path.exists(DB_PATH):
            logger.debug("Database not available, skipping save")
            return None

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # Calculate statistics
        total = len(certificates)
        platform_managed = len([c for c in certificates if 'Platform-Managed' in c.get('managed_status', '')])
        user_managed = len([c for c in certificates if 'User-Managed' in c.get('managed_status', '')])
        auto_rotated = len([c for c in certificates if 'Auto-Rotated' in c.get('managed_status', '')])

        # Insert discovery run
        cursor.execute('''
            INSERT INTO certificate_discoveries
            (cluster_name, total_certificates, platform_managed, user_managed, auto_rotated, discovery_duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (cluster_name, total, platform_managed, user_managed, auto_rotated, duration))

        discovery_id = cursor.lastrowid

        # Insert certificates
        for cert in certificates:
            cursor.execute('''
                INSERT INTO certificates
                (discovery_id, namespace, name, resource_type, fingerprint, issuer, expiry, validity_years,
                 managed_status, ca_category, cert_role, key_type, key_size, issuer_origin,
                 tls_registry_status, rotate_at, rotate_at_source, owning_component)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                discovery_id,
                cert.get('namespace'),
                cert.get('name'),
                cert.get('resource_type'),
                cert.get('fingerprint'),
                cert.get('issuer'),
                cert.get('expiry'),
                cert.get('validity_years'),
                cert.get('managed_status'),
                cert.get('ca_category'),
                cert.get('cert_role'),
                cert.get('key_type'),
                cert.get('key_size'),
                cert.get('issuer_origin'),
                cert.get('tls_registry_status'),
                cert.get('rotate_at'),
                cert.get('rotate_at_source'),
                cert.get('owning_component'),
            ))

        conn.commit()
        conn.close()

        logger.info(f"Saved discovery #{discovery_id} to database: {total} certificates")

        # Cleanup old discoveries (keep last 30 days)
        cleanup_old_discoveries(retention_days=30)

        return discovery_id
    except Exception as e:
        logger.error(f"Error saving discovery to database: {e}", exc_info=True)
        return None

# kube-apiserver operator foreverPeriod secrets (OCPSTRAT-1826).
# certrotationcontroller.go: Refresh at 80% of 10y is 8y, "we effectively do not rotate".
# ShortCertRotation skips ValidityDuration == "10y". Manual rotation is the Feature, not shipped.
OCPSTRAT_1826_NO_ROTATE = frozenset({
    'localhost-serving-signer',
    'service-network-serving-signer',
    'loadbalancer-serving-signer',
    'localhost-recovery-serving-signer',
    'localhost-recovery-serving-certkey',
})
# Installer ValidityTenYears signers: created once, not library-go certrotation.
INSTALLER_NO_ROTATE = frozenset({
    'admin-kubeconfig-signer',
    'kubelet-bootstrap-kubeconfig-signer',
})
INSTALLER_KEYLESS_CA_CN = frozenset({
    'admin-kubeconfig-signer',
    'kubelet-bootstrap-kubeconfig-signer',
})
INSTALLER_KEYLESS_NOTES = {
    'revocable-bootstrap': (
        'Installer leftover client CA; no private key. Deleting this ConfigMap '
        'revokes installer master-bootstrap client certs. New workers already use '
        'the node-bootstrapper token. Do not delete while control-plane nodes still '
        'use the original cert-based /etc/kubernetes/kubeconfig.'
    ),
    'keep-recovery': (
        'Installer leftover client CA; no private key. Keep this: it authenticates '
        'the original admin kubeconfig. Removing it invalidates that kubeconfig.'
    ),
}
# OpenShift 10y = 10 * 365 * 24h (not calendar years). Days remaining is not lifetime.
TEN_YEAR_DAYS = 3650
# Floor so 3649d leap/day rounding still counts. Rotating signers that reuse
# HyperShift names are 30d, 60d, 1y, or 5y — well below this.
TEN_YEAR_MIN_DAYS = TEN_YEAR_DAYS - 365
# HPSTRAT-99 / OCPSTRAT-2272 / 2273 policy: OpenShift days, not calendar years.
POLICY_5Y_DAYS = 5 * 365
POLICY_2Y_DAYS = 2 * 365
LIST_PAGE_SIZE = 500
MAX_PARSE_CERTS_PER_PEM = 8
SECRET_CERT_FIELDS = ('tls.crt', 'ca.crt', 'cert.crt')
SECRET_KEY_FIELDS = ('tls.key', 'cert.key')
# library-go InspectConfigMap CA bundle keys (origin TLS registry).
ORIGIN_CA_BUNDLE_KEYS = (
    'ca-bundle.crt',
    'client-ca-file',
    'client-ca.crt',
    'metrics-ca-bundle.crt',
    'requestheader-client-ca-file',
    'image-registry.openshift-image-registry.svc..5000',
    'image-registry.openshift-image-registry.svc.cluster.local..5000',
)
CM_CERT_FIELDS = ORIGIN_CA_BUNDLE_KEYS + ('tls.crt', 'ca.crt', 'cert.crt')
# Grandfathered OpenShift TLS-registry ownership-violations.json (remove-only). Same 5 as
# tls/ownership/ownership.md Missing Owners.
ORIGIN_OWNERSHIP_VIOLATIONS = (
    ('certificate', 'openshift-ingress', 'router-certs-default'),
    ('certificate', 'openshift-ingress-operator', 'router-ca'),
    ('ca-bundle', 'kube-system', 'extension-apiserver-authentication'),
    ('ca-bundle', 'openshift-config-managed', 'default-ingress-cert'),
    ('ca-bundle', 'openshift-console', 'default-ingress-cert'),
)
ORIGIN_OWNERSHIP_VIOLATION_KEYS = frozenset(
    (ns, name) for _kind, ns, name in ORIGIN_OWNERSHIP_VIOLATIONS
)
# CNO OperatorPKI (ovn-ca, signer-ca): 10y validity, Refresh after 9y — they DO auto-rotate.
CNO_OPERATOR_PKI_SIGNERS = frozenset({
    'ovn-ca',
    'signer-ca',
})
# HyperShift CPO ReconcileSelfSignedCA: 10y, no-op if the secret already has a CA.
# Only flag when the secret still holds a private key (management cluster), not guest copies.
HYPERSHIFT_TEN_YEAR_CAS = frozenset({
    'root-ca',
    'etcd-signer',
    'etcd-metrics-signer',
    'konnectivity-signer',
    'aggregator-client-signer',
    'kas-aggregator-client-signer',
    'kube-control-plane-signer',
    'kube-apiserver-to-kubelet-signer',
    'system-admin-signer',
    'hcco-signer',
    'kube-csr-signer',
    'cluster-signer-ca',
    'csr-signer',
})
# CNs of CAs that do not auto-rotate (OCPSTRAT-1826, installer, HyperShift ReconcileSelfSignedCA).
# Match the PEM subject, not only the secret name — hosted guests often store these as copies.
KNOWN_NON_ROTATE_CN = frozenset({
    'kube-apiserver-localhost-signer',
    'kube-apiserver-service-network-signer',
    'kube-apiserver-lb-signer',
    'localhost-recovery-serving-signer',
    'kubelet-bootstrap-kubeconfig-signer',
    'admin-kubeconfig-signer',
    'kube-apiserver-to-kubelet-signer',
    'kube-csr-signer',
    'kube-control-plane-signer',
    'root-ca',
    'etcd-signer',
    'etcd-metrics-signer',
    'konnectivity-signer',
    'aggregator-signer',
    'hcco-signer',
})
OCPSTRAT_1826_EXPECTED = (
    'localhost-serving-signer',
    'service-network-serving-signer',
    'loadbalancer-serving-signer',
    'localhost-recovery-serving-signer',
    'localhost-recovery-serving-certkey',
)
FOREVER_PERIOD_SIGNERS = OCPSTRAT_1826_NO_ROTATE - {'localhost-recovery-serving-certkey'}
FOREVER_PERIOD_LEAFS = frozenset({'localhost-recovery-serving-certkey'})
# Static-pod revisions of the recovery leaf (localhost-recovery-serving-certkey-2, …).
FOREVER_PERIOD_CERTKEY_RE = re.compile(r'^localhost-recovery-serving-certkey(?:-\d+)?$')


def is_forever_period_leaf_name(name):
    if not name:
        return False
    if name in FOREVER_PERIOD_LEAFS:
        return True
    return bool(FOREVER_PERIOD_CERTKEY_RE.match(name))


def is_forever_period_name(name):
    """kube-apiserver-operator Validity: foreverPeriod artifacts (OCPSTRAT-1826)."""
    if not name:
        return False
    if name in FOREVER_PERIOD_SIGNERS:
        return True
    return is_forever_period_leaf_name(name)


# Secrets ShortCertRotation does not shorten (payload test leftovers).
# foreverPeriod is classified separately via is_forever_period_name.
# 10y: ValidityDuration == "10y" skip. Namespace: operators that never wired the gate.
SCR_UNSHORTENED_10Y_SECRETS = frozenset({
    ('openshift-machine-config-operator', 'machine-config-server-ca'),
    ('openshift-machine-config-operator', 'machine-config-server-tls'),
    ('openshift-ovn-kubernetes', 'ovn-ca'),
    ('openshift-ovn-kubernetes', 'signer-ca'),
    ('openshift-network-node-identity', 'network-node-identity-ca'),
})
SCR_UNSHORTENED_NAMESPACE_SECRETS = frozenset({
    ('openshift-ingress-operator', 'router-ca'),
    ('openshift-ingress', 'router-certs-default'),
    ('openshift-operator-lifecycle-manager', 'packageserver-service-cert'),
})
# Live-check rows for "which certs are NOT shortened by ShortCertRotation?"
SCR_UNSHORTENED_EXPECTED = (
    ('openshift-kube-apiserver-operator', 'localhost-serving-signer', 'foreverPeriod'),
    ('openshift-kube-apiserver-operator', 'service-network-serving-signer', 'foreverPeriod'),
    ('openshift-kube-apiserver-operator', 'loadbalancer-serving-signer', 'foreverPeriod'),
    ('openshift-kube-apiserver-operator', 'localhost-recovery-serving-signer', 'foreverPeriod'),
    ('openshift-kube-apiserver', 'localhost-recovery-serving-certkey', 'foreverPeriod'),
    ('openshift-machine-config-operator', 'machine-config-server-ca', '10y'),
    ('openshift-machine-config-operator', 'machine-config-server-tls', '10y'),
    ('openshift-ovn-kubernetes', 'ovn-ca', '10y'),
    ('openshift-ovn-kubernetes', 'signer-ca', '10y'),
    ('openshift-network-node-identity', 'network-node-identity-ca', '10y'),
    ('openshift-ingress-operator', 'router-ca', 'namespace'),
    ('openshift-ingress', 'router-certs-default', 'namespace'),
    ('openshift-operator-lifecycle-manager', 'packageserver-service-cert', 'namespace'),
)
SCR_SKIP_LABELS = {
    'foreverPeriod': (
        'foreverPeriod — ShortCertRotation does not shorten 10y (OCPSTRAT-1826)'
    ),
    '10y': (
        '10y ValidityDuration — ShortCertRotation does not shorten this '
        '(payload test skip). OVN/NNI CAs still refresh at 9y; MCS at 8y.'
    ),
    'namespace': (
        'Owning operator does not use ShortCertRotation '
        '(ingress / OLM; payload-test ignored namespace).'
    ),
}


def classify_short_cert_rotation_skip(name, namespace, resource_type, validity_days,
                                      injected_ca_copy=False):
    """Which payload-test skip (if any) leaves this secret long when SCR is on."""
    if injected_ca_copy:
        return ''
    if is_forever_period_name(name):
        return 'foreverPeriod' if is_ten_year_lifetime(validity_days) else ''
    if resource_type != 'secret':
        return ''
    key = (namespace, name)
    if key in SCR_UNSHORTENED_10Y_SECRETS:
        return '10y' if is_ten_year_lifetime(validity_days) else ''
    if key in SCR_UNSHORTENED_NAMESPACE_SECRETS:
        # Typical 2y. Hour-scale lifetime means the operator started honoring the gate.
        return 'namespace' if (validity_days or 0) >= 7 else ''
    return ''


INJECTED_CA_BUNDLE_NAMES = frozenset({
    'kube-root-ca.crt',
    'openshift-service-ca.crt',
    'service-ca.crt',
})
# Operator-reconciled copies of a platform bundle, often in non-openshift-* namespaces
# (MCE/assisted, HyperShift control-plane). Not something an admin rotates by hand.
OPERATOR_COPIED_BUNDLE_NAMES = frozenset({
    'default-ingress-cert',
    'assisted-trusted-ca-bundle',
    'openshift-config-managed-trusted-ca-bundle',
    'trusted-ca-bundle',
})
HYPERSHIFT_REFERENCED_PREFIX = 'referenced-resource.hypershift.openshift.io/'
CA_BUNDLE_FIELDS = frozenset({'ca-bundle.crt', 'ca.crt'})
PLATFORM_ISSUER_MARKERS = (
    'openshift', 'kubernetes', 'etcd', 'kube-apiserver', 'kube-controller-manager',
    'kube-csr-signer', 'cluster-manager-webhook', 'konnectivity', 'ovn',
    'ingress-operator', 'olm-selfsigned', 'service-ca', 'openshift-service-serving',
    'root-ca', 'kubelet', 'aggregator-signer', 'machine-config', 'hostedcp',
    'cluster-proxy', 'open-cluster-management',
)
EXTERNAL_ISSUER_MARKERS = (
    "let's encrypt", 'letsencrypt', 'digicert', 'sectigo', 'globalsign',
    'comodo', 'geotrust', 'thawte', 'godaddy', 'amazon', 'amazonaws',
    'google trust', 'microsoft', 'entrust', 'usertrust', 'pkiaccv', 'accvraiz',
)


def _as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def extract_first_pem(cert_data):
    """Return the first PEM certificate in a bundle, or None."""
    if not cert_data:
        return None
    if isinstance(cert_data, bytes):
        cert_data = cert_data.decode('utf-8', errors='ignore')
    if '-----BEGIN CERTIFICATE-----' not in cert_data:
        return cert_data
    start_idx = cert_data.find('-----BEGIN CERTIFICATE-----')
    end_idx = cert_data.find('-----END CERTIFICATE-----', start_idx)
    if end_idx == -1:
        return None
    end_idx += len('-----END CERTIFICATE-----')
    return cert_data[start_idx:end_idx]


def parse_openshift_duration(value):
    """Parse TLS-registry refresh-period values such as 15d, 2y, 24h, 2160h0m0s."""
    if not value:
        return None
    total = timedelta(0)
    matches = re.findall(r'(\d+)([smhdwy])', value.strip().lower())
    if not matches:
        return None
    for amount, unit in matches:
        n = int(amount)
        if unit == 's':
            total += timedelta(seconds=n)
        elif unit == 'm':
            total += timedelta(minutes=n)
        elif unit == 'h':
            total += timedelta(hours=n)
        elif unit == 'd':
            total += timedelta(days=n)
        elif unit == 'w':
            total += timedelta(weeks=n)
        elif unit == 'y':
            total += timedelta(days=n * 365)
    return total if total.total_seconds() > 0 else None


def public_key_info(cert):
    """Return (key_type, key_size_bits) for an x509 certificate."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return 'RSA', pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return 'ECDSA', pub.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return 'Ed25519', 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return 'Ed448', 456
    if isinstance(pub, dsa.DSAPublicKey):
        return 'DSA', pub.key_size
    return type(pub).__name__, None


def parse_certificate(cert_data):
    """Parse the first PEM in cert_data. Returns a dict or None."""
    pem = extract_first_pem(cert_data)
    if not pem:
        return None
    try:
        cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    except Exception as e:
        logger.debug(f"Error parsing certificate: {e}")
        return None

    not_before = _as_utc(cert.not_valid_before)
    not_after = _as_utc(cert.not_valid_after)
    now = datetime.now(timezone.utc)
    validity = not_after - not_before
    key_type, key_size = public_key_info(cert)
    is_ca = False
    try:
        is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        pass

    return {
        'fingerprint': cert.fingerprint(hashes.SHA256()).hex().upper(),
        'issuer': cert.issuer.rfc4514_string(),
        'subject': cert.subject.rfc4514_string(),
        'not_before': not_before,
        'not_after': not_after,
        'issued': not_before.strftime('%Y-%m-%d'),
        'expires': not_after.strftime('%Y-%m-%d'),
        'validity': validity,
        'validity_days': validity.days,
        'days_remaining': (not_after - now).days,
        'expiry': not_after.strftime('%b %d %H:%M:%S %Y GMT'),
        'key_type': key_type,
        'key_size': key_size,
        'is_ca': is_ca,
        'is_self_signed': cert.issuer == cert.subject,
    }


def parse_pem_certs(pem, max_certs=MAX_PARSE_CERTS_PER_PEM):
    """Parse certificates in a PEM bundle, capped so huge trust bundles do not explode CPU."""
    certs = []
    if not pem or 'BEGIN CERTIFICATE' not in pem:
        return certs
    for chunk in pem.split('-----END CERTIFICATE-----'):
        if '-----BEGIN CERTIFICATE-----' not in chunk:
            continue
        parsed = parse_certificate(chunk + '-----END CERTIFICATE-----\n')
        if parsed:
            certs.append(parsed)
        if max_certs and len(certs) >= max_certs:
            break
    return certs


def select_primary_cert(name, certs):
    """Prefer the cert whose subject matches the secret name; else the first."""
    if not certs:
        return None
    name_l = (name or '').lower()
    for cert in certs:
        if name_l and name_l in (cert.get('subject') or '').lower():
            return cert
    return certs[0]


def is_ten_year_lifetime(validity_days):
    """True for OpenShift ~10-year CAs (typically 3650 days).

    HyperShift ReconcileSelfSignedCA uses the same secret names as rotating
    library-go signers (aggregator-client-signer, csr-signer,
    kube-control-plane-signer, etcd-signer, kube-apiserver-to-kubelet-signer).
    Those rotating certs are 30d–5y; only a ~10y lifetime is the no-rotate gap.
    """
    return (validity_days or 0) >= TEN_YEAR_MIN_DAYS


def validity_label(days):
    """Lifetime label from not_after - not_before, not from days remaining."""
    if days is None or days < 0:
        return ''
    if is_ten_year_lifetime(days):
        return '10y'
    if days >= 700:
        return f'{round(days / 365)}y'
    if days >= 330:
        return '1y'
    return f'{days}d'


def subject_cn(subject):
    for part in (subject or '').split(','):
        part = part.strip()
        if part[:3].upper() == 'CN=':
            return part[3:]
    return ''


def cert_public_fields(parsed):
    """JSON-safe fields for one PEM certificate (no datetime objects)."""
    days = parsed.get('validity_days')
    return {
        'fingerprint': parsed.get('fingerprint'),
        'subject': parsed.get('subject'),
        'issuer': parsed.get('issuer'),
        'issued': parsed.get('issued'),
        'expires': parsed.get('expires'),
        'validity_days': days,
        'validity_label': validity_label(days),
        'days_remaining': parsed.get('days_remaining'),
        'is_ca': parsed.get('is_ca'),
        'is_self_signed': parsed.get('is_self_signed'),
        'cn': subject_cn(parsed.get('subject')),
    }


def non_rotate_reason_for_cert(name, parsed):
    """Return reason if this PEM is a 10-year CA that OpenShift will not auto-rotate."""
    if not parsed or not is_ten_year_lifetime(parsed.get('validity_days')):
        return ''
    if name in CNO_OPERATOR_PKI_SIGNERS:
        return ''
    cn = subject_cn(parsed.get('subject'))
    if name in OCPSTRAT_1826_NO_ROTATE or cn in {
        'kube-apiserver-localhost-signer',
        'kube-apiserver-service-network-signer',
        'kube-apiserver-lb-signer',
        'localhost-recovery-serving-signer',
    }:
        return 'ocpstrat-1826'
    if name in INSTALLER_NO_ROTATE or cn in {
        'admin-kubeconfig-signer',
        'kubelet-bootstrap-kubeconfig-signer',
    }:
        return 'installer-10y'
    if (
        name in HYPERSHIFT_TEN_YEAR_CAS
        or cn in KNOWN_NON_ROTATE_CN
    ):
        return 'hypershift-10y'
    return ''


def compute_rotate_at(parsed, annotations, will_not_rotate, name=None):
    """Rotate-at from refresh-period annotation, CNO 9y refresh, else library-go 80%."""
    not_before = parsed['not_before']
    not_after = parsed['not_after']
    validity = parsed['validity']
    rotate_80 = not_after - (validity / 5)
    refresh_raw = (annotations or {}).get('certificates.openshift.io/refresh-period', '')
    period = parse_openshift_duration(refresh_raw)
    if period:
        rotate_at = not_before + period
        source = 'refresh-period'
    elif name in CNO_OPERATOR_PKI_SIGNERS:
        rotate_at = not_before + timedelta(days=9 * 365)
        source = 'cno-9y'
    else:
        rotate_at = rotate_80
        source = '80-percent'
    now = datetime.now(timezone.utc)
    return {
        'rotate_at': rotate_at.strftime('%Y-%m-%d'),
        'rotate_at_iso': rotate_at.isoformat(),
        'rotate_at_source': source,
        'refresh_period': refresh_raw,
        'days_until_rotate': (rotate_at - now).days,
        'rotation_mode': 'manual' if will_not_rotate else source,
    }


def determine_cert_role(resource_type, name, data_fields, annotations, labels, parsed,
                        has_private_key=False, pem_cert_count=1):
    """Classify signer vs leaf vs ca-bundle."""
    managed_type = (
        (labels or {}).get('auth.openshift.io/managed-certificate-type')
        or (annotations or {}).get('auth.openshift.io/managed-certificate-type')
        or ''
    ).lower()
    fields = {f.strip() for f in (data_fields or '').split(',') if f.strip()}
    if managed_type == 'signer' or name in FOREVER_PERIOD_SIGNERS:
        return 'signer'
    if managed_type == 'target' or is_forever_period_leaf_name(name):
        return 'leaf'
    if name in INJECTED_CA_BUNDLE_NAMES:
        return 'ca-bundle'
    # Guest copies of HyperShift CAs: tls.crt only, often a multi-cert bundle.
    if resource_type == 'secret' and not has_private_key and (
        pem_cert_count > 1 or (name or '').endswith('-signer') or name in HYPERSHIFT_TEN_YEAR_CAS
    ):
        return 'ca-bundle'
    if 'tls.crt' not in fields and fields.intersection({'ca-bundle.crt', 'ca.crt'}):
        return 'ca-bundle'
    if resource_type == 'configmap' and fields and fields.issubset(CA_BUNDLE_FIELDS):
        return 'ca-bundle'
    if parsed.get('is_ca') or name.endswith('-signer') or 'serving-signer' in name:
        return 'signer'
    return 'leaf'


def is_tls_registry_namespace(namespace):
    """Match OpenShift TLS-registry platform namespaces (certgraphanalysis)."""
    if namespace.startswith('openshift-') or namespace.startswith('kubernetes-'):
        return True
    return namespace in ('openshift', 'default', 'kube-system', 'kube-public', 'kubernetes')


def is_revisioned_tls_object(obj):
    """OpenShift TLS registry SkipRevisioned: owner ref name starts with revision-status-."""
    for ref in getattr(obj.metadata, 'owner_references', None) or []:
        if str(getattr(ref, 'name', '') or '').startswith('revision-status-'):
            return True
    return False


def is_monitoring_hashed_tls_object(obj):
    """OpenShift TLS registry SkipHashed: monitoring.openshift.io/hash label."""
    labels = obj.metadata.labels or {}
    return 'monitoring.openshift.io/hash' in labels


def decode_secret_data_value(value):
    if value is None:
        return ''
    try:
        if isinstance(value, bytes):
            raw = value
        else:
            raw = base64.b64decode(value)
        return raw.decode('utf-8', errors='ignore')
    except Exception:
        return value.decode('utf-8', errors='ignore') if isinstance(value, bytes) else str(value)


def parse_kubeconfig_pems(text):
    """Client-cert and cluster-CA PEMs from a kubeconfig (Inspect*AsKubeConfig)."""
    if not text or 'clusters:' not in text:
        return None, None
    if yaml is None:
        return None, None
    try:
        cfg = yaml.safe_load(text)
    except Exception:
        return None, None
    if not isinstance(cfg, dict):
        return None, None
    if not cfg.get('clusters') and not cfg.get('users'):
        return None, None
    client_pems = []
    ca_pems = []
    for user in cfg.get('users') or []:
        if not isinstance(user, dict):
            continue
        b64 = ((user.get('user') or {}).get('client-certificate-data'))
        if not b64:
            continue
        try:
            client_pems.append(base64.b64decode(b64).decode('utf-8', errors='ignore'))
        except Exception:
            pass
    for cluster in cfg.get('clusters') or []:
        if not isinstance(cluster, dict):
            continue
        b64 = ((cluster.get('cluster') or {}).get('certificate-authority-data'))
        if not b64:
            continue
        try:
            ca_pems.append(base64.b64decode(b64).decode('utf-8', errors='ignore'))
        except Exception:
            pass
    return (
        '\n'.join(client_pems) if client_pems else None,
        '\n'.join(ca_pems) if ca_pems else None,
    )


def kubeconfig_pems_from_secret(obj):
    skip_keys = {'tls.crt', 'tls.key', 'cert.key', 'ca.crt'}
    for key, value in (obj.data or {}).items():
        if key in skip_keys:
            continue
        text = decode_secret_data_value(value)
        if len(text) > 300000:
            continue
        client_pem, ca_pem = parse_kubeconfig_pems(text)
        if client_pem or ca_pem:
            return client_pem, ca_pem
    return None, None


def kubeconfig_pems_from_configmap(obj):
    for _key, value in (obj.data or {}).items():
        if not value or not isinstance(value, str) or len(value) > 300000:
            continue
        client_pem, ca_pem = parse_kubeconfig_pems(value)
        if client_pem or ca_pem:
            return client_pem, ca_pem
    return None, None


def origin_registry_kind(resource_type, obj):
    """How the OpenShift TLS collector would classify this object, or '' if it would skip it.

    GatherCertsFromPlatformNamespaces: InspectSecret (tls.crt, else kubeconfig
    client cert) / InspectConfigMap (kubeconfig CA, else fixed CA-bundle keys),
    then SkipRevisioned + SkipHashed.
    """
    if is_revisioned_tls_object(obj) or is_monitoring_hashed_tls_object(obj):
        return ''
    data = obj.data or {}
    keys = set(data.keys())
    if resource_type == 'secret':
        if 'tls.crt' in keys:
            return 'certificate'
        client_pem, _ca = kubeconfig_pems_from_secret(obj)
        if client_pem:
            return 'certificate'
        return ''
    _client, ca_pem = kubeconfig_pems_from_configmap(obj)
    if ca_pem:
        return 'ca-bundle'
    if any(k in keys for k in ORIGIN_CA_BUNDLE_KEYS):
        return 'ca-bundle'
    return ''


def determine_tls_registry_status(namespace, owning_component, injected_ca_copy,
                                  origin_kind=''):
    """registered / uncovered / injected-copy / out-of-registry / not-origin-artifact.

    uncovered is the missing-owner requirement: an in-cluster TLS artifact
    the OpenShift collector accepts, in a platform namespace, with empty openshift.io/owning-component.
    """
    if injected_ca_copy:
        return 'injected-copy'
    if not is_tls_registry_namespace(namespace):
        return 'out-of-registry'
    if not origin_kind:
        return 'not-origin-artifact'
    if owning_component:
        return 'registered'
    return 'uncovered'


def collector_owner_skip_reason(resource_type, obj, namespace, name):
    """Why owning-component is not required, or '' if the collector requires it."""
    ns = namespace or ''
    if name in INJECTED_CA_BUNDLE_NAMES:
        return (
            f'Injected CA replica ({name}); collector skips kube-root-ca.crt / service-ca copies'
        )
    if not is_tls_registry_namespace(ns):
        return (
            f'{ns} is not an OpenShift platform namespace '
            f'(openshift-*, kubernetes-*, kube-system, …)'
        )
    if is_revisioned_tls_object(obj):
        return 'Skipped: owner reference is revision-status-*'
    if is_monitoring_hashed_tls_object(obj):
        return 'Skipped: label monitoring.openshift.io/hash'
    if origin_registry_kind(resource_type, obj):
        return ''
    if resource_type == 'secret':
        return 'Not InspectSecret: no tls.crt or kubeconfig client cert'
    return 'Not InspectConfigMap: no CA-bundle key or kubeconfig CA'


def missing_owner_why_lines(namespace, resource_type, origin_kind, data_fields, known):
    """Why the OpenShift TLS collector puts this object in Missing owners (four checks)."""
    ns = namespace or ''
    fields = data_fields or ''
    if ns.startswith('openshift-'):
        ns_why = f'{ns} matches openshift-* (OpenShift platform namespace)'
    elif ns.startswith('kubernetes-'):
        ns_why = f'{ns} matches kubernetes-* (OpenShift platform namespace)'
    else:
        ns_why = f'{ns} is a well-known OpenShift platform namespace'
    if origin_kind == 'certificate':
        if resource_type == 'secret' and 'tls.crt' in fields:
            inspect = 'OpenShift InspectSecret: tls.crt → certificate'
        else:
            inspect = 'OpenShift InspectSecret: kubeconfig client cert → certificate'
    elif origin_kind == 'ca-bundle':
        inspect = 'OpenShift InspectConfigMap: CA-bundle key or kubeconfig CA → CA bundle'
    else:
        inspect = 'OpenShift TLS collector accepted this object'
    lines = [
        'Grandfathered missing owner' if known else 'New missing owner',
        ns_why,
        inspect,
        'Not skipped (not revisioned, hashed, or injected replica)',
        'openshift.io/owning-component is empty',
    ]
    if known:
        lines.append('One of five remove-only names in GitHub ownership.md')
    return lines


def determine_issuer_origin(issuer, ca_category):
    """platform vs external vs unknown (OCPSTRAT-2029 visibility)."""
    issuer_lower = (issuer or '').lower()
    if not issuer_lower or issuer_lower == 'n/a':
        return 'unknown'
    if ca_category == 'External CA' or any(m in issuer_lower for m in EXTERNAL_ISSUER_MARKERS):
        return 'external'
    if any(m in issuer_lower for m in PLATFORM_ISSUER_MARKERS):
        return 'platform'
    return 'external'


def unique_issuer_dns(pem_certs, fallback=''):
    """Distinct issuer DNs from every PEM in the object (order preserved)."""
    seen = []
    for parsed in pem_certs or []:
        issuer = (parsed.get('issuer') or '').strip()
        if issuer and issuer not in seen:
            seen.append(issuer)
    if not seen and (fallback or '').strip():
        seen.append(fallback.strip())
    return seen


def classify_no_auto_rotate(name, cert_role, validity_days, injected_ca_copy,
                            resource_type='secret', has_private_key=False,
                            pem_certs=None):
    """Resources whose *secret* will not auto-rotate.

    Named lists (OCPSTRAT-1826, installer, HyperShift) only explain *why*.
    They must not override lifetime: HyperShift ReconcileSelfSignedCA 10y CAs
    share names with rotating library-go signers on standalone/management
    clusters. Serving leaves that embed a 10y signer in tls.crt still rotate.
    CA bundles and other keyless copies that merely *contain* a 10-year CA
    are not will-not-rotate work items (the signer secret with the key is).
    Exception: a dedicated leftover installer CA (single PEM, no private key)
    never rotates because the key was deleted with the bootstrap machine.
    """
    if name in CNO_OPERATOR_PKI_SIGNERS:
        return False, ''
    if injected_ca_copy:
        return False, ''
    certs = pem_certs or []
    primary = select_primary_cert(name, certs) if certs else None
    days = (primary or {}).get('validity_days')
    if days is None:
        days = validity_days
    if not is_ten_year_lifetime(days):
        return False, ''
    if is_forever_period_name(name):
        return True, 'ocpstrat-1826'
    if name in INSTALLER_NO_ROTATE:
        return True, 'installer-10y'
    cn = subject_cn((primary or {}).get('subject'))
    if (
        not has_private_key
        and len(certs) == 1
        and cn in INSTALLER_KEYLESS_CA_CN
    ):
        return True, 'installer-10y-keyless'
    if cert_role == 'ca-bundle' or not has_private_key:
        return False, ''
    if cert_role == 'leaf':
        return False, ''
    if name in HYPERSHIFT_TEN_YEAR_CAS:
        return True, 'hypershift-10y'
    if len(certs) > 8:
        return False, ''
    reason = non_rotate_reason_for_cert(name, primary)
    return (True, reason) if reason else (False, '')


NO_ROTATE_LABELS = {
    'ocpstrat-1826': 'OCPSTRAT-1826 foreverPeriod',
    'installer-10y': 'Installer 10-year signer',
    'installer-10y-keyless': 'Installer leftover CA (no key)',
    'hypershift-10y': 'HyperShift 10-year CA',
}


def no_rotate_label_for(reason):
    if not reason:
        return ''
    return NO_ROTATE_LABELS.get(reason) or 'Will not auto-rotate'


def installer_keyless_lifecycle(name, cn):
    if name == 'kubelet-bootstrap-kubeconfig' or cn == 'kubelet-bootstrap-kubeconfig-signer':
        return 'revocable-bootstrap'
    if name == 'admin-kubeconfig-client-ca' or cn == 'admin-kubeconfig-signer':
        return 'keep-recovery'
    return ''


def management_display(managed_status, will_not_rotate, no_rotate_reason, injected_ca_copy,
                       hypershift_referenced=False):
    """Who rotates this cert — not a health status."""
    if 'User-Managed' in (managed_status or ''):
        if hypershift_referenced:
            return 'User-supplied (HyperShift copies it; you rotate it)', 'critical'
        return 'User-managed — action needed', 'critical'
    if will_not_rotate:
        if no_rotate_reason == 'ocpstrat-1826':
            return 'Will not auto-rotate (OCPSTRAT-1826)', 'critical'
        if no_rotate_reason == 'installer-10y':
            return 'Will not auto-rotate (installer 10y)', 'critical'
        if no_rotate_reason == 'installer-10y-keyless':
            return 'Will not auto-rotate (installer leftover, no key)', 'critical'
        if no_rotate_reason == 'hypershift-10y':
            return 'Will not auto-rotate (10-year CA)', 'critical'
        return 'Will not auto-rotate', 'critical'
    if injected_ca_copy:
        return 'Platform, injected CA copy', 'user'
    if 'Auto-Rotated' in (managed_status or '') and 'Not Auto-Rotated' not in (managed_status or ''):
        return 'Platform, auto-rotated', 'good'
    if 'Platform-Managed' in (managed_status or ''):
        return 'Platform, auto-rotated', 'good'
    return managed_status or '', 'warning'


def determine_key_policy(cert_role, key_type, key_size, is_self_signed, user_managed=False):
    """OCPSTRAT-2271: RSA root CAs (self-signed signers) must be 4096 bits.

    ECDSA/Ed25519 are not this gap. Leaves, CA-bundle copies, and user-supplied
    certs are not flagged; the platform signer secret is what must be re-keyed.
    """
    if user_managed:
        return 'ok'
    if (
        cert_role == 'signer'
        and is_self_signed
        and key_type == 'RSA'
        and key_size
        and key_size < 4096
    ):
        return 'below-4096-ca'
    return 'ok'

def determine_ca_category(issuer, annotations):
    """Determine CA category from issuer and annotations."""
    issuer_lower = issuer.lower()
    annotations_str = str(annotations).lower()
    
    # Service-CA
    if 'service-ca' in annotations_str or 'openshift-service-serving-signer' in issuer_lower:
        return "Service-CA"
    
    # Cluster-Proxy CA
    if 'open-cluster-management:cluster-proxy' in issuer_lower or 'cluster-proxy' in issuer_lower:
        return "Cluster-Proxy CA"
    
    # Kube-CSR-Signer
    if 'kube-csr-signer' in issuer_lower:
        return "Kube-CSR-Signer"
    
    # Cluster-Manager-Webhook
    if 'cluster-manager-webhook' in issuer_lower:
        return "Cluster-Manager-Webhook"
    
    # OVN CA
    if 'openshift-ovn-kubernetes' in issuer_lower:
        return "OVN CA"
    
    # Monitoring CA
    if 'openshift-cluster-monitoring' in issuer_lower:
        return "Monitoring CA"
    
    # Konnectivity CA
    if 'konnectivity-signer' in issuer_lower:
        return "Konnectivity CA"
    
    # Ingress CA
    if 'ingress-operator' in issuer_lower:
        return "Ingress CA"
    
    # OLM CA
    if 'olm-selfsigned' in issuer_lower:
        return "OLM CA"
    
    # External CA
    if 'accvraiz1' in issuer_lower or 'pkiaccv' in issuer_lower:
        return "External CA"
    
    # Platform-CA
    if 'root-ca' in issuer_lower or 'kube-apiserver-to-kubelet-signer' in issuer_lower:
        return "Platform-CA"
    
    # Generic platform patterns
    if any(x in issuer_lower for x in ['etcd', 'kube-apiserver', 'kube-controller-manager', 'openshift', 'kubernetes']):
        return "Platform-CA"
    
    return "Unknown"

def is_platform_namespace(namespace):
    """Check if namespace is a platform namespace."""
    if namespace.startswith('openshift-') and namespace != 'openshift-config':
        return True
    if namespace.startswith('kubernetes-'):
        return True
    if namespace in ['openshift', 'openshift-config-managed', 'kube-system', 'kube-public', 'default', 'kubernetes']:
        return True
    return False

def _platform_managed_label(will_not_rotate):
    if will_not_rotate:
        return "Platform-Managed (10-Year, Not Auto-Rotated)"
    return "Platform-Managed (Auto-Rotated)"


def is_hypershift_referenced(annotations):
    return any(
        (k or '').startswith(HYPERSHIFT_REFERENCED_PREFIX)
        for k in (annotations or {})
    )


def determine_managed_status(resource_type, name, namespace, cert_data, issuer, validity_days, annotations, labels, will_not_rotate=False):
    """Determine if certificate is platform-managed or user-managed."""
    owning_component = annotations.get('openshift.io/owning-component', '')
    cert_not_after = annotations.get('auth.openshift.io/certificate-not-after', '')
    cert_not_before = annotations.get('auth.openshift.io/certificate-not-before', '')
    managed_cert_type = labels.get('auth.openshift.io/managed-certificate-type', '')
    platform_label = _platform_managed_label(will_not_rotate)

    # kube-root-ca.crt is an injected replica, not the OCPSTRAT-1826 signer
    if resource_type == 'configmap' and name == 'kube-root-ca.crt':
        return "Platform-Managed (Auto-Rotated)", "Kubernetes-managed configmap with platform certificates"

    if name in OPERATOR_COPIED_BUNDLE_NAMES:
        return (
            "Platform-Managed (Auto-Rotated)",
            f"Operator-copied platform bundle; issuer: {issuer}; {validity_days} days validity",
        )

    # HostedCluster named serving cert: CPO copies it and does not regenerate it.
    if is_hypershift_referenced(annotations):
        return (
            "User-Managed (Not Auto-Rotated)",
            f"HyperShift named serving cert (HostedCluster references this Secret; "
            f"CPO copies it into the control-plane namespace and does not regenerate it); "
            f"issuer: {issuer}; {validity_days} days validity",
        )
    
    # Check owning-component annotation
    if owning_component:
        return platform_label, f"Issuer: {issuer}; {validity_days} days validity"
    
    # Check platform namespace
    if is_platform_namespace(namespace):
        return platform_label, f"Issuer: {issuer}; {validity_days} days validity"
    
    # Check rotation annotation
    if cert_not_after:
        return "Platform-Managed (Auto-Rotated)", f"Issuer: {issuer}; {validity_days} days validity"
    
    # Check issuer patterns (matching bash script logic)
    issuer_lower = issuer.lower()
    if 'service-ca' in issuer_lower or 'openshift-service-serving-signer' in issuer_lower:
        return "Platform-Managed (Auto-Rotated)", f"Service-CA signed; {validity_days} days validity"
    # Cluster-Proxy CA pattern: open-cluster-management:cluster-proxy
    if 'open-cluster-management:cluster-proxy' in issuer_lower or 'cluster-proxy' in issuer_lower:
        return "Platform-Managed (Auto-Rotated)", f"Cluster-Proxy CA signed; {validity_days} days validity"
    # Must stay aligned with PLATFORM_ISSUER_MARKERS (ingress-operator, root-ca, …).
    if any(pattern in issuer_lower for pattern in PLATFORM_ISSUER_MARKERS):
        return platform_label, f"Platform-CA signed; {validity_days} days validity"

    # Check managed label
    if managed_cert_type:
        return platform_label, f"Issuer: {issuer}; {validity_days} days validity"
    
    # Default: User-Managed
    return "User-Managed (Not Auto-Rotated)", f"Issuer: {issuer}; {validity_days} days validity"

def iter_cluster_resources(list_fn):
    """Paginate a cluster-scoped list so large inventories do not timeout in one call."""
    _continue = None
    while True:
        kwargs = {'limit': LIST_PAGE_SIZE, '_request_timeout': 120}
        if _continue:
            kwargs['_continue'] = _continue
        resp = list_fn(**kwargs)
        for item in resp.items or []:
            yield item
        meta = resp.metadata
        _continue = getattr(meta, '_continue', None) or getattr(meta, 'continue_', None) or None
        if not _continue:
            break


def listed_cert_pem(resource_type, obj):
    """Pull PEM and field names from a list payload (no extra GET)."""
    if resource_type == 'secret':
        data = obj.data or {}
        fields = [k for k in ('tls.crt', 'tls.key', 'ca.crt', 'cert.crt', 'cert.key') if k in data]
        pem = None
        for field in SECRET_CERT_FIELDS:
            if field in data:
                try:
                    pem = base64.b64decode(data[field]).decode('utf-8', errors='ignore')
                except Exception:
                    return None, False, []
                break
        if not pem:
            client_pem, _ca = kubeconfig_pems_from_secret(obj)
            if client_pem:
                pem = client_pem
                fields = list(fields) + ['kubeconfig']
        has_private_key = any(k in data for k in SECRET_KEY_FIELDS)
        return pem, has_private_key, fields
    data = obj.data or {}
    fields = [k for k in CM_CERT_FIELDS if k in data]
    pem = None
    client_pem, ca_pem = kubeconfig_pems_from_configmap(obj)
    if ca_pem:
        pem = ca_pem
        if 'kubeconfig' not in fields:
            fields = list(fields) + ['kubeconfig']
    if not pem:
        for field in CM_CERT_FIELDS:
            if field in data:
                pem = data[field]
                break
    return pem, False, fields


def process_resource_obj(resource_type, obj, cert_data, has_private_key, cert_fields):
    """Classify a secret or configmap already loaded from a list response."""
    try:
        name = obj.metadata.name
        namespace = obj.metadata.namespace
        if not cert_data or len(cert_data) < 100:
            return None
        annotations = obj.metadata.annotations or {}
        labels = obj.metadata.labels or {}

        raw_pem_count = cert_data.count('-----BEGIN CERTIFICATE-----')
        pem_certs = parse_pem_certs(cert_data)
        parsed = select_primary_cert(name, pem_certs)
        if not parsed or not parsed.get('issuer'):
            return None
        pem_cert_count = raw_pem_count or len(pem_certs)

        issuer = parsed['issuer']
        validity_days = parsed['validity_days']
        validity_years = validity_days // 365 if validity_days > 0 else 0
        is_10_year = is_ten_year_lifetime(validity_days)
        owning_component = annotations.get('openshift.io/owning-component', '')
        owning_description = annotations.get('openshift.io/description', '')
        data_fields = ', '.join(cert_fields)
        injected_ca_copy = name in INJECTED_CA_BUNDLE_NAMES
        origin_kind = origin_registry_kind(resource_type, obj) if is_tls_registry_namespace(namespace) else ''

        cert_role = determine_cert_role(
            resource_type, name, data_fields, annotations, labels, parsed,
            has_private_key=has_private_key, pem_cert_count=pem_cert_count
        )
        will_not_rotate, no_rotate_reason = classify_no_auto_rotate(
            name, cert_role, validity_days, injected_ca_copy, resource_type,
            has_private_key=has_private_key, pem_certs=pem_certs
        )
        installer_lifecycle = (
            installer_keyless_lifecycle(name, subject_cn(parsed.get('subject')))
            if no_rotate_reason == 'installer-10y-keyless' else ''
        )
        scr_skip_kind = classify_short_cert_rotation_skip(
            name, namespace, resource_type, validity_days, injected_ca_copy
        )
        managed_status, managed_details = determine_managed_status(
            resource_type, name, namespace, cert_data, issuer, validity_days,
            annotations, labels, will_not_rotate
        )
        rotation = compute_rotate_at(parsed, annotations, will_not_rotate, name)
        ca_category = determine_ca_category(issuer, annotations)
        issuer_origin = determine_issuer_origin(issuer, ca_category)
        tls_registry_status = determine_tls_registry_status(
            namespace, owning_component, injected_ca_copy, origin_kind
        )
        known_origin_violation = (
            tls_registry_status == 'uncovered'
            and (namespace, name) in ORIGIN_OWNERSHIP_VIOLATION_KEYS
        )
        hs_ref = is_hypershift_referenced(annotations)
        key_policy = determine_key_policy(
            cert_role, parsed['key_type'], parsed['key_size'], parsed['is_self_signed'],
            user_managed='User-Managed' in (managed_status or ''),
        )
        mgmt_label, mgmt_class = management_display(
            managed_status, will_not_rotate, no_rotate_reason, injected_ca_copy,
            hypershift_referenced=hs_ref,
        )
        key_display = (
            f"{parsed['key_type']}-{parsed['key_size']}"
            if parsed.get('key_size')
            else (parsed.get('key_type') or '')
        )

        # Build relevant annotations (one per line)
        relevant_annos = []
        if owning_component:
            relevant_annos.append(f"openshift.io/owning-component: {owning_component}")
        if owning_description:
            relevant_annos.append(f"openshift.io/description: {owning_description}")
        if 'certificates.openshift.io/refresh-period' in annotations:
            relevant_annos.append(
                f"certificates.openshift.io/refresh-period: {annotations['certificates.openshift.io/refresh-period']}"
            )
        if 'auth.openshift.io/certificate-not-before' in annotations:
            relevant_annos.append(
                f"auth.openshift.io/certificate-not-before: {annotations['auth.openshift.io/certificate-not-before']}"
            )
        if 'auth.openshift.io/certificate-not-after' in annotations:
            relevant_annos.append(
                f"auth.openshift.io/certificate-not-after: {annotations['auth.openshift.io/certificate-not-after']}"
            )
        managed_type = (
            labels.get('auth.openshift.io/managed-certificate-type')
            or annotations.get('auth.openshift.io/managed-certificate-type')
        )
        if managed_type:
            relevant_annos.append(f"auth.openshift.io/managed-certificate-type: {managed_type}")
        for key in annotations:
            if key.startswith(HYPERSHIFT_REFERENCED_PREFIX):
                relevant_annos.append(f"{key}: {annotations[key]}")

        return {
            'resource_type': resource_type,
            'name': name,
            'namespace': namespace,
            'data_fields': data_fields,
            'validity_years': validity_years,
            'validity_days': validity_days,
            'validity_label': validity_label(validity_days),
            'issued': parsed.get('issued'),
            'expires': parsed.get('expires'),
            'days_remaining': parsed['days_remaining'],
            'expiry': parsed['expiry'],
            'pem_cert_count': pem_cert_count,
            'has_private_key': has_private_key,
            'private_key': has_private_key,
            'bundle_certs': (
                [cert_public_fields(p) for p in pem_certs]
                if pem_cert_count <= 8 else []
            ),
            'fingerprint': parsed['fingerprint'],
            'managed_status': managed_status,
            'managed_details': managed_details,
            'ca_category': ca_category,
            'relevant_annotations': '\n'.join(relevant_annos) if relevant_annos else '',
            'issuer': issuer,
            'issuers': unique_issuer_dns(pem_certs, issuer),
            'subject': parsed['subject'],
            'cert_role': cert_role,
            'is_ca': parsed['is_ca'],
            'is_self_signed': parsed['is_self_signed'],
            'is_10_year': is_10_year,
            'will_not_auto_rotate': will_not_rotate,
            'no_rotate_reason': no_rotate_reason,
            'no_rotate_label': no_rotate_label_for(no_rotate_reason) if will_not_rotate else '',
            'installer_ca_lifecycle': installer_lifecycle,
            'installer_ca_note': INSTALLER_KEYLESS_NOTES.get(installer_lifecycle, ''),
            'is_forever_period_signer': name in FOREVER_PERIOD_SIGNERS,
            'is_forever_period_leaf': is_forever_period_leaf_name(name),
            'is_forever_period': is_forever_period_name(name) and will_not_rotate,
            'is_ocpstrat_1826': is_forever_period_name(name) and will_not_rotate,
            'scr_skip_kind': scr_skip_kind,
            'scr_skip_label': SCR_SKIP_LABELS.get(scr_skip_kind, ''),
            'not_shortened_by_scr': bool(scr_skip_kind),
            'injected_ca_copy': injected_ca_copy,
            'key_type': parsed['key_type'],
            'key_size': parsed['key_size'],
            'key_display': key_display,
            'key_policy': key_policy,
            'issuer_origin': issuer_origin,
            'tls_registry_status': tls_registry_status,
            'missing_owner': tls_registry_status == 'uncovered',
            'needs_owning_component': tls_registry_status in ('uncovered', 'registered'),
            'owner_not_required_reason': (
                '' if tls_registry_status in ('uncovered', 'registered') else
                collector_owner_skip_reason(resource_type, obj, namespace, name)
            ),
            'origin_kind': origin_kind,
            'known_origin_violation': known_origin_violation,
            'registry_why_lines': (
                missing_owner_why_lines(
                    namespace, resource_type, origin_kind, data_fields, known_origin_violation
                )
                if tls_registry_status == 'uncovered' else []
            ),
            'owning_component': owning_component,
            'owning_description': owning_description,
            'rotate_at': rotation['rotate_at'],
            'rotate_at_iso': rotation['rotate_at_iso'],
            'rotate_at_source': rotation['rotate_at_source'],
            'refresh_period': rotation['refresh_period'],
            'days_until_rotate': rotation['days_until_rotate'],
            'rotation_mode': rotation['rotation_mode'],
            'mgmt_label': mgmt_label,
            'mgmt_class': mgmt_class,
            'hypershift_referenced': hs_ref,
        }
    except ApiException as e:
        loc = f"{getattr(obj.metadata, 'namespace', '?')}/{getattr(obj.metadata, 'name', '?')}"
        if e.status != 404:
            logger.warning(f"Error processing {resource_type} {loc}: {e}")
        return None
    except Exception as e:
        loc = f"{getattr(obj.metadata, 'namespace', '?')}/{getattr(obj.metadata, 'name', '?')}"
        logger.warning(f"Error processing {resource_type} {loc}: {e}")
        return None


def _append_listed_cert(resource_type, obj, certificates, injected_canonical, stats):
    """Process one listed object; skip re-parse of identical injected CA copies."""
    data = obj.data or {}
    if resource_type == 'secret':
        if not any(field in data for field in SECRET_CERT_FIELDS):
            return
    elif not any(field in data for field in CM_CERT_FIELDS):
        return

    pem, has_private_key, cert_fields = listed_cert_pem(resource_type, obj)
    if not pem or len(pem) < 100:
        return

    name = obj.metadata.name
    namespace = obj.metadata.namespace
    stats['candidates'] += 1

    if name in INJECTED_CA_BUNDLE_NAMES:
        digest = hashlib.sha256(pem.encode('utf-8', errors='ignore')).hexdigest()
        cache_key = (name, digest)
        canonical = injected_canonical.get(cache_key)
        if canonical:
            canonical['copy_count'] = canonical.get('copy_count', 1) + 1
            ns_list = canonical.setdefault('copy_namespaces', [canonical['namespace']])
            if namespace not in ns_list:
                ns_list.append(namespace)
            replica = dict(canonical)
            replica['namespace'] = namespace
            replica['is_injected_replica'] = True
            replica['copy_count'] = 1
            replica['copy_namespaces'] = [namespace]
            certificates.append(replica)
            stats['injected_skipped'] += 1
            return

    cert_info = process_resource_obj(resource_type, obj, pem, has_private_key, cert_fields)
    if not cert_info:
        return
    if cert_info.get('injected_ca_copy'):
        digest = hashlib.sha256(pem.encode('utf-8', errors='ignore')).hexdigest()
        cert_info['copy_count'] = 1
        cert_info['copy_namespaces'] = [namespace]
        cert_info['is_injected_replica'] = False
        injected_canonical[(name, digest)] = cert_info
    certificates.append(cert_info)
    stats['parsed'] += 1


def discover_certificates():
    """Discover all certificates in the cluster from list payloads (no per-object GET)."""
    v1 = client.CoreV1Api()
    certificates = []
    injected_canonical = {}
    stats = {'candidates': 0, 'parsed': 0, 'injected_skipped': 0}

    try:
        for secret in iter_cluster_resources(v1.list_secret_for_all_namespaces):
            _append_listed_cert('secret', secret, certificates, injected_canonical, stats)
    except Exception as e:
        logger.error(f"Error listing secrets: {e}")

    try:
        for cm in iter_cluster_resources(v1.list_config_map_for_all_namespaces):
            _append_listed_cert('configmap', cm, certificates, injected_canonical, stats)
    except Exception as e:
        logger.error(f"Error listing configmaps: {e}")

    logger.info(
        "Discovery scan: %s cert-bearing objects, %s parsed, %s injected copies reused",
        stats['candidates'], stats['parsed'], stats['injected_skipped']
    )

    certificates.sort(key=lambda c: (
        c.get('days_remaining') is None,
        c.get('days_remaining') if c.get('days_remaining') is not None else 10**9,
        c.get('namespace') or '',
        c.get('name') or '',
    ))
    return certificates


def certificates_for_ui(certificates):
    """Collapse identical injected CA copies for the HTML table."""
    rows = []
    collapsed = 0
    for cert in certificates:
        apply_inventory_filter_flags(cert)
        if cert.get('is_injected_replica'):
            collapsed += 1
            continue
        rows.append(cert)
    return rows, collapsed


def summarize_certificates(certificates):
    """Phase 1 rollups for the confidence console and API."""
    certificates = [apply_inventory_filter_flags(c) for c in certificates if c]
    uncovered = [
        c for c in certificates
        if c.get('tls_registry_status') == 'uncovered'
    ]
    return {
        'total': len(certificates),
        'platform_managed': sum(1 for c in certificates if 'Platform-Managed' in c.get('managed_status', '')),
        'user_managed': sum(1 for c in certificates if 'User-Managed' in c.get('managed_status', '')),
        'auto_rotated': sum(
            1 for c in certificates
            if 'Auto-Rotated' in c.get('managed_status', '')
            and 'Not Auto-Rotated' not in c.get('managed_status', '')
        ),
        'uncovered': len(uncovered),
        'missing_owners': len(uncovered),
        'missing_owners_new': sum(1 for c in uncovered if not c.get('known_origin_violation')),
        'missing_owners_known': sum(1 for c in uncovered if c.get('known_origin_violation')),
        'injected_copies': sum(1 for c in certificates if c.get('injected_ca_copy')),
        'signers': sum(1 for c in certificates if c.get('cert_role') == 'signer'),
        'leaves': sum(1 for c in certificates if c.get('cert_role') == 'leaf'),
        'ca_bundles': sum(1 for c in certificates if c.get('cert_role') == 'ca-bundle'),
        'external_issuers': sum(1 for c in certificates if c.get('issuer_origin') == 'external'),
        'ten_year': sum(1 for c in certificates if c.get('will_not_auto_rotate')),
        'will_not_auto_rotate': sum(1 for c in certificates if c.get('will_not_auto_rotate')),
        'forever_period_signers': sum(1 for c in certificates if c.get('is_forever_period_signer')),
        'forever_period': sum(1 for c in certificates if c.get('is_forever_period')),
        'not_shortened_by_scr': sum(1 for c in certificates if c.get('not_shortened_by_scr')),
        'ocpstrat_1826': sum(1 for c in certificates if c.get('is_ocpstrat_1826')),
        'ocpstrat_1826_filter': sum(1 for c in certificates if c.get('filter_1826')),
        'below_4096_ca': sum(1 for c in certificates if c.get('key_policy') == 'below-4096-ca'),
        'past_rotate_at': sum(
            1 for c in certificates
            if c.get('days_until_rotate') is not None and c.get('days_until_rotate') < 0
            and not c.get('will_not_auto_rotate')
            and c.get('has_private_key')
            and c.get('cert_role') != 'ca-bundle'
            and not c.get('injected_ca_copy')
        ),
        'registered': sum(1 for c in certificates if c.get('tls_registry_status') == 'registered'),
        'tls_registry': sum(1 for c in certificates if c.get('origin_kind')),
        'validity_over_5y': sum(1 for c in certificates if c.get('filter_2272')),
        'validity_over_2y': sum(1 for c in certificates if c.get('filter_2273')),
    }


def ocpstrat_1826_inventory(certificates):
    """The five OCPSTRAT-1826 named secrets vs what this API actually has."""
    rows = []
    for name in OCPSTRAT_1826_EXPECTED:
        if name == 'localhost-recovery-serving-certkey':
            hits = [c for c in certificates if is_forever_period_leaf_name(c.get('name'))]
        else:
            hits = [c for c in certificates if c.get('name') == name]
        primary = next((c for c in hits if c.get('has_private_key')), hits[0] if hits else None)
        owners = sorted({c.get('owning_component') for c in hits if c.get('owning_component')})
        revision_names = sorted({c.get('name') for c in hits if c.get('name')})
        rows.append({
            'name': name,
            'found': bool(hits),
            'on_this_api': bool(hits),
            'namespaces': sorted({c.get('namespace') for c in hits if c.get('namespace')}),
            'issued': (primary or {}).get('issued') or '',
            'validity_label': (primary or {}).get('validity_label') or '',
            'has_private_key': any(c.get('has_private_key') for c in hits),
            'private_key': any(c.get('has_private_key') for c in hits),
            'owning_component': ', '.join(owners),
            'owning_description': (primary or {}).get('owning_description') or '',
            'revision_count': len(hits),
            'revision_names': revision_names,
        })
    return rows


def short_cert_rotation_inventory(certificates):
    """Named secrets ShortCertRotation does not shorten vs what this API has."""
    rows = []
    for namespace, name, kind in SCR_UNSHORTENED_EXPECTED:
        if name == 'localhost-recovery-serving-certkey':
            hits = [
                c for c in certificates
                if is_forever_period_leaf_name(c.get('name'))
                and c.get('resource_type') == 'secret'
            ]
        else:
            hits = [
                c for c in certificates
                if c.get('namespace') == namespace
                and c.get('name') == name
                and c.get('resource_type') == 'secret'
            ]
        primary = next((c for c in hits if c.get('has_private_key')), hits[0] if hits else None)
        owners = sorted({c.get('owning_component') for c in hits if c.get('owning_component')})
        revision_names = sorted({c.get('name') for c in hits if c.get('name')})
        rows.append({
            'namespace': namespace,
            'name': name,
            'skip_kind': kind,
            'skip_label': SCR_SKIP_LABELS.get(kind, ''),
            'found': bool(hits),
            'on_this_api': bool(hits),
            'namespaces': sorted({c.get('namespace') for c in hits if c.get('namespace')}),
            'issued': (primary or {}).get('issued') or '',
            'validity_label': (primary or {}).get('validity_label') or '',
            'has_private_key': any(c.get('has_private_key') for c in hits),
            'private_key': any(c.get('has_private_key') for c in hits),
            'owning_component': ', '.join(owners),
            'owning_description': (primary or {}).get('owning_description') or '',
            'revision_count': len(hits),
            'revision_names': revision_names,
            'in_1826_scope': kind == 'foreverPeriod',
        })
    return rows


def origin_ownership_inventory(certificates):
    """ownership.md Missing Owners (5), plus any new live gaps."""
    certificates = [c for c in (certificates or []) if c]
    by_key = {(c.get('namespace'), c.get('name')): c for c in certificates}
    expected = []
    for kind, ns, name in ORIGIN_OWNERSHIP_VIOLATIONS:
        hit = by_key.get((ns, name))
        expected.append({
            'origin_kind': kind,
            'namespace': ns,
            'name': name,
            'found': bool(hit),
            'owning_component': (hit or {}).get('owning_component') or '',
            'owning_description': (hit or {}).get('owning_description') or '',
            'tls_registry_status': (hit or {}).get('tls_registry_status') or '',
            'still_missing': bool(hit) and hit.get('tls_registry_status') == 'uncovered',
            'issued': (hit or {}).get('issued') or '',
            'validity_label': (hit or {}).get('validity_label') or '',
        })
    extras = sorted(
        [
            c for c in certificates
            if c.get('tls_registry_status') == 'uncovered'
            and (c.get('namespace'), c.get('name')) not in ORIGIN_OWNERSHIP_VIOLATION_KEYS
        ],
        key=lambda c: ((c.get('origin_kind') or ''), (c.get('namespace') or ''), (c.get('name') or '')),
    )
    return expected, extras


def unique_non_rotating_cas(certificates):
    """One row per 10-year non-rotating CA fingerprint, including injected copies."""
    by_fp = {}
    for c in certificates or []:
        for parsed in c.get('bundle_certs') or []:
            reason = non_rotate_reason_for_cert(c.get('name'), {
                'validity_days': parsed.get('validity_days'),
                'subject': parsed.get('subject'),
            })
            if not reason:
                continue
            fp = parsed.get('fingerprint')
            if not fp:
                continue
            rec = by_fp.get(fp)
            loc = f"{c.get('namespace')}/{c.get('name')}"
            owner = (c.get('owning_component') or '').strip()
            desc = (c.get('owning_description') or '').strip()
            if rec is None:
                rec = dict(parsed)
                rec['reason'] = reason
                rec['copy_count'] = 0
                rec['locations'] = []
                rec['has_private_key'] = False
                rec['_owners'] = []
                rec['owning_description'] = ''
                by_fp[fp] = rec
            rec['copy_count'] += 1
            if c.get('has_private_key'):
                rec['has_private_key'] = True
                if desc:
                    rec['owning_description'] = desc
            elif desc and not rec['owning_description']:
                rec['owning_description'] = desc
            if owner and owner not in rec['_owners']:
                rec['_owners'].append(owner)
            if loc not in rec['locations'] and len(rec['locations']) < 12:
                rec['locations'].append(loc)
    rows = sorted(by_fp.values(), key=lambda r: ((r.get('cn') or ''), (r.get('subject') or '')))
    for rec in rows:
        rec['owning_component'] = ', '.join(rec.pop('_owners', []))
        rec['private_key'] = bool(rec.get('has_private_key'))
    return rows


JIRA_BROWSE = 'https://issues.redhat.com/browse/'
WORK_TICKETS = {
    'ocpstrat-1826': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'installer-10y': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'installer-10y-keyless': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'hypershift-10y': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'scr-10y': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'scr-namespace': ('OCPSTRAT-1826', JIRA_BROWSE + 'OCPSTRAT-1826'),
    'rsa-ca-below-4096': ('OCPSTRAT-2271', JIRA_BROWSE + 'OCPSTRAT-2271'),
    'past-rotate-at': ('OCPSTRAT-1990', JIRA_BROWSE + 'OCPSTRAT-1990'),
    'validity-over-5y': ('OCPSTRAT-2272', JIRA_BROWSE + 'OCPSTRAT-2272'),
    'validity-over-2y': ('OCPSTRAT-2273', JIRA_BROWSE + 'OCPSTRAT-2273'),
    'external-ca': ('OCPSTRAT-2029', JIRA_BROWSE + 'OCPSTRAT-2029'),
    'missing-owner': ('OpenShift CI', 'https://github.com/openshift/origin/blob/main/tls/README.md'),
    'user-managed': ('', ''),
}
WORK_ACTIONS = {
    'missing-owner-new': 'Set openshift.io/owning-component to the Jira component that owns this lifecycle. OpenShift CI fails on new unowned artifacts.',
    'missing-owner-known': 'Grandfathered OpenShift TLS-registry violation (remove-only). Still needs an owner; do not add more of these.',
    'ocpstrat-1826': 'kube-apiserver foreverPeriod artifact. ShortCertRotation does not shorten 10y; the payload test skips it. No supported auto or manual rotation yet.',
    'scr-10y': 'ShortCertRotation payload test skips ValidityDuration == "10y". This cert still auto-rotates on a long cycle (MCS ~8y, OVN/NNI ~9y).',
    'scr-namespace': 'Owning operator never wired ShortCertRotation (ingress / OLM). The payload test ignores this namespace. Typical lifetime ~2y; still auto-rotated.',
    'installer-10y': 'Installer created-once 10-year signer. Same rotation gap as OCPSTRAT-1826.',
    'installer-10y-keyless': 'Installer leftover CA: public cert only; the private key was deleted with the bootstrap machine. This object will never be regenerated. kubelet-bootstrap-kubeconfig can be deleted to revoke installer master-bootstrap client certs after control-plane kubeconfigs no longer use them. admin-kubeconfig-client-ca must be kept for the original admin kubeconfig.',
    'hypershift-10y': 'HyperShift created-once 10-year CA (private key is on this API). Same rotation gap as OCPSTRAT-1826.',
    'rsa-ca-below-4096': 'Self-signed RSA signer below 4096 bits. OCPSTRAT-2271 (TP) / OCPSTRAT-3050 (GA) require 4096 for RSA root CAs; re-issue this signer key.',
    'user-managed': 'OpenShift will not rotate this because an administrator supplied it. Rotate it before expiry, or move it onto Service-CA / an operator. This is not OCPSTRAT-1826 (those are platform 10-year signers).',
    'user-managed-hypershift': 'HostedCluster named serving cert: HyperShift copies this Secret and does not regenerate it. You rotate it. This is not OCPSTRAT-1826 (those are platform 10-year signers).',
    'past-rotate-at': 'Predicted rotate-at is in the past and this is not a will-not-rotate signer. Check the owning operator is reconciling (OCPSTRAT-1990 visibility).',
    'validity-over-5y': 'Lifetime is over 5 years. HPSTRAT-99 / OCPSTRAT-2272 phase 1 is to cap platform certs at 5 years (then 2 years in phase 2).',
    'validity-over-2y': 'Lifetime is over 2 years and at most 5 years. OCPSTRAT-2273 phase 2 is to cap platform certs at 2 years.',
    'external-ca': 'Issuer DN is not classified as OpenShift internal PKI. OCPSTRAT-2029 is not a to-do to remove this: the Feature is a customer intermediate CA so platform certs can chain to an enterprise root while OpenShift still rotates them. Confirm this issuer is expected.',
}
WORK_CATEGORY_LABELS = {
    'missing-owner': 'Missing owner',
    'will-not-rotate': 'Will not auto-rotate',
    'scr-test-skip': 'SCR test skip',
    'rsa-ca-below-4096': 'RSA CA below 4096',
    'user-managed': 'User-managed',
    'past-rotate-at': 'Past rotate-at',
    'validity-over-5y': 'Validity over 5y',
    'validity-over-2y': 'Validity over 2y',
    'external-ca': 'External issuer',
}
TICKET_GROUP_ORDER = (
    'OCPSTRAT-1826',
    'OCPSTRAT-2272',
    'OCPSTRAT-2273',
    'OCPSTRAT-2271',
    'OCPSTRAT-2029',
    'OCPSTRAT-1990',
    'OpenShift CI',
    'No OCPSTRAT',
)
TICKET_GROUP_TITLES = {
    'OCPSTRAT-1826': 'Manual rotation of 10-year certificates',
    'OCPSTRAT-2272': 'Phase 1: platform certificate validity ≤ 5 years',
    'OCPSTRAT-2273': 'Phase 2: platform certificate validity ≤ 2 years',
    'OCPSTRAT-2271': 'RSA CA key size 4096 (TP; GA is OCPSTRAT-3050)',
    'OCPSTRAT-2029': 'External CA for platform certificates',
    'OCPSTRAT-1990': 'Platform certificate rotation information',
    'OpenShift CI': 'Missing openshift.io/owning-component',
    'No OCPSTRAT': 'User-managed (no Feature)',
}
TICKET_GROUP_URLS = {
    'OCPSTRAT-1826': JIRA_BROWSE + 'OCPSTRAT-1826',
    'OCPSTRAT-2272': JIRA_BROWSE + 'OCPSTRAT-2272',
    'OCPSTRAT-2273': JIRA_BROWSE + 'OCPSTRAT-2273',
    'OCPSTRAT-2271': JIRA_BROWSE + 'OCPSTRAT-2271',
    'OCPSTRAT-2029': JIRA_BROWSE + 'OCPSTRAT-2029',
    'OCPSTRAT-1990': JIRA_BROWSE + 'OCPSTRAT-1990',
    'OpenShift CI': 'https://github.com/openshift/origin/blob/main/tls/README.md',
    'No OCPSTRAT': '',
}
TICKET_GROUP_WHY = {
    'OCPSTRAT-1826': 'Certs the ShortCertRotation payload test ignores: foreverPeriod (kube-apiserver 10y), other 10y ValidityDuration (MCS / OVN / NNI), and ingress/OLM namespaces. Auto-rotated leftovers stay listed; Management says who rotates.',
    'OCPSTRAT-2272': 'Listed items are examples on this API of why this Feature is important: platform certificates whose lifetime is still over 5 years.',
    'OCPSTRAT-2273': 'Listed items are examples on this API of why this Feature is important: platform certificates whose lifetime is still over 2 years (and at most 5).',
    'OCPSTRAT-2271': 'Listed items are examples on this API of why this Feature is important: RSA self-signed signers still below 4096 bits (GA is OCPSTRAT-3050).',
    'OCPSTRAT-2029': 'Why this Feature is important: government and telco customers need platform certificates to chain to their enterprise root CA, without handing minting or rotation to that CA (bootstrap, DR, and self-healing must keep working offline). The design is an intermediate signing CA supplied at install. This API cannot list that gap as secrets: until the Feature ships, platform certs already look healthy under OpenShift-internal CAs. Operator-local issuers and proxy trust bundles are a different inventory (External issuers filter); they are not this work, and they do not need to be folded into the intermediate CA for the Feature to land.',
    'OCPSTRAT-1990': 'Listed items are examples on this API of why this Feature is important: certificates already past their predicted rotate-at (overdue for refresh).',
    'OpenShift CI': 'Listed items are examples on this API of why owning-component annotations matter. A row is here because the OpenShift TLS collector accepted it (platform namespace, InspectSecret/InspectConfigMap, not skipped) and owning-component is empty.',
    'No OCPSTRAT': 'These are certificates OpenShift will not rotate because an administrator supplied them (for example a HyperShift HostedCluster named serving cert). They are not the OCPSTRAT-1826 10-year platform signers. Rotate them yourself, or move them onto Service-CA / an operator.',
}


def _owner_group(cert):
    owner = (cert.get('owning_component') or '').strip()
    if owner:
        return owner
    ns = cert.get('namespace') or ''
    return f'unassigned ({ns})' if ns else 'unassigned'


def _work_item(cert, category, why, status=''):
    ticket_key = why if why in WORK_TICKETS else category
    ticket, ticket_url = WORK_TICKETS.get(ticket_key, ('', ''))
    action_key = why if why in WORK_ACTIONS else category
    lifecycle = cert.get('installer_ca_lifecycle') or ''
    action = WORK_ACTIONS.get(action_key, '')
    if lifecycle == 'keep-recovery':
        action = INSTALLER_KEYLESS_NOTES.get(lifecycle, action)
    elif lifecycle == 'revocable-bootstrap':
        action = INSTALLER_KEYLESS_NOTES.get(lifecycle, action)
    return {
        'category': category,
        'category_label': WORK_CATEGORY_LABELS.get(category, category),
        'status': status,
        'why': why,
        'ticket': ticket,
        'ticket_url': ticket_url,
        'action': action,
        'owning_component': (cert.get('owning_component') or '').strip(),
        'needs_owning_component': cert.get('tls_registry_status') in ('uncovered', 'registered'),
        'owner_not_required_reason': cert.get('owner_not_required_reason') or '',
        'owner_group': _owner_group(cert),
        'namespace': cert.get('namespace') or '',
        'name': cert.get('name') or '',
        'resource_type': cert.get('resource_type') or '',
        'role': cert.get('cert_role') or '',
        'description': cert.get('owning_description') or '',
        'validity_label': cert.get('validity_label') or '',
        'days_remaining': cert.get('days_remaining'),
        'key_type': cert.get('key_type') or '',
        'key_size': cert.get('key_size'),
        'private_key': bool(cert.get('has_private_key')),
        'fingerprint': cert.get('fingerprint') or '',
        'issuer': cert.get('issuer') or '',
        'rotate_at': cert.get('rotate_at') or '',
        'rotate_at_source': cert.get('rotate_at_source') or '',
        'days_until_rotate': cert.get('days_until_rotate'),
        'is_forever_period': bool(cert.get('is_forever_period')),
        'installer_ca_lifecycle': lifecycle,
        'installer_ca_note': cert.get('installer_ca_note') or '',
        'scr_skip_kind': cert.get('scr_skip_kind') or '',
        'scr_skip_label': cert.get('scr_skip_label') or '',
        'not_shortened_by_scr': bool(cert.get('not_shortened_by_scr')),
    }


def _has_key_not_bundle(cert):
    if cert.get('injected_ca_copy'):
        return False
    if 'User-Managed' in (cert.get('managed_status') or ''):
        return False
    if cert.get('cert_role') == 'ca-bundle' or not cert.get('has_private_key'):
        return False
    return True


def apply_inventory_filter_flags(cert):
    """Flags for the Feature filter strip (must match visible inventory rows)."""
    if not cert:
        return cert
    cert['filter_1826'] = bool(
        cert.get('not_shortened_by_scr') or cert.get('will_not_auto_rotate')
    )
    cert['filter_2272'] = (
        _has_key_not_bundle(cert) and (cert.get('validity_days') or 0) > POLICY_5Y_DAYS
    )
    cert['filter_2273'] = (
        _has_key_not_bundle(cert)
        and POLICY_2Y_DAYS < (cert.get('validity_days') or 0) <= POLICY_5Y_DAYS
    )
    return cert


def _unique_by_fingerprint(certs):
    by_fp = {}
    for c in certs:
        fp = c.get('fingerprint') or f"{c.get('namespace')}/{c.get('name')}"
        prev = by_fp.get(fp)
        if prev is None or (c.get('has_private_key') and not prev.get('has_private_key')):
            by_fp[fp] = c
    return list(by_fp.values())


def hpstrat99_tracker(certificates, counts):
    """HPSTRAT-99 child Features vs what this cluster still shows.

    Counts are live from this API. Jira status and priority are not stored here;
    open the issue for those.
    """
    certificates = [apply_inventory_filter_flags(c) for c in (certificates or []) if c]
    named_1826 = sum(1 for c in certificates if c.get('is_ocpstrat_1826'))
    rotate_at_n = sum(
        1 for c in certificates
        if c.get('rotate_at') and not c.get('injected_ca_copy')
    )
    refresh_n = sum(1 for c in certificates if c.get('refresh_period'))
    return {
        'outcome': {
            'key': 'HPSTRAT-99',
            'url': JIRA_BROWSE + 'HPSTRAT-99',
            'title': 'Enhanced Platform Certificate Lifecycle Management and Compliance',
        },
        'features': [
            {
                'key': 'OCPSTRAT-1826',
                'url': JIRA_BROWSE + 'OCPSTRAT-1826',
                'title': 'Manual rotation of 10-year certificates',
                'filter': 'ocpstrat-1826',
                'count': sum(
                    1 for c in certificates
                    if c.get('not_shortened_by_scr') or c.get('will_not_auto_rotate')
                ),
                'observable': True,
                'gap': 'Secrets the ShortCertRotation payload test ignores (10y ValidityDuration including foreverPeriod, plus ingress/OLM namespaces). Auto-rotated leftovers stay in this count.',
            },
            {
                'key': 'OCPSTRAT-2272',
                'url': JIRA_BROWSE + 'OCPSTRAT-2272',
                'title': 'Phase 1: platform certificate validity ≤ 5 years',
                'filter': 'ocpstrat-2272',
                'count': sum(1 for c in certificates if c.get('filter_2272')),
                'observable': True,
                'gap': 'Secrets with a private key whose lifetime is over 5 years (3650d 10y CAs, including CNO which still issues 10y).',
            },
            {
                'key': 'OCPSTRAT-2273',
                'url': JIRA_BROWSE + 'OCPSTRAT-2273',
                'title': 'Phase 2: platform certificate validity ≤ 2 years',
                'filter': 'ocpstrat-2273',
                'count': sum(1 for c in certificates if c.get('filter_2273')),
                'observable': True,
                'gap': 'Secrets with a private key whose lifetime is over 2 years and at most 5 years (etcd 3y/5y, node-system-admin-signer, …).',
            },
            {
                'key': 'OCPSTRAT-2271',
                'url': JIRA_BROWSE + 'OCPSTRAT-2271',
                'title': '[Tech Preview] Customize RSA key size of OpenShift CAs',
                'filter': 'ocpstrat-2271',
                'also_key': 'OCPSTRAT-3050',
                'also_url': JIRA_BROWSE + 'OCPSTRAT-3050',
                'count': sum(1 for c in certificates if c.get('key_policy') == 'below-4096-ca'),
                'observable': True,
                'gap': 'Self-signed RSA signers still below 4096 bits (today typically hardcoded 2048). GA is OCPSTRAT-3050; same live set.',
            },
            {
                'key': 'OCPSTRAT-2029',
                'url': JIRA_BROWSE + 'OCPSTRAT-2029',
                'title': 'External CA for platform certificates',
                'filter': '',
                'count': None,
                'observable': False,
                'gap': 'Not a list of secrets. Until a customer intermediate CA is accepted at install, platform certs still chain only to OpenShift-internal roots. That missing capability does not show up as an issuer DN on this API.',
            },
            {
                'key': 'OCPSTRAT-1990',
                'url': JIRA_BROWSE + 'OCPSTRAT-1990',
                'title': 'Provide platform certificate rotation information to users',
                'filter': 'ocpstrat-1990',
                'count': counts.get('past-rotate-at') or 0,
                'observable': True,
                'gap': (
                    f'This console is the stand-in (rotate-at on {rotate_at_n} artifacts, '
                    f'{refresh_n} with certificates.openshift.io/refresh-period). '
                    'The product API/CLI is not shipped. Count is secrets past predicted rotate-at.'
                ),
            },
            {
                'key': 'OCPSTRAT-1346',
                'url': JIRA_BROWSE + 'OCPSTRAT-1346',
                'title': 'Automated node re-authentication after certificate expiry',
                'filter': '',
                'count': None,
                'observable': False,
                'gap': 'Not visible from in-cluster PEMs (node CSR / hibernation recovery after kubelet cert expiry).',
            },
            {
                'key': 'OCPSTRAT-2655',
                'url': JIRA_BROWSE + 'OCPSTRAT-2655',
                'title': 'Operator certificate audit for 4.22',
                'filter': 'uncovered',
                'count': counts.get('missing-owner-new') or 0,
                'observable': True,
                'gap': 'Audit is closed. Leftover new missing owners (often optional operators in openshift-* namespaces, for example OpenShift Virtualization) still fail OpenShift CI. Filter opens all missing owners (new + grandfathered).',
            },
        ],
        'named_ocpstrat_1826_on_this_api': named_1826,
    }


def workboard_report(certificates):
    """Product-team gaps: one row per work item, grouped by owning component.

    CA-bundle copies and injected replicas are not work items. RSA CAs are
    unique by fingerprint (the signer secret with the key).
    """
    certificates = [apply_inventory_filter_flags(c) for c in (certificates or []) if c]
    items = []

    for c in certificates:
        if c.get('tls_registry_status') != 'uncovered':
            continue
        known = bool(c.get('known_origin_violation'))
        items.append(_work_item(
            c, 'missing-owner',
            'missing-owner-known' if known else 'missing-owner-new',
            status='grandfathered' if known else 'new',
        ))

    added_1826 = set()
    for c in certificates:
        if not c.get('will_not_auto_rotate'):
            continue
        why = c.get('no_rotate_reason') or 'will-not-rotate'
        items.append(_work_item(c, 'will-not-rotate', why, status='strategy'))
        added_1826.add((c.get('namespace'), c.get('name')))

    for c in certificates:
        if not c.get('not_shortened_by_scr'):
            continue
        loc = (c.get('namespace'), c.get('name'))
        if loc in added_1826:
            continue
        kind = c.get('scr_skip_kind') or ''
        why = 'scr-namespace' if kind == 'namespace' else 'scr-10y'
        items.append(_work_item(c, 'scr-test-skip', why, status='strategy'))

    rsa_by_fp = {}
    for c in certificates:
        if c.get('key_policy') != 'below-4096-ca' or not c.get('has_private_key'):
            continue
        if 'User-Managed' in (c.get('managed_status') or ''):
            continue
        fp = c.get('fingerprint') or f"{c.get('namespace')}/{c.get('name')}"
        prev = rsa_by_fp.get(fp)
        if prev is None or (c.get('origin_kind') and not prev.get('origin_kind')):
            rsa_by_fp[fp] = c
    for c in rsa_by_fp.values():
        items.append(_work_item(c, 'rsa-ca-below-4096', 'rsa-ca-below-4096', status='strategy'))

    um_by_fp = {}
    for c in certificates:
        if 'User-Managed' not in (c.get('managed_status') or ''):
            continue
        if c.get('injected_ca_copy') or c.get('cert_role') == 'ca-bundle' or not c.get('has_private_key'):
            continue
        fp = c.get('fingerprint') or f"{c.get('namespace')}/{c.get('name')}"
        rec = um_by_fp.setdefault(fp, {'cert': c, 'count': 0})
        rec['count'] += 1
        # Prefer the HostedCluster-namespace copy over the longer CPO namespace.
        if len(c.get('namespace') or '') < len(rec['cert'].get('namespace') or ''):
            rec['cert'] = c
    for rec in um_by_fp.values():
        why = 'user-managed-hypershift' if rec['cert'].get('hypershift_referenced') else 'user-managed'
        item = _work_item(rec['cert'], 'user-managed', why, status='action')
        if rec['count'] > 1:
            item['copy_count'] = rec['count']
        items.append(item)

    for c in certificates:
        if c.get('days_until_rotate') is None or c.get('days_until_rotate') >= 0:
            continue
        if c.get('will_not_auto_rotate') or c.get('injected_ca_copy'):
            continue
        if 'User-Managed' in (c.get('managed_status') or ''):
            continue
        if not c.get('has_private_key') or c.get('cert_role') == 'ca-bundle':
            continue
        items.append(_work_item(c, 'past-rotate-at', 'past-rotate-at', status='stuck'))

    for c in _unique_by_fingerprint(
        c for c in certificates
        if _has_key_not_bundle(c) and (c.get('validity_days') or 0) > POLICY_5Y_DAYS
    ):
        items.append(_work_item(c, 'validity-over-5y', 'validity-over-5y', status='strategy'))

    for c in _unique_by_fingerprint(
        c for c in certificates
        if _has_key_not_bundle(c)
        and POLICY_2Y_DAYS < (c.get('validity_days') or 0) <= POLICY_5Y_DAYS
    ):
        items.append(_work_item(c, 'validity-over-2y', 'validity-over-2y', status='strategy'))

    items.sort(key=lambda r: (
        r.get('ticket') or 'No OCPSTRAT',
        r.get('owning_component') or '',
        r.get('namespace') or '',
        r.get('name') or '',
    ))
    by_ticket = {
        key: {
            'ticket': key,
            'ticket_url': TICKET_GROUP_URLS.get(key, ''),
            'title': TICKET_GROUP_TITLES.get(key, key),
            'why': TICKET_GROUP_WHY.get(key, ''),
            'count': 0,
            'gaps': [],
        }
        for key in TICKET_GROUP_ORDER
    }
    for item in items:
        key = item.get('ticket') or 'No OCPSTRAT'
        rec = by_ticket.setdefault(key, {
            'ticket': key,
            'ticket_url': item.get('ticket_url') or '',
            'title': TICKET_GROUP_TITLES.get(key) or item.get('category_label') or key,
            'why': TICKET_GROUP_WHY.get(key, ''),
            'count': 0,
            'gaps': [],
        })
        rec['count'] += 1
        rec['gaps'].append(item)
        if not rec.get('ticket_url') and item.get('ticket_url'):
            rec['ticket_url'] = item['ticket_url']
    order = {k: i for i, k in enumerate(TICKET_GROUP_ORDER)}
    groups = sorted(
        by_ticket.values(),
        key=lambda g: (order.get(g['ticket'], 80), g['ticket']),
    )
    counts = {k: sum(1 for i in items if i['category'] == k) for k in WORK_CATEGORY_LABELS}
    counts['missing-owner-new'] = sum(1 for i in items if i.get('why') == 'missing-owner-new')
    counts['missing-owner-known'] = sum(1 for i in items if i.get('why') == 'missing-owner-known')
    hpstrat99 = hpstrat99_tracker(certificates, counts)
    return {
        'total': len(items),
        'ticket_count': len(groups),
        'counts': counts,
        'by_ticket': groups,
        'gaps': items,
        'hpstrat99': hpstrat99,
    }


def compact_cert(cert):
    """Fields used by the uncovered table and API summary lists."""
    return {
        'resource_type': cert.get('resource_type'),
        'name': cert.get('name'),
        'namespace': cert.get('namespace'),
        'cert_role': cert.get('cert_role'),
        'key_display': cert.get('key_display'),
        'key_type': cert.get('key_type'),
        'key_size': cert.get('key_size'),
        'key_policy': cert.get('key_policy'),
        'days_remaining': cert.get('days_remaining'),
        'issued': cert.get('issued'),
        'expires': cert.get('expires'),
        'validity_days': cert.get('validity_days'),
        'validity_label': cert.get('validity_label'),
        'pem_cert_count': cert.get('pem_cert_count'),
        'rotate_at': cert.get('rotate_at'),
        'rotate_at_source': cert.get('rotate_at_source'),
        'issuer_origin': cert.get('issuer_origin'),
        'tls_registry_status': cert.get('tls_registry_status'),
        'needs_owning_component': cert.get('tls_registry_status') in ('uncovered', 'registered'),
        'owner_not_required_reason': cert.get('owner_not_required_reason') or '',
        'origin_kind': cert.get('origin_kind'),
        'known_origin_violation': cert.get('known_origin_violation'),
        'registry_why_lines': cert.get('registry_why_lines') or [],
        'owning_component': cert.get('owning_component'),
        'owning_description': cert.get('owning_description'),
        'managed_status': cert.get('managed_status'),
        'mgmt_label': cert.get('mgmt_label'),
        'will_not_auto_rotate': cert.get('will_not_auto_rotate'),
        'no_rotate_reason': cert.get('no_rotate_reason'),
        'no_rotate_label': cert.get('no_rotate_label') or '',
        'is_forever_period': bool(cert.get('is_forever_period')),
        'is_ocpstrat_1826': bool(cert.get('is_ocpstrat_1826')),
        'scr_skip_kind': cert.get('scr_skip_kind') or '',
        'scr_skip_label': cert.get('scr_skip_label') or '',
        'not_shortened_by_scr': bool(cert.get('not_shortened_by_scr')),
        'issuer': cert.get('issuer'),
        'issuers': cert.get('issuers') or ([cert.get('issuer')] if cert.get('issuer') else []),
        'private_key': bool(cert.get('has_private_key')),
        'has_private_key': bool(cert.get('has_private_key')),
        'missing_owner': cert.get('tls_registry_status') == 'uncovered',
        'installer_ca_lifecycle': cert.get('installer_ca_lifecycle') or '',
        'installer_ca_note': cert.get('installer_ca_note') or '',
    }

@app.route('/')
def index():
    """Main page displaying certificate discovery results."""
    try:
        # Get cached certificate data
        certificates, cluster_name, last_update = cert_cache.get_data()

        # Use last update time or current time
        if last_update:
            generated_time = last_update.strftime('%Y-%m-%d %H:%M:%S UTC')
        else:
            generated_time = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

        certificates = [c for c in certificates if c is not None]
        summary = summarize_certificates(certificates)
        uncovered = [
            c for c in certificates
            if c.get('tls_registry_status') == 'uncovered'
        ]
        no_rotate = [
            c for c in certificates
            if c.get('will_not_auto_rotate')
        ]
        ocpstrat_1826 = ocpstrat_1826_inventory(certificates)
        scr_unshortened = short_cert_rotation_inventory(certificates)
        origin_expected, origin_new = origin_ownership_inventory(certificates)
        uncovered_certificates = [c for c in uncovered if c.get('origin_kind') == 'certificate']
        uncovered_ca_bundles = [c for c in uncovered if c.get('origin_kind') == 'ca-bundle']
        unique_cas = unique_non_rotating_cas(certificates)
        workboard = workboard_report(certificates)
        summary['unique_10y_cas'] = len(unique_cas)
        summary['work_items'] = workboard['total']
        topology = getattr(cert_cache, 'control_plane_topology', '') or ''
        hosted_guest = topology == 'External'
        ui_certificates, collapsed_injected = certificates_for_ui(certificates)

        return render_template_string(HTML_TEMPLATE,
            certificates=ui_certificates,
            collapsed_injected=collapsed_injected,
            uncovered=uncovered,
            no_rotate=no_rotate,
            ocpstrat_1826=ocpstrat_1826,
            scr_unshortened=scr_unshortened,
            origin_expected=origin_expected,
            origin_new=origin_new,
            uncovered_certificates=uncovered_certificates,
            uncovered_ca_bundles=uncovered_ca_bundles,
            unique_cas=unique_cas,
            workboard=workboard,
            hosted_guest=hosted_guest,
            control_plane_topology=topology,
            summary=summary,
            cluster_name=cluster_name,
            generated_time=generated_time,
            total=summary['total'],
            platform_managed=summary['platform_managed'],
            user_managed=summary['user_managed'],
            auto_rotated=summary['auto_rotated']
        )
    except Exception as e:
        import traceback
        error_msg = f"Error: {str(e)}\n{traceback.format_exc()}"
        logger.error(f"Error in index route: {error_msg}")
        return f"<html><body><h1>Error</h1><pre>{error_msg}</pre></body></html>", 500

@app.route('/healthz')
def healthz():
    """Liveness/readiness: process is up. Does not call the Kubernetes API."""
    return "OK", 200


@app.route('/health')
def health():
    """Alias of /healthz so older probes keep working."""
    return healthz()

@app.route('/api/certificates')
def api_certificates():
    """API endpoint returning JSON data.

    Leading keys are the product-team view (summary + workboard). Full
    ``certificates`` remains for inventory; each row still has the original
    field names plus ``private_key`` / ``missing_owner`` aliases.
    """
    try:
        certificates, cluster_name, last_update = cert_cache.get_data()
        certificates = [c for c in certificates if c]
        compact_rows, collapsed_injected = certificates_for_ui(certificates)
        compact_rows = [{k: v for k, v in row.items() if k != 'bundle_certs'} for row in compact_rows]
        summary = summarize_certificates(certificates)
        unique_cas = unique_non_rotating_cas(certificates)
        workboard = workboard_report(certificates)
        summary['unique_10y_cas'] = len(unique_cas)
        summary['work_items'] = workboard['total']
        uncovered = [compact_cert(c) for c in certificates if c.get('tls_registry_status') == 'uncovered']
        no_rotate = [compact_cert(c) for c in certificates if c.get('will_not_auto_rotate')]
        return jsonify({
            'cluster_name': cluster_name,
            'last_update': last_update.isoformat() if last_update else None,
            'control_plane_topology': getattr(cert_cache, 'control_plane_topology', '') or '',
            'summary': summary,
            'workboard': workboard,
            'ocpstrat_1826': ocpstrat_1826_inventory(certificates),
            'short_cert_rotation_unshortened': short_cert_rotation_inventory(certificates),
            'unique_non_rotating_cas': unique_cas,
            'missing_owners': uncovered,
            'uncovered': uncovered,
            'will_not_auto_rotate': no_rotate,
            'forever_period': [compact_cert(c) for c in certificates if c.get('is_forever_period')],
            'not_shortened_by_scr': [compact_cert(c) for c in certificates if c.get('not_shortened_by_scr')],
            'compact': compact_rows,
            'collapsed_injected_copies': collapsed_injected,
            'certificates': certificates,
            'total': summary['total'],
        })
    except Exception as e:
        logger.error(f"Error in API endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/workboard')
def api_workboard():
    """Product-team gaps: missing owners, will-not-rotate signers, RSA CAs, user-managed, stuck rotate-at."""
    try:
        certificates, cluster_name, last_update = cert_cache.get_data()
        certificates = [c for c in certificates if c]
        report = workboard_report(certificates)
        report['cluster_name'] = cluster_name
        report['last_update'] = last_update.isoformat() if last_update else None
        report['control_plane_topology'] = getattr(cert_cache, 'control_plane_topology', '') or ''
        return jsonify(report)
    except Exception as e:
        logger.error(f"Error in workboard endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/uncovered')
def api_uncovered():
    """Platform TLS artifacts missing an owning-component (Jira lifecycle owner)."""
    try:
        certificates, cluster_name, last_update = cert_cache.get_data()
        uncovered = [
            compact_cert(c) for c in certificates
            if c and c.get('tls_registry_status') == 'uncovered'
        ]
        expected, extras = origin_ownership_inventory(certificates)
        return jsonify({
            'cluster_name': cluster_name,
            'last_update': last_update.isoformat() if last_update else None,
            'total': len(uncovered),
            'origin_known_violations': expected,
            'new_missing_owners': [compact_cert(c) for c in extras],
            'certificates': uncovered
        })
    except Exception as e:
        logger.error(f"Error in uncovered endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def api_history():
    """Get list of all discovery runs from database."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({'error': 'Database not available - PV may not be mounted'}), 503

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute('''
            SELECT id, timestamp, cluster_name, total_certificates as certificate_count,
                   platform_managed, user_managed, auto_rotated, discovery_duration_seconds
            FROM certificate_discoveries
            ORDER BY timestamp DESC
            LIMIT 100
        ''')

        discoveries = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify(discoveries)
    except Exception as e:
        logger.error(f"Error in history endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<int:discovery_id>')
def api_history_detail(discovery_id):
    """Get certificates from a specific discovery run."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({'error': 'Database not available - PV may not be mounted'}), 503

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get discovery metadata
        cursor.execute('''
            SELECT id, timestamp, cluster_name, total_certificates as certificate_count,
                   platform_managed, user_managed, auto_rotated, discovery_duration_seconds
            FROM certificate_discoveries
            WHERE id = ?
        ''', (discovery_id,))

        discovery = cursor.fetchone()
        if not discovery:
            conn.close()
            return jsonify({'error': 'Discovery not found'}), 404

        # Get certificates
        cursor.execute('''
            SELECT * FROM certificates
            WHERE discovery_id = ?
        ''', (discovery_id,))

        certificates = [dict(row) for row in cursor.fetchall()]
        conn.close()

        return jsonify({
            'discovery': dict(discovery),
            'certificates': certificates
        })
    except Exception as e:
        logger.error(f"Error in history detail endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/changes')
def api_changes():
    """Show changes between last two discovery runs."""
    try:
        if not os.path.exists(DB_PATH):
            return jsonify({'error': 'Database not available - PV may not be mounted'}), 503

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get last two discoveries
        cursor.execute('''
            SELECT id, timestamp FROM certificate_discoveries
            ORDER BY timestamp DESC
            LIMIT 2
        ''')

        discoveries = [dict(row) for row in cursor.fetchall()]

        if len(discoveries) < 2:
            conn.close()
            return jsonify({'message': 'Need at least 2 discovery runs to compare'})

        older_id = discoveries[1]['id']
        newer_id = discoveries[0]['id']

        # Get older certificates
        cursor.execute('''
            SELECT namespace, name, fingerprint FROM certificates
            WHERE discovery_id = ?
        ''', (older_id,))
        old_certs = {(row['namespace'], row['name']): row['fingerprint'] for row in cursor.fetchall()}

        # Get newer certificates
        cursor.execute('''
            SELECT namespace, name, fingerprint FROM certificates
            WHERE discovery_id = ?
        ''', (newer_id,))
        new_certs = {(row['namespace'], row['name']): row['fingerprint'] for row in cursor.fetchall()}

        conn.close()

        # Detect changes
        added = [k for k in new_certs if k not in old_certs]
        removed = [k for k in old_certs if k not in new_certs]
        changed = [k for k in new_certs if k in old_certs and new_certs[k] != old_certs[k]]

        return jsonify({
            'older_discovery': discoveries[1],
            'newer_discovery': discoveries[0],
            'summary': {
                'added': len(added),
                'removed': len(removed),
                'changed': len(changed)
            },
            'details': {
                'added': [{'namespace': k[0], 'name': k[1]} for k in added],
                'removed': [{'namespace': k[0], 'name': k[1]} for k in removed],
                'changed': [{'namespace': k[0], 'name': k[1]} for k in changed]
            }
        })
    except Exception as e:
        logger.error(f"Error in changes endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

# HTML Template with same color scheme
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Certificate Roadmap Console</title>
    <meta http-equiv="refresh" content="300">
    <style>
        body {
            font-family: "RedHatText", "Overpass", "Red Hat Text", Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #F0F0F0;
            color: #151515;
            min-height: 100vh;
        }
        .header {
            background: #FFFFFF;
            padding: 24px 30px;
            border-radius: 4px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid #E0E0E0;
        }
        .header h1 {
            margin: 0 0 8px 0;
            font-size: 1.8em;
            font-weight: 400;
        }
        .header p { color: #6A6A6A; margin: 0; }
        .glossary {
            margin-top: 16px;
            border: 1px solid #E0E0E0;
            border-radius: 4px;
            background: #FAFAFA;
        }
        .glossary summary {
            cursor: pointer;
            padding: 10px 14px;
            font-weight: 600;
            color: #0066CC;
            list-style: none;
        }
        .glossary summary::-webkit-details-marker { display: none; }
        .glossary summary::before { content: "▸ "; color: #6A6A6A; }
        .glossary[open] summary::before { content: "▾ "; }
        .glossary-body {
            padding: 0 14px 14px;
            border-top: 1px solid #E0E0E0;
        }
        .glossary-body p { margin: 10px 0 0; font-size: 0.85em; }
        .glossary dl {
            margin: 12px 0 0;
            display: grid;
            grid-template-columns: minmax(8.5rem, 11rem) 1fr;
            gap: 10px 16px;
            font-size: 0.9em;
        }
        .glossary dt { font-weight: 600; color: #151515; padding-top: 2px; }
        .glossary dd { margin: 0; color: #3D3D3D; }
        .glossary .use {
            display: block;
            margin-top: 4px;
            color: #6A6A6A;
        }
        th[title], .has-tip {
            text-decoration: underline dotted #8A8A8A;
            text-underline-offset: 3px;
            cursor: help;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 12px;
            margin: 20px 0;
        }
        .summary-card {
            background: #FFFFFF;
            padding: 16px;
            border-radius: 4px;
            text-align: center;
            border: 1px solid #E0E0E0;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            cursor: pointer;
        }
        .summary-card:hover { border-color: #007BFF; }
        .summary-card.active { border-color: #007BFF; outline: 2px solid #007BFF; }
        .summary-card h3 {
            margin: 0 0 8px 0;
            color: #6A6A6A;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .summary-count { font-size: 2em; font-weight: 400; margin: 0; }
        .filters { margin: 12px 0 20px; }
        .filters button {
            background: #FFFFFF;
            border: 1px solid #E0E0E0;
            padding: 6px 12px;
            margin: 0 6px 6px 0;
            border-radius: 3px;
            cursor: pointer;
            font-size: 0.85em;
        }
        .filters button.active { background: #007BFF; color: #fff; border-color: #007BFF; }
        .section-title { font-size: 1.15em; font-weight: 600; margin: 24px 0 8px; }
        .cert-table {
            width: 100%;
            border-collapse: collapse;
            margin: 12px 0 24px;
            background: #FFFFFF;
            border-radius: 4px;
            overflow: hidden;
            font-size: 0.85em;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
            border: 1px solid #E0E0E0;
        }
        .cert-table th {
            background: #F5F5F5;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #E0E0E0;
            font-size: 0.78em;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .cert-table td {
            padding: 10px;
            border-bottom: 1px solid #E0E0E0;
            vertical-align: top;
        }
        .cert-table tr:hover { background: #F8F9FA; }
        .cert-table th.row-num, .cert-table td.row-num {
            width: 2.4em;
            text-align: right;
            color: #6A6A6A;
            font-variant-numeric: tabular-nums;
            white-space: nowrap;
        }
        .pill {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
        }
        .status-good { background: #E8F5E9; color: #1E7E34; }
        .status-warning { background: #FFF3CD; color: #856404; }
        .status-critical { background: #F8D7DA; color: #721C24; }
        .status-user { background: #E9ECEF; color: #6A6A6A; }
        .status-info { background: #E6F7FF; color: #0056B3; }
        .managed-status-cell { font-size: 0.9em; }
        .managed-status-cell.status-critical { font-weight: 600; }
        .info-box {
            background: #E6F7FF;
            border-left: 4px solid #007BFF;
            padding: 12px 15px;
            margin: 12px 0 0;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .warn-box {
            background: #FFF8E1;
            border-left: 4px solid #FFC107;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .warn-box p, .info-box p { margin: 0 0 8px; }
        .warn-box p:last-child, .info-box p:last-child { margin-bottom: 0; }
        .filter-note ol {
            margin: 0 0 10px 1.3em;
            padding: 0;
        }
        .filter-note li { margin: 4px 0; }
        .why-cell { max-width: 26em; }
        .why-cell .muted { margin-top: 2px; }
        .ok-box {
            background: #E8F5E9;
            border-left: 4px solid #28A745;
            padding: 12px 15px;
            margin: 12px 0;
            border-radius: 4px;
            font-size: 0.9em;
        }
        .muted { color: #6A6A6A; font-size: 0.8em; }
        .refresh-info {
            text-align: center;
            margin-top: 24px;
            color: #6A6A6A;
            font-size: 0.85em;
        }
        a { color: #007BFF; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .owner-cell { max-width: 280px; word-wrap: break-word; }
        .issuer-cell { max-width: 36em; word-break: break-word; }
        .issuer-cell code { font-size: 0.85em; display: block; }
        #inventory-table .col-evidence { display: none; }
        #inventory-table.view-ocpstrat-1826 .col-evidence,
        #inventory-table.view-uncovered .col-evidence,
        #inventory-table.view-external .col-evidence,
        #inventory-table.view-ocpstrat-2271 .col-evidence,
        #inventory-table.view-ocpstrat-1990 .col-evidence,
        #inventory-table.view-usermanaged .col-evidence { display: table-cell; }
        #inventory-table .ev { display: none; }
        #inventory-table.view-ocpstrat-1826 .ev-1826,
        #inventory-table.view-uncovered .ev-uncovered,
        #inventory-table.view-external .ev-external,
        #inventory-table.view-ocpstrat-2271 .ev-2271,
        #inventory-table.view-ocpstrat-1990 .ev-1990,
        #inventory-table.view-usermanaged .ev-usermanaged { display: block; }
        #inventory-table.view-ocpstrat-1826 .gap-pill { display: none; }
        .filter-group-label {
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            color: #6A6A6A;
            margin: 16px 0 8px;
        }
        #hpstrat99-table tr.filter-jump { cursor: pointer; }
        #hpstrat99-table tr.filter-jump:hover { background: #F8F9FA; }
        #hpstrat99-table tr.filter-jump.active { outline: 2px solid #007BFF; }
        .owner-cell details { margin-top: 4px; }
        .owner-cell details summary {
            cursor: pointer;
            color: #6A6A6A;
            font-size: 0.85em;
        }
        .registry-owner {
            margin: 8px 0;
            border: 1px solid #E0E0E0;
            border-radius: 4px;
            background: #FFFFFF;
        }
        .registry-owner > summary {
            padding: 8px 12px;
            cursor: pointer;
            font-weight: 600;
            list-style: none;
        }
        .registry-owner > summary::-webkit-details-marker { display: none; }
        .registry-owner > summary::before { content: "▸ "; color: #6A6A6A; }
        .registry-owner[open] > summary::before { content: "▾ "; }
        .registry-owner .registry-body { padding: 0 12px 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Certificate Roadmap Console</h1>
        <p>For OpenShift PMs and engineers: this cluster is the evidence for
            <a href="https://issues.redhat.com/browse/HPSTRAT-99" target="_blank" rel="noopener noreferrer">HPSTRAT-99</a>.
            Click a Feature count or a filter card — same control. Inventory columns stay
            put; the Evidence column changes with the Feature.</p>
        <div class="info-box">
            <strong>Generated:</strong> {{ generated_time }} &nbsp;|&nbsp; <strong>Cluster:</strong> {{ cluster_name }}
            {% if control_plane_topology %}&nbsp;|&nbsp; <strong>Control plane:</strong> {{ control_plane_topology }}{% endif %}
            &nbsp;|&nbsp; <a href="/api/workboard">Workboard JSON</a>
            &nbsp;|&nbsp; <a href="/api/certificates">Full JSON</a>
            &nbsp;|&nbsp; <a href="/api/uncovered">Missing-owner API</a>
        </div>
        <details class="glossary">
            <summary>Glossary — TLS registry, signer, CA, PEM, leaf, rotation, foreverPeriod, ShortCertRotation, owning component</summary>
            <div class="glossary-body">
                <p class="muted">Collapsed until you need it. Same words appear as filters and column values.</p>
                <dl>
                    <dt>TLS Registry</dt>
                    <dd>OpenShift’s inventory of platform TLS artifacts, generated by
                        <code>[sig-arch][Late] collect certificate data</code> the same way this console
                        collects from the live API: secrets with <code>tls.crt</code> (or a kubeconfig client cert)
                        and configmaps with CA-bundle keys (or a kubeconfig CA), in platform namespaces
                        (<code>openshift-*</code>, <code>kube-system</code>, …). Revisioned static-pod copies and
                        hashed monitoring objects are dropped. Copies of the same PEM are one logical cert with
                        several locations; ownership is still required <em>per location</em>.
                        The human report is
                        <a href="https://github.com/openshift/origin/blob/main/tls/README.md" target="_blank" rel="noopener noreferrer">tls/README.md</a>
                        / <a href="https://github.com/openshift/origin/blob/main/tls/ownership/ownership.md" target="_blank" rel="noopener noreferrer">ownership.md</a>
                        (grouped by owning Jira component). The missing-owners app on this cluster
                        groups live artifacts the same way. Payload e2e also scrapes cert files on nodes; this console does not.
                        <span class="use">Used for: knowing every platform TLS artifact, who owns it, and blocking new artifacts that lack <code>openshift.io/owning-component</code>.</span></dd>
                    <dt>TLS artifact</dt>
                    <dd>OpenShift’s name for a certificate key pair <em>or</em> a CA bundle in the TLS registry — a secret or configmap the collector accepted, not every PEM in the cluster.
                        <span class="use">Used for: talking about registry entries without saying “secret vs configmap” each time.</span></dd>
                    <dt>CA</dt>
                    <dd>Certificate Authority — a certificate allowed to sign other certificates. OpenShift has many (API, service, ingress, etcd).
                        <span class="use">Used for: establishing a chain of trust. Anything this CA has signed is accepted by clients that trust it.</span></dd>
                    <dt>Signer</dt>
                    <dd>The secret that holds a CA and its private key. Platform signers rotate at 80% of their own validity, except named 10-year CAs that are never regenerated
                        (<a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>,
                        installer kubeconfig signers, HyperShift oneshot). CNO <code>ovn-ca</code> / <code>signer-ca</code> are issued for 10 years but do rotate after 9.
                        <span class="use">Used for: issuing and renewing leaf certificates.</span></dd>
                    <dt>Leaf</dt>
                    <dd>An end-entity certificate (API serving, client, webhook) signed by a CA.
                        A platform-managed leaf is rotated by its owning operator on <em>that leaf’s</em>
                        schedule (library-go 80% of the leaf’s validity, or
                        <code>certificates.openshift.io/refresh-period</code>) — not on the CA’s schedule.
                        Service-CA serving certs use the same 2-year lifetime as the Service-CA;
                        kube-apiserver serving leaves under 10-year CAs are 30 days and still rotate.
                        Two exceptions do not auto-rotate:
                        <code>localhost-recovery-serving-certkey</code> (10-year leaf,
                        <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>),
                        and any <strong>user-managed</strong> leaf (you rotate it).
                        <span class="use">Used for: proving this server or client’s identity to whoever trusts the issuing CA.</span></dd>
                    <dt>CA bundle</dt>
                    <dd>One or more CA certificates stored together (a PEM list) in a configmap or secret. It does not hold the CA private key.
                        <span class="use">Used for: supplying a trust store to a process (apiserver, kubelet, operand) so it can verify other certificates.</span></dd>
                    <dt>Trust store</dt>
                    <dd>The set of CA certificates a component treats as trusted issuers. In this console that material appears as a CA bundle.
                        <span class="use">Used for: deciding whether a presented leaf is authentic. If it chains to a CA in the store, the TLS connection is trusted.</span></dd>
                    <dt>Injected</dt>
                    <dd>An <em>injected replica</em>: a CA bundle the platform copies into many namespaces automatically
                        (<code>kube-root-ca.crt</code>, <code>openshift-service-ca.crt</code>, <code>service-ca.crt</code>).
                        It is a replica of a signer’s public CA, not a separately owned certificate and not the private key.
                        This console tags those rows <strong>injected</strong> instead of missing-owner, and excludes them from “Will not rotate.”
                        <span class="use">Used for: giving every namespace a local trust store so pods can verify the API server and service-serving certificates.</span></dd>
                    <dt>PEM</dt>
                    <dd><strong>Privacy-Enhanced Mail</strong> — the original IETF name for this encoding; TLS still uses the same text format even though nobody emails certificates this way. A PEM block is Base64 between
                        <code>-----BEGIN CERTIFICATE-----</code> / <code>-----BEGIN … KEY-----</code> and the matching <code>END</code> line. One secret can hold several PEMs (a chain or a bundle).
                        <span class="use">Used for: storing certs and keys as data in Kubernetes secrets and configmaps.</span></dd>
                    <dt>Rotation</dt>
                    <dd>The owning operator replaces the certificate before <code>notAfter</code>. Platform-managed certs refresh at 80% of that cert’s lifetime, or at
                        <code>certificates.openshift.io/refresh-period</code>. Named 10-year CAs and user-managed certs are not rotated this way.
                        <span class="use">Used for: keeping TLS valid so certificates do not expire in production.</span></dd>
                    <dt>Rotate-at</dt>
                    <dd>The date this console predicts the operator will next refresh the cert (80% of validity, or the refresh annotation).
                        <span class="use">Used for: spotting stuck rotation. If that date is past and the row is not in “Will not rotate”, the operator may not be reconciling.</span></dd>
                    <dt>10-year CA</dt>
                    <dd>Issued for about 10 years (3650 days) and never regenerated. That is the
                        <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>
                        / installer / HyperShift oneshot gap. Short-lived certs that share those names (30d, 1y, 5y) still rotate and are not listed here.
                        <span class="use">Used for: signing leaves for the life of the cluster. The gap is there is no supported way to replace that CA yet.</span></dd>
                    <dt>foreverPeriod</dt>
                    <dd>The kube-apiserver operator’s name for a 10-year lifetime
                        (<code>10 × 365 × 24h</code>, not calendar years). It is a Go duration in
                        <code>certrotationcontroller.go</code>, not a Kubernetes annotation.
                        The operator sets those serving signers (and the localhost-recovery leaf)
                        to <code>Validity: foreverPeriod</code> and refresh at 8 years (80%).
                        Rotating the CA then would not publish a replacement trust bundle, so
                        the code treats that as “we effectively do not rotate.”
                        That is the
                        <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>
                        set: <code>localhost-serving-signer</code>,
                        <code>service-network-serving-signer</code>,
                        <code>loadbalancer-serving-signer</code>,
                        <code>localhost-recovery-serving-signer</code>,
                        and <code>localhost-recovery-serving-certkey</code>
                        (plus static-pod revisions <code>localhost-recovery-serving-certkey-2</code> …).
                        Installer and HyperShift 10-year CAs are the same gap by lifetime, but they
                        are not this operator variable. CNO OperatorPKI, MCS, and network-node-identity
                        10y certs are not <code>foreverPeriod</code>.
                        <span class="use">Used for: naming the kube-apiserver artifacts that will not auto-rotate, and explaining why their Validity is 10y.</span></dd>
                    <dt>ShortCertRotation</dt>
                    <dd>An install-time feature gate that shortens most library-go cert lifetimes to hours
                        (so payload tests can observe rotation). It does <em>not</em> rewrite
                        kube-apiserver <code>foreverPeriod</code> (10y). The payload test then skips any
                        remaining <code>ValidityDuration == "10y"</code> certs, and separately ignores
                        ingress and OLM namespaces whose operators never wired the gate.
                        <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>
                        on this console is the live list of certs that test ignores
                        (foreverPeriod, other 10y, ingress/OLM). Management still shows
                        which of those auto-rotate.
                        <span class="use">Used for: the OCPSTRAT-1826 filter — which certs the ShortCertRotation payload test ignores.</span></dd>
                    <dt>Owning component</dt>
                    <dd>The Jira component in <code>openshift.io/owning-component</code>. The OpenShift TLS registry requires this on every collected artifact so cert bugs route to a team.
                        <span class="use">Used for: assigning ownership. Empty means Missing Owner — OpenShift CI blocks new ones; five grandfathered ingress/kube-system gaps remain.</span></dd>
                    <dt>Description</dt>
                    <dd>The <code>openshift.io/description</code> annotation: API-docs style text for what the artifact is (who it authenticates, what it signs, which names it terminates).
                        <span class="use">Used for: telling a human (and this console) what the cert or CA bundle is for, not who owns the bug.</span></dd>
                    <dt>Validity</dt>
                    <dd>Lifetime of this certificate (<code>notAfter − notBefore</code>), not days remaining. A 10-year CA issued last month still shows Validity 10y and about 9 years left.
                        <span class="use">Used for: telling a 30-day rotating cert from a 10-year CA that will not be regenerated.</span></dd>
                </dl>
            </div>
        </details>
        {% if hosted_guest %}
        <div class="warn-box">
            This API is a <strong>hosted guest</strong> (<code>controlPlaneTopology: External</code>).
            The five kube-apiserver <code>foreverPeriod</code> signer secrets in
            <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>
            (<code>localhost-serving-signer</code>,
            <code>service-network-serving-signer</code>,
            <code>loadbalancer-serving-signer</code>,
            <code>localhost-recovery-serving-signer</code>,
            <code>localhost-recovery-serving-certkey</code>)
            are <strong>not stored in this guest</strong>. On a standalone cluster they live in
            <code>openshift-kube-apiserver-operator</code>; for this hosted cluster they live on
            the <strong>management cluster</strong> (and HyperShift 10-year CAs with private keys
            live in the hosted control-plane namespace). This console can only list secrets on
            <em>this</em> API. 10-year CAs that do appear here are copies of those signers.
            Scan the management cluster to see the signer secrets with keys.
        </div>
        {% endif %}
    </div>

    <div id="workboard-panel">
        {% if workboard and workboard.hpstrat99 %}
        <div class="section-title">HPSTRAT-99 — OpenShift product gaps on this cluster</div>
        <p class="muted">
            Outcome:
            <a href="{{ workboard.hpstrat99.outcome.url }}" target="_blank" rel="noopener noreferrer">{{ workboard.hpstrat99.outcome.key }}</a>
            {{ workboard.hpstrat99.outcome.title }}.
            Child Features below are the work the product team still has to ship.
            Open a Feature in Jira for its current status and priority.
            <strong>On this cluster</strong> is how many live gaps this console can see for that Feature.
        </p>
        <table class="cert-table" id="hpstrat99-table">
            <thead>
                <tr>
                    <th>Feature</th>
                    <th>On this cluster</th>
                    <th>What we measure</th>
                </tr>
            </thead>
            <tbody>
                {% for feat in workboard.hpstrat99.features %}
                <tr {% if feat.filter %}class="filter-jump" data-filter="{{ feat.filter }}" onclick="applyFilter('{{ feat.filter }}')"{% endif %}>
                    <td>
                        <a href="{{ feat.url }}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()"><code>{{ feat.key }}</code></a>
                        {% if feat.also_key %}
                        · <a href="{{ feat.also_url }}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()"><code>{{ feat.also_key }}</code></a>
                        {% endif %}
                        <div>{{ feat.title }}</div>
                    </td>
                    <td>
                        {% if not feat.observable %}
                        <span class="pill status-user">not in API PEMs</span>
                        {% elif feat.count == 0 %}
                        <span class="pill status-good">0</span>
                        {% else %}
                        <span class="pill status-critical">{{ feat.count }}</span>
                        {% endif %}
                    </td>
                    <td class="owner-cell">{{ feat.gap }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}

        <div class="section-title">What to fix (by OCPSTRAT)</div>
        <p class="muted">Every Feature stays listed even when this API has 0 matching rows (common on hosted guests).
            Rows under a Feature are examples on this API of why that work matters — for example, certificates already past rotate-at.
            <a href="https://issues.redhat.com/browse/OCPSTRAT-2029" target="_blank" rel="noopener noreferrer">OCPSTRAT-2029</a>
            is missing product capability (customer intermediate CA), not a PEM list.
            Owning component is <code>openshift.io/owning-component</code>
            (required on collector-accepted platform TLS artifacts; otherwise labeled not required).
            CA-bundle copies of the same 10-year CA are not listed.
            JSON: <a href="/api/workboard">/api/workboard</a>.</p>
        {% if workboard and workboard.by_ticket %}
        <p>
            <strong>{{ workboard.total }}</strong> example items on this API
            · {{ workboard.ticket_count }} Features listed
        </p>
        {% for group in workboard.by_ticket %}
        <details class="registry-owner">
            <summary>
                {% if group.ticket_url %}
                <a href="{{ group.ticket_url }}" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">{{ group.ticket }}</a>
                {% else %}{{ group.ticket }}{% endif %}
                — {{ group.title }} ({{ group.count }})
            </summary>
            <div class="registry-body">
                {% if group.why %}<p class="muted">{{ group.why }}</p>{% endif %}
                {% if group.gaps %}
                <table class="cert-table">
                    <thead>
                        <tr>
                            <th class="row-num">#</th>
                            {% if group.ticket != 'OCPSTRAT-2271' %}
                            <th>Owning component</th>
                            {% endif %}
                            <th>Namespace</th>
                            <th>Name</th>
                            {% if group.ticket == 'OCPSTRAT-1826' %}
                            <th>Why the SCR test skips</th>
                            {% endif %}
                            {% if group.ticket == 'OpenShift CI' %}
                            <th>New vs grandfathered</th>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-2029' %}
                            <th>Issuer</th>
                            {% endif %}
                            {% if group.ticket != 'OCPSTRAT-2271' %}
                            <th>Role</th>
                            <th>Validity</th>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-2271' %}
                            <th>Key type</th>
                            <th>Key size</th>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-1990' %}
                            <th class="has-tip" title="When the operator is expected to refresh this cert (certificates.openshift.io/refresh-period, CNO 9y, or library-go 80% of lifetime).">Rotate-at</th>
                            {% endif %}
                        </tr>
                    </thead>
                    <tbody>
                        {% for item in group.gaps %}
                        <tr>
                            <td class="row-num">{{ loop.index }}</td>
                            {% if group.ticket != 'OCPSTRAT-2271' %}
                            <td class="owner-cell">
                                {% if item.owning_component %}
                                {{ item.owning_component }}
                                {% elif item.needs_owning_component %}
                                <span class="pill status-critical">no owner</span>
                                {% else %}
                                <span class="pill status-user">not required</span>
                                {% endif %}
                            </td>
                            {% endif %}
                            <td>{{ item.namespace }}</td>
                            <td><code>{{ item.name }}</code>
                                {% if item.is_forever_period %}
                                <div><span class="pill status-critical">foreverPeriod</span></div>
                                {% endif %}
                                {% if item.copy_count and item.copy_count > 1 %}
                                <div class="muted">{{ item.copy_count }} copies of this certificate</div>
                                {% endif %}
                                {% if item.installer_ca_lifecycle == 'keep-recovery' %}
                                <div class="muted">Keep: original admin kubeconfig CA</div>
                                {% elif item.installer_ca_lifecycle == 'revocable-bootstrap' %}
                                <div class="muted">Revocable leftover master-bootstrap CA</div>
                                {% endif %}
                            </td>
                            {% if group.ticket == 'OCPSTRAT-1826' %}
                            <td class="owner-cell">
                                {% if item.scr_skip_kind == 'foreverPeriod' %}
                                <span class="pill status-critical">foreverPeriod</span>
                                {% elif item.scr_skip_kind == '10y' %}
                                <span class="pill status-warning">10y skip</span>
                                {% elif item.scr_skip_kind == 'namespace' %}
                                <span class="pill status-user">namespace skip</span>
                                {% elif item.category == 'will-not-rotate' %}
                                <span class="pill status-critical">will not auto-rotate</span>
                                {% endif %}
                                {% if item.scr_skip_label %}
                                <div class="muted">{{ item.scr_skip_label }}</div>
                                {% endif %}
                            </td>
                            {% endif %}
                            {% if group.ticket == 'OpenShift CI' %}
                            <td>
                                {% if item.status == 'grandfathered' %}
                                <span class="pill status-warning">grandfathered</span>
                                {% else %}
                                <span class="pill status-critical">new</span>
                                {% endif %}
                            </td>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-2029' %}
                            <td class="owner-cell">{% if item.issuer %}<code>{{ item.issuer }}</code>{% else %}—{% endif %}</td>
                            {% endif %}
                            {% if group.ticket != 'OCPSTRAT-2271' %}
                            <td>{{ item.role or '—' }}</td>
                            <td>{{ item.validity_label or '—' }}</td>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-2271' %}
                            <td>{{ item.key_type or '—' }}</td>
                            <td>{% if item.key_size %}<span class="pill status-critical">{{ item.key_size }} bits</span>{% else %}—{% endif %}</td>
                            {% endif %}
                            {% if group.ticket == 'OCPSTRAT-1990' %}
                            <td>{% if item.rotate_at %}{{ item.rotate_at }}
                                {% if item.rotate_at_source %}<div class="muted">{{ item.rotate_at_source }}{% if item.days_until_rotate is not none %} · {{ item.days_until_rotate }}d{% endif %}</div>{% endif %}
                                {% else %}—{% endif %}</td>
                            {% endif %}
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                {% if group.ticket == 'OCPSTRAT-2029' %}
                <div class="ok-box">Not a to-do list of secrets. This Feature is missing product capability
                    (accept a customer intermediate CA at install), not a set of PEMs to re-issue.
                    Operator-local CAs and proxy trust bundles stay on the External issuers filter;
                    they are out of scope for the intermediate CA.</div>
                {% else %}
                <div class="ok-box">No examples on this API.</div>
                {% endif %}
                {% endif %}
            </div>
        </details>
        {% endfor %}
        {% else %}
        <div class="ok-box">No product-team gaps on this API.</div>
        {% endif %}
    </div>

    <div class="filter-group-label">Features (HPSTRAT-99)</div>
    <div class="summary">
        <div class="summary-card" data-filter="ocpstrat-1826" onclick="applyFilter('ocpstrat-1826')">
            <h3>OCPSTRAT-1826</h3>
            <div class="summary-count" style="color: #721C24;">{{ summary.ocpstrat_1826_filter }}</div>
        </div>
        <div class="summary-card" data-filter="ocpstrat-2272" onclick="applyFilter('ocpstrat-2272')">
            <h3>OCPSTRAT-2272</h3>
            <div class="summary-count" style="color: #721C24;">{{ summary.validity_over_5y }}</div>
        </div>
        <div class="summary-card" data-filter="ocpstrat-2273" onclick="applyFilter('ocpstrat-2273')">
            <h3>OCPSTRAT-2273</h3>
            <div class="summary-count">{{ summary.validity_over_2y }}</div>
        </div>
        <div class="summary-card" data-filter="ocpstrat-2271" onclick="applyFilter('ocpstrat-2271')">
            <h3>OCPSTRAT-2271</h3>
            <div class="summary-count" style="color: #721C24;">{{ summary.below_4096_ca }}</div>
        </div>
        <div class="summary-card" data-filter="ocpstrat-1990" onclick="applyFilter('ocpstrat-1990')">
            <h3>OCPSTRAT-1990</h3>
            <div class="summary-count">{{ summary.past_rotate_at }}</div>
        </div>
        <div class="summary-card" data-filter="uncovered" onclick="applyFilter('uncovered')">
            <h3>Missing owners</h3>
            <div class="summary-count" style="color: #856404;">{{ summary.uncovered }}</div>
        </div>
        <div class="summary-card" data-filter="usermanaged" onclick="applyFilter('usermanaged')">
            <h3>User-managed</h3>
            <div class="summary-count" style="color: #721C24;">{{ summary.user_managed }}</div>
        </div>
    </div>
    <div class="filter-group-label">Inventory</div>
    <div class="summary">
        <div class="summary-card active" data-filter="all" onclick="applyFilter('all')">
            <h3>Total</h3>
            <div class="summary-count">{{ summary.total }}</div>
        </div>
        <div class="summary-card" data-filter="signer" onclick="applyFilter('signer')">
            <h3>Signers</h3>
            <div class="summary-count">{{ summary.signers }}</div>
        </div>
        <div class="summary-card" data-filter="leaf" onclick="applyFilter('leaf')">
            <h3>Leaves</h3>
            <div class="summary-count">{{ summary.leaves }}</div>
        </div>
        <div class="summary-card" data-filter="external" onclick="applyFilter('external')">
            <h3>External issuers</h3>
            <div class="summary-count" style="color: #0056B3;">{{ summary.external_issuers }}</div>
        </div>
    </div>

    <div id="filter-notes">
        <div class="info-box filter-note" data-filter-note="all">
            Platform certs should rotate before they expire. Feature cards are the
            HPSTRAT-99 gaps on this API. <strong>Validity</strong> is lifetime
            (<code>notAfter − notBefore</code>), not days left.
        </div>
        <div class="warn-box filter-note" data-filter-note="ocpstrat-1826" style="display: none;">
            <a href="https://issues.redhat.com/browse/OCPSTRAT-1826" target="_blank" rel="noopener noreferrer">OCPSTRAT-1826</a>:
            certs the ShortCertRotation payload test ignores.
            Skip kinds: <code>foreverPeriod</code> (kube-apiserver 10y),
            <code>10y</code> ValidityDuration (MCS / OVN / NNI),
            <code>namespace</code> (ingress / OLM).
            Auto-rotated leftovers stay listed — Management says who rotates.
            Installer 10y leftovers also hit the 10y skip.
        </div>
        <div class="warn-box filter-note" data-filter-note="ocpstrat-2272" style="display: none;">
            <a href="https://issues.redhat.com/browse/OCPSTRAT-2272" target="_blank" rel="noopener noreferrer">OCPSTRAT-2272</a>
            phase 1: platform certs with a private key whose lifetime is still over 5 years.
        </div>
        <div class="warn-box filter-note" data-filter-note="ocpstrat-2273" style="display: none;">
            <a href="https://issues.redhat.com/browse/OCPSTRAT-2273" target="_blank" rel="noopener noreferrer">OCPSTRAT-2273</a>
            phase 2: lifetime over 2 years and at most 5 years.
        </div>
        <div class="warn-box filter-note" data-filter-note="ocpstrat-2271" style="display: none;">
            <a href="https://issues.redhat.com/browse/OCPSTRAT-2271" target="_blank" rel="noopener noreferrer">OCPSTRAT-2271</a>
            (GA <a href="https://issues.redhat.com/browse/OCPSTRAT-3050" target="_blank" rel="noopener noreferrer">OCPSTRAT-3050</a>):
            self-signed RSA signers below 4096 bits. Same live set for both tickets.
        </div>
        <div class="warn-box filter-note" data-filter-note="ocpstrat-1990" style="display: none;">
            <a href="https://issues.redhat.com/browse/OCPSTRAT-1990" target="_blank" rel="noopener noreferrer">OCPSTRAT-1990</a>:
            secrets with a private key whose predicted rotate-at is past
            (not will-not-rotate, not user-managed, not CA-bundle copies).
        </div>
        <div class="warn-box filter-note" data-filter-note="uncovered" style="display: none;">
            TLS collector would accept this object and
            <code>openshift.io/owning-component</code> is empty.
            Evidence: new (CI fails) vs grandfathered (five remove-only names).
            {{ summary.missing_owners_new }} new, {{ summary.missing_owners_known }} grandfathered.
        </div>
        <div class="info-box filter-note" data-filter-note="signer" style="display: none;">
            CAs that issue other certificates. Most rotate at 80% of validity.
            OVN OperatorPKI (<code>ovn-ca</code>, <code>signer-ca</code>) is 10y and refreshes at 9y.
        </div>
        <div class="info-box filter-note" data-filter-note="leaf" style="display: none;">
            End-entity certs. Platform leaves rotate on their own schedule, not the CA’s.
            Exception: recovery <code>certkey</code> (foreverPeriod) and user-managed leaves.
        </div>
        <div class="warn-box filter-note" data-filter-note="external" style="display: none;">
            Issuer DN is not classified as OpenShift internal PKI.
            Evidence is that DN. This is not
            <a href="https://issues.redhat.com/browse/OCPSTRAT-2029" target="_blank" rel="noopener noreferrer">OCPSTRAT-2029</a>
            (customer intermediate CA for platform certs — not visible as PEMs yet).
        </div>
        <div class="warn-box filter-note" data-filter-note="usermanaged" style="display: none;">
            An administrator supplied this cert; OpenShift will not rotate it.
            Evidence is days left. Not OCPSTRAT-1826.
        </div>
    </div>

    <div id="scr-panel" style="display: none;">
        <div class="section-title">Named secrets the ShortCertRotation test ignores</div>
        <p class="muted">Presence checklist for the operator-wiring set. Skip kind is
            foreverPeriod, 10y, or namespace. Hosted guests usually lack foreverPeriod
            secrets (they live on the management cluster). Inventory rows below include
            installer 10y leftovers that also hit the 10y skip.</p>
        <table class="cert-table" id="scr-unshortened-table">
            <thead>
                <tr>
                    <th class="row-num">#</th>
                    <th>Secret</th>
                    <th>Namespace</th>
                    <th>Skip kind</th>
                    <th>On this API</th>
                </tr>
            </thead>
            <tbody>
                {% for row in scr_unshortened %}
                <tr>
                    <td class="row-num">{{ loop.index }}</td>
                    <td><code>{{ row.name }}</code>
                        {% if row.revision_count and row.revision_count > 1 %}
                        <div class="muted">{{ row.revision_count }} objects (includes static-pod revisions)</div>
                        {% endif %}
                    </td>
                    <td>{{ row.namespace }}</td>
                    <td>
                        {% if row.skip_kind == 'foreverPeriod' %}
                        <span class="pill status-critical">foreverPeriod</span>
                        {% elif row.skip_kind == '10y' %}
                        <span class="pill status-warning">10y</span>
                        {% else %}
                        <span class="pill status-user">namespace</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if row.found %}
                        <span class="pill status-info">present</span>
                        {% elif hosted_guest and row.skip_kind == 'foreverPeriod' %}
                        <span class="pill status-user">not on this API</span>
                        {% else %}
                        <span class="pill status-warning">not on this API</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div id="uncovered-panel" style="display: none;">
        <div class="section-title">Grandfathered missing owners (live check)</div>
        <p class="muted">Five remove-only names from the TLS-registry ownership snapshot.</p>
        <table class="cert-table" id="origin-known-table">
            <thead>
                <tr>
                    <th class="row-num">#</th>
                    <th>Kind</th>
                    <th>Namespace</th>
                    <th>Name</th>
                    <th>On this API</th>
                </tr>
            </thead>
            <tbody>
                {% for row in origin_expected %}
                <tr>
                    <td class="row-num">{{ loop.index }}</td>
                    <td>{{ 'certificate' if row.origin_kind == 'certificate' else 'CA bundle' }}</td>
                    <td>{{ row.namespace }}</td>
                    <td><code>{{ row.name }}</code></td>
                    <td>
                        {% if not row.found %}
                        <span class="pill status-user">not on this API</span>
                        {% elif row.still_missing %}
                        <span class="pill status-critical">present, no owner</span>
                        {% else %}
                        <span class="pill status-good">present, has owner</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <div class="section-title"><span id="cert-heading-label">Certificates</span> <span class="muted" id="visible-count"></span></div>
    {% if collapsed_injected %}
    <p class="muted">Table shows unique resources. {{ collapsed_injected }} identical injected CA copies
        (same PEM as <code>kube-root-ca.crt</code> / service-ca) are collapsed here.
        Full dump: <a href="/api/certificates">/api/certificates</a>.</p>
    {% endif %}
    <table class="cert-table" id="inventory-table">
        <thead>
            <tr>
                <th class="row-num">#</th>
                <th>Name</th>
                <th>Namespace</th>
                <th class="has-tip" title="Jira component in openshift.io/owning-component. Open Description on the name for openshift.io/description.">Owning component</th>
                <th class="has-tip" title="Signer (CA + key), leaf (end-entity), or CA bundle (trust store).">Role</th>
                <th class="has-tip" title="Certificate lifetime (notAfter minus notBefore), not days remaining.">Validity</th>
                <th class="has-tip" title="Who rotates this artifact.">Management</th>
                <th class="col-evidence" id="evidence-heading">Evidence</th>
            </tr>
        </thead>
        <tbody id="cert-body">
            {% for cert in certificates %}
            <tr
                data-role="{{ cert.cert_role }}"
                data-registry="{{ cert.tls_registry_status }}"
                data-origin="{{ cert.issuer_origin }}"
                data-1826="{{ '1' if cert.filter_1826 else '0' }}"
                data-2272="{{ '1' if cert.filter_2272 else '0' }}"
                data-2273="{{ '1' if cert.filter_2273 else '0' }}"
                data-keypolicy="{{ cert.key_policy }}"
                data-pastrotate="{{ '1' if cert.days_until_rotate is not none and cert.days_until_rotate < 0 and not cert.will_not_auto_rotate and cert.has_private_key and cert.cert_role != 'ca-bundle' and not cert.injected_ca_copy else '0' }}"
                data-usermanaged="{{ '1' if 'User-Managed' in cert.managed_status else '0' }}"
            >
                <td class="row-num"></td>
                <td>{{ cert.name }}
                    {% if cert.copy_count and cert.copy_count > 1 %}
                    <div class="muted" title="{{ (cert.copy_namespaces or []) | join(', ') }}">×{{ cert.copy_count }} copies</div>
                    {% endif %}
                    {% if cert.is_forever_period %}
                    <div class="gap-pill"><span class="pill status-critical">foreverPeriod</span></div>
                    {% elif cert.not_shortened_by_scr %}
                    <div class="gap-pill"><span class="pill status-warning">SCR skip</span></div>
                    {% elif cert.will_not_auto_rotate %}
                    <div class="gap-pill"><span class="pill status-critical">will not auto-rotate</span></div>
                    {% endif %}
                    {% if cert.is_forever_period_leaf and cert.name != 'localhost-recovery-serving-certkey' %}
                    <div class="muted">Static-pod revision of localhost-recovery-serving-certkey</div>
                    {% endif %}
                    {% if cert.installer_ca_lifecycle == 'keep-recovery' %}
                    <div class="muted">Keep: original admin kubeconfig CA</div>
                    {% elif cert.installer_ca_lifecycle == 'revocable-bootstrap' %}
                    <div class="muted">Revocable leftover master-bootstrap CA</div>
                    {% endif %}
                    {% if cert.owning_description %}
                    <details><summary>Description</summary>
                    <div class="muted">{{ cert.owning_description }}</div>
                    </details>
                    {% endif %}
                </td>
                <td>{{ cert.namespace }}</td>
                <td class="owner-cell">
                    {% if cert.owning_component %}
                    {{ cert.owning_component }}
                    {% elif cert.needs_owning_component %}
                    <span class="pill status-critical">no owner</span>
                    {% else %}
                    <span class="pill status-user">not required</span>
                    {% endif %}
                </td>
                <td>
                    {% if cert.cert_role == 'signer' %}
                    <span class="pill status-warning" title="CA plus private key.">signer</span>
                    {% elif cert.cert_role == 'ca-bundle' %}
                    <span class="pill status-user" title="Trust store copy, not the private key.">ca-bundle</span>
                    {% else %}
                    <span class="pill status-info" title="End-entity cert signed by a CA.">leaf</span>
                    {% endif %}
                </td>
                <td>
                    {{ cert.validity_label or '—' }}
                    {% if cert.validity_days %}
                    <div class="muted">{{ cert.validity_days }}d lifetime</div>
                    {% endif %}
                    {% if cert.pem_cert_count and cert.pem_cert_count > 1 %}
                    <div class="muted">bundle of {{ cert.pem_cert_count }}</div>
                    {% endif %}
                </td>
                <td class="managed-status-cell status-{{ cert.mgmt_class }}">
                    {{ cert.mgmt_label }}
                </td>
                <td class="col-evidence">
                    <div class="ev ev-1826">
                        {% if cert.scr_skip_kind == 'foreverPeriod' %}
                        <span class="pill status-critical">foreverPeriod</span>
                        {% elif cert.scr_skip_kind == '10y' %}
                        <span class="pill status-warning">10y skip</span>
                        {% elif cert.scr_skip_kind == 'namespace' %}
                        <span class="pill status-user">namespace skip</span>
                        {% elif cert.will_not_auto_rotate %}
                        <span class="pill status-critical">will not auto-rotate</span>
                        {% else %}
                        —
                        {% endif %}
                        {% if cert.scr_skip_label %}
                        <div class="muted">{{ cert.scr_skip_label }}</div>
                        {% elif cert.no_rotate_label %}
                        <div class="muted">{{ cert.no_rotate_label }}</div>
                        {% endif %}
                    </div>
                    <div class="ev ev-uncovered">
                        {% if cert.known_origin_violation %}
                        <span class="pill status-warning">grandfathered</span>
                        {% else %}
                        <span class="pill status-critical">new</span>
                        {% endif %}
                    </div>
                    <div class="ev ev-external issuer-cell">
                        {% set issuer_list = cert.issuers if cert.issuers else ([cert.issuer] if cert.issuer else []) %}
                        {% if issuer_list %}
                            {% for iss in issuer_list %}
                            <code>{{ iss }}</code>
                            {% endfor %}
                        {% else %}
                        —
                        {% endif %}
                    </div>
                    <div class="ev ev-2271">
                        {% if cert.key_size %}
                            {% if cert.key_policy == 'below-4096-ca' %}
                            <span class="pill status-critical">{{ cert.key_type }} {{ cert.key_size }} bits</span>
                            {% else %}
                            {{ cert.key_type }} {{ cert.key_size }} bits
                            {% endif %}
                        {% else %}
                        —
                        {% endif %}
                    </div>
                    <div class="ev ev-1990">
                        {{ cert.rotate_at or '—' }}
                        {% if cert.rotate_at_source %}
                        <div class="muted">{{ cert.rotate_at_source }}{% if cert.days_until_rotate is not none %} · {{ cert.days_until_rotate }}d{% endif %}</div>
                        {% endif %}
                    </div>
                    <div class="ev ev-usermanaged">
                        {% if cert.days_remaining is not none and cert.days_remaining < 30 %}
                        <span class="pill status-critical">{{ cert.days_remaining }}d left</span>
                        {% elif cert.days_remaining is not none and cert.days_remaining < 90 %}
                        <span class="pill status-warning">{{ cert.days_remaining }}d left</span>
                        {% elif cert.days_remaining is not none %}
                        {{ cert.days_remaining }}d left
                        {% else %}
                        —
                        {% endif %}
                    </div>
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>

    <div class="refresh-info">
        Page auto-refreshes every 5 minutes | Last updated: {{ generated_time }} |
        Rotate-at uses <code>certificates.openshift.io/refresh-period</code> when present, otherwise library-go 80% of validity.
    </div>
<script>
function applyFilter(name) {
  var rows = document.querySelectorAll('#cert-body tr');
  var visible = 0;
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var show = true;
    if (name === 'uncovered') show = row.getAttribute('data-registry') === 'uncovered';
    else if (name === 'signer') show = row.getAttribute('data-role') === 'signer';
    else if (name === 'leaf') show = row.getAttribute('data-role') === 'leaf';
    else if (name === 'external') show = row.getAttribute('data-origin') === 'external';
    else if (name === 'ocpstrat-1826') show = row.getAttribute('data-1826') === '1';
    else if (name === 'ocpstrat-2272') show = row.getAttribute('data-2272') === '1';
    else if (name === 'ocpstrat-2273') show = row.getAttribute('data-2273') === '1';
    else if (name === 'ocpstrat-2271') show = row.getAttribute('data-keypolicy') === 'below-4096-ca';
    else if (name === 'ocpstrat-1990') show = row.getAttribute('data-pastrotate') === '1';
    else if (name === 'usermanaged') show = row.getAttribute('data-usermanaged') === '1';
    row.style.display = show ? '' : 'none';
    var num = row.querySelector('.row-num');
    if (show) {
      visible++;
      if (num) num.textContent = visible;
    } else if (num) {
      num.textContent = '';
    }
  }
  var label = document.getElementById('visible-count');
  if (label) label.textContent = '(' + visible + ' shown)';
  var chips = document.querySelectorAll('.summary-card');
  for (var j = 0; j < chips.length; j++) {
    if (chips[j].getAttribute('data-filter') === name) chips[j].classList.add('active');
    else chips[j].classList.remove('active');
  }
  var hp = document.querySelectorAll('#hpstrat99-table tr.filter-jump');
  for (var h = 0; h < hp.length; h++) {
    if (hp[h].getAttribute('data-filter') === name) hp[h].classList.add('active');
    else hp[h].classList.remove('active');
  }
  var panel = document.getElementById('uncovered-panel');
  if (panel) panel.style.display = (name === 'uncovered') ? '' : 'none';
  var scrp = document.getElementById('scr-panel');
  if (scrp) scrp.style.display = (name === 'ocpstrat-1826') ? '' : 'none';
  var notes = document.querySelectorAll('[data-filter-note]');
  for (var n = 0; n < notes.length; n++) {
    notes[n].style.display = (notes[n].getAttribute('data-filter-note') === name) ? '' : 'none';
  }
  var headings = {
    all: 'Certificates',
    uncovered: 'Missing owners',
    signer: 'Signers',
    leaf: 'Leaves',
    external: 'External issuers (not OCPSTRAT-2029)',
    'ocpstrat-1826': 'OCPSTRAT-1826 — ShortCertRotation test ignores',
    'ocpstrat-2272': 'OCPSTRAT-2272 — validity over 5y',
    'ocpstrat-2273': 'OCPSTRAT-2273 — validity 2–5y',
    'ocpstrat-2271': 'OCPSTRAT-2271 — RSA CA below 4096',
    'ocpstrat-1990': 'OCPSTRAT-1990 — past rotate-at',
    usermanaged: 'User-managed — action needed'
  };
  var heading = document.getElementById('cert-heading-label');
  if (heading) heading.textContent = headings[name] || 'Certificates';
  var evidenceHead = {
    'ocpstrat-1826': 'Why the SCR test skips',
    uncovered: 'New vs grandfathered',
    external: 'Issuer DN',
    'ocpstrat-2271': 'Key size',
    'ocpstrat-1990': 'Rotate-at',
    usermanaged: 'Days left'
  };
  var eh = document.getElementById('evidence-heading');
  if (eh) eh.textContent = evidenceHead[name] || 'Evidence';
  var inv = document.getElementById('inventory-table');
  if (inv) {
    inv.className = 'cert-table view-' + name;
  }
}
applyFilter('all');
</script>
</body>
</html>
'''

if os.environ.get('CERT_DISCOVERY_NO_START') != '1':
    db_available = init_database()
    if db_available:
        logger.info("Database initialized and available for historical tracking")
    else:
        logger.warning("Database not available - running without persistent storage")
    cert_cache.start_background_refresh()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)

