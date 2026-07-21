#!/bin/sh
# Audited, fail-closed G008 startup. Secret payloads never cross argv, environment, or logs.
set -eu
umask 077
exec >/dev/null 2>&1

METADATA_ROOT=http://169.254.169.254/computeMetadata/v1
METADATA="$METADATA_ROOT/instance/attributes"
METADATA_IP=169.254.169.254
BOOTSTRAP_UID=65530
RUNTIME_DIR=/run/secrets
TRANSACTION_DIR=/run/recova-g008-transaction
STATE_DIR=/var/lib/recova-g008/consumed
COMPOSE_FILE=/opt/recova/compose.yaml
RUNNER_SOURCE=/opt/g008/run-g008-live-smoke.py
TRUSTED_KEYSET_SOURCE=/opt/g008/trusted/phase_c_live_preflight_v1.json
PROVIDER_SCRIPT_SOURCE=/opt/g009/run-registration-transaction.js
EVIDENCE_ROOT=/var/lib/recova-g008/evidence
COMPOSE_ENV_FILE=/opt/recova/g008-compose.env
COMPOSE_ROOT=/opt/recova


bootstrap_curl() {
  /usr/bin/setpriv --reuid "$BOOTSTRAP_UID" --regid "$BOOTSTRAP_UID" --clear-groups \
    /usr/bin/curl --fail --silent --show-error --max-time 5 \
    -H 'Metadata-Flavor: Google' "$1"
}

metadata() {
  bootstrap_curl "$METADATA/$1"
}

contain() {
  status=$?
  cleanup_failed=0
  trap '' HUP INT TERM

  /usr/bin/env -u COMPOSE_ENV_FILES -u COMPOSE_FILE -u COMPOSE_PROJECT_NAME \
    /usr/bin/docker compose --env-file "$COMPOSE_ENV_FILE" --project-directory "$COMPOSE_ROOT" \
    -f "$COMPOSE_FILE" --profile g008-live-smoke down --timeout 0 >/dev/null 2>&1 || cleanup_failed=1
  containers=$(/usr/bin/docker ps --quiet || true)
  if [ -n "$containers" ]; then
    /usr/bin/docker stop $containers >/dev/null 2>&1 || cleanup_failed=1
  fi
  /usr/bin/systemctl stop docker.service docker.socket containerd.service containerd.socket >/dev/null 2>&1 || cleanup_failed=1
  for directory in "$TRANSACTION_DIR" "$RUNTIME_DIR"; do
    if /usr/bin/mountpoint --quiet "$directory"; then
      /usr/bin/umount "$directory" || cleanup_failed=1
    fi
    if [ -d "$directory" ]; then
      /usr/bin/rmdir "$directory" || cleanup_failed=1
    fi
  done
  /usr/bin/rm -f "$COMPOSE_ENV_FILE" || cleanup_failed=1

  if [ "$status" -eq 0 ] && [ "$cleanup_failed" -ne 0 ]; then
    status=1
  fi
  trap - EXIT HUP INT TERM
  exit "$status"
}
trap contain EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# No container runtime or candidate process may run before metadata containment.
/usr/bin/systemctl stop docker.service docker.socket containerd.service containerd.socket
/usr/bin/systemctl disable docker.service docker.socket containerd.service containerd.socket
/usr/bin/systemctl mask --runtime docker.service docker.socket containerd.service containerd.socket
if ! /usr/bin/getent group "$BOOTSTRAP_UID" >/dev/null; then
  /usr/sbin/groupadd --system --gid "$BOOTSTRAP_UID" recova-g008-bootstrap
fi
[ "$(/usr/bin/getent group "$BOOTSTRAP_UID" | /usr/bin/cut -d: -f1)" = recova-g008-bootstrap ]
if ! /usr/bin/getent passwd "$BOOTSTRAP_UID" >/dev/null; then
  /usr/sbin/useradd --system --uid "$BOOTSTRAP_UID" --gid "$BOOTSTRAP_UID" \
    --no-create-home --shell /usr/sbin/nologin recova-g008-bootstrap
fi
[ "$(/usr/bin/getent passwd "$BOOTSTRAP_UID" | /usr/bin/cut -d: -f1)" = recova-g008-bootstrap ]

# Only the unprivileged, single-purpose bootstrap UID may reach metadata. Host root,
# forwarded container traffic, and every other UID are rejected before the first fetch.
/usr/sbin/iptables -I OUTPUT 1 -d "$METADATA_IP/32" -m owner --uid-owner "$BOOTSTRAP_UID" -j ACCEPT
/usr/sbin/iptables -I OUTPUT 2 -d "$METADATA_IP/32" -j REJECT
/usr/sbin/iptables -I FORWARD 1 -d "$METADATA_IP/32" -j REJECT
/usr/sbin/iptables -C OUTPUT -d "$METADATA_IP/32" -m owner --uid-owner "$BOOTSTRAP_UID" -j ACCEPT
/usr/sbin/iptables -C OUTPUT -d "$METADATA_IP/32" -j REJECT
/usr/sbin/iptables -C FORWARD -d "$METADATA_IP/32" -j REJECT
if /usr/bin/curl --fail --silent --max-time 2 -H 'Metadata-Flavor: Google' \
  "$METADATA_ROOT/instance/service-accounts/default/token" >/dev/null 2>&1; then
  exit 1
fi
bootstrap_curl "$METADATA_ROOT/instance/id" >/dev/null

[ "$(metadata workload-dispatch-enabled)" = TRUE ]
[ "$(metadata sip-register-enabled)" = TRUE ]
[ "$(metadata media-enabled)" = TRUE ]
[ "$(metadata outbound-call-enabled)" = TRUE ]
[ "$(metadata inbound-call-enabled)" = TRUE ]
[ "$(metadata g008-secret-mounts-read-only)" = TRUE ]

nonce_digest=$(metadata g008-execution-nonce-sha256)
manifest_handle=$(metadata g008-bootstrap-manifest-handle)
manifest_binding=$(metadata g008-bootstrap-manifest-binding-sha256)
review_payload_digest=$(metadata g008-review-payload-digest)
binding_receipt=$(metadata g008-exact-binding-receipt-sha256)
request_digest=$(metadata g008-execution-request-sha256)
operator_credential_digest=$(metadata g008-operator-credential-sha256)
runner_digest=$(metadata g008-execution-runner-sha256)
keyset_digest=$(metadata g008-trusted-keyset-sha256)
provider_script_digest=$(metadata g008-provider-script-sha256)
live_window_end=$(metadata live-window-end-utc)
watchdog_cutoff=$(metadata g008-watchdog-cutoff-utc)
cost_ceiling=$(metadata g008-watchdog-cost-ceiling-krw)
case "$nonce_digest:$manifest_binding:$binding_receipt:$request_digest:$operator_credential_digest:$runner_digest:$keyset_digest:$provider_script_digest:${review_payload_digest#sha256:}" in
  *[!0-9a-f:]*|:|*::*|*:) exit 1 ;;
esac
for digest in \
  "$nonce_digest" "$manifest_binding" "$binding_receipt" "$request_digest" \
  "$operator_credential_digest" "$runner_digest" "$keyset_digest" "$provider_script_digest"
do
  [ "${#digest}" -eq 64 ]
done
case "$review_payload_digest" in
  sha256:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) exit 1 ;;
esac
[ "$binding_receipt" = "$manifest_binding" ]
case "$manifest_handle" in
  projects/*/secrets/*/versions/*) ;;
  *) exit 1 ;;
esac

/usr/bin/install -d -m 0700 /var/lib/recova-g008 "$STATE_DIR"
# mkdir is the durable, atomic consume operation. It precedes every runtime side effect.
/usr/bin/mkdir "$STATE_DIR/$nonce_digest"
/usr/bin/install -d -m 0700 "$EVIDENCE_ROOT"
/usr/bin/mkdir "$EVIDENCE_ROOT/$nonce_digest"
/usr/bin/chown 1000:1000 "$EVIDENCE_ROOT/$nonce_digest"
/usr/bin/chmod 0700 "$EVIDENCE_ROOT/$nonce_digest"
/bin/sync "$EVIDENCE_ROOT"
/bin/sync "$STATE_DIR"

for directory in "$RUNTIME_DIR" "$TRANSACTION_DIR"; do
  /usr/bin/install -d -m 0700 -o "$BOOTSTRAP_UID" -g "$BOOTSTRAP_UID" "$directory"
  /usr/bin/mount -t tmpfs -o rw,nosuid,nodev,noexec,size=2m,mode=0700,uid="$BOOTSTRAP_UID",gid="$BOOTSTRAP_UID" tmpfs "$directory"
done
# Bind the required Google APIs to the restricted VIP without DNS or general Internet egress.
printf '%s\n' \
  '199.36.153.4 secretmanager.googleapis.com' \
  '199.36.153.4 iamcredentials.googleapis.com' >>/etc/hosts

# The sole metadata-published secret reference is an opaque manifest handle. The
# externally provisioned manifest contains the numeric purpose inventory, while
# Terraform state and instance metadata persist only its redacted binding digest.
/usr/bin/setpriv --reuid "$BOOTSTRAP_UID" --regid "$BOOTSTRAP_UID" --clear-groups \
  /usr/bin/python3 - "$RUNTIME_DIR" "$TRANSACTION_DIR" "$manifest_handle" "$manifest_binding" \
  "$request_digest" "$nonce_digest" "$operator_credential_digest" <<'PY'
import base64
import hashlib
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request

REFERENCE = re.compile(r"projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*\Z")
SERVICE_ACCOUNT = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com\Z")
TRANSACTION_PURPOSES = {
    "f12_mtls_private_key",
    "f12_mtls_certificate",
    "f12_mtls_ca_certificate",
    "registration_attestation_es256_private_key",
    "registration_f12_endpoint_credential",
}
EXECUTION_KEYS = {"request", "sip_username", "sip_password", "sip_realm", "target", "execution_nonce", "operator_credential"}
EXPECTED_MOUNTS = {
    "postgres_password": ("/run/secrets/g008-recova-postgres-password", "backend"),
    "redis_password": ("/run/secrets/g008-recova-redis-password", "backend"),
    "f12_tls_private_key": ("/run/secrets/g008-f12-tls-private-key", "f12_ingress"),
    "f12_tls_certificate": ("/run/secrets/g008-f12-tls-certificate", "f12_ingress"),
    "f12_mtls_private_key": ("/run/secrets/g008-f12-mtls-private-key", "transaction_authority"),
    "f12_mtls_certificate": ("/run/secrets/g008-f12-mtls-certificate", "transaction_authority"),
    "f12_mtls_ca_certificate": ("/run/secrets/g008-f12-mtls-ca-certificate", "transaction_authority"),
    "dispatch_es256_private_key": ("/run/secrets/g008-dispatch-es256-private-key", "backend"),
    "dispatch_es256_public_key": ("/run/secrets/g008-dispatch-es256-public-key", "backend"),
    "media_es256_private_key": ("/run/secrets/g008-media-es256-private-key", "backend"),
    "media_es256_public_key": ("/run/secrets/g008-media-es256-public-key", "backend"),
    "execution_evidence_es256_private_key": ("/run/secrets/g008-execution-evidence-es256-private-key", "backend"),
    "execution_evidence_es256_public_key": ("/run/secrets/g008-execution-evidence-es256-public-key", "backend"),
    "registration_attestation_es256_private_key": ("/run/secrets/g008-registration-attestation-es256-private-key", "transaction_authority"),
    "registration_attestation_es256_public_key": ("/run/secrets/g008-registration-attestation-es256-public-key", "backend"),
    "authority_recovery_key": ("/run/secrets/g008-authority-recovery-key", "backend"),
    "mariadb_root_password": ("/run/secrets/g009-mariadb-root-password", "backend"),
    "webhook_secret": ("/run/secrets/g009-webhook-secret", "backend"),
    "account_api_token": ("/run/secrets/g009-account-api-token", "backend"),
    "registration_egress_proof": ("/run/secrets/g009-registration-egress-proof", "backend"),
    "f12_endpoint_credential": ("/run/secrets/g008-f12-endpoint-credential", "backend"),
    "registration_f12_endpoint_credential": ("/run/secrets/g008-registration-f12-endpoint-credential", "transaction_authority"),
    "stock_api_token": ("/run/secrets/g008-stock-api-token", "backend"),
    "jambones_mysql_password": ("/run/secrets/g009-jambones-mysql-password", "backend"),
    "jwt_secret": ("/run/secrets/g009-jwt-secret", "backend"),
    "encryption_secret": ("/run/secrets/g009-encryption-secret", "backend"),
    "drachtio_feature_secret": ("/run/secrets/g009-drachtio-feature-secret", "backend"),
    "drachtio_sip_secret": ("/run/secrets/g009-drachtio-sip-secret", "backend"),
    "freeswitch_esl_password": ("/run/secrets/g009-freeswitch-esl-password", "backend"),
}
(runtime_dir, transaction_dir, manifest_handle, expected_binding,
 expected_request_digest, expected_nonce_digest, expected_operator_digest) = sys.argv[1:]
if REFERENCE.fullmatch(manifest_handle) is None:
    raise SystemExit(1)

context = ssl.create_default_context()
metadata_request = urllib.request.Request(
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
    headers={"Metadata-Flavor": "Google", "Host": "metadata.google.internal"},
)
with urllib.request.urlopen(metadata_request, timeout=5) as response:
    runtime_token = json.load(response)["access_token"]
if not isinstance(runtime_token, str) or not runtime_token:
    raise SystemExit(1)

def payload(reference, token):
    if REFERENCE.fullmatch(reference) is None:
        raise SystemExit(1)
    request = urllib.request.Request(
        "https://secretmanager.googleapis.com/v1/" + urllib.parse.quote(reference, safe="/") + ":access",
        headers={"Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(request, timeout=10, context=context) as response:
        value = base64.b64decode(json.load(response)["payload"]["data"], validate=True)
    if not value or len(value) > 131072:
        raise SystemExit(1)
    return value

# BEGIN G008_BOOTSTRAP_MANIFEST_PARSER
def parse_bootstrap_manifest(manifest_raw, expected_binding):
    if not manifest_raw.endswith(b"\n") or manifest_raw.endswith(b"\n\n"):
        raise SystemExit(1)
    try:
        manifest = json.loads(manifest_raw[:-1])
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise SystemExit(1)
    # Exact compact sorted UTF-8 JSON bytes terminated by one LF.
    if json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n" != manifest_raw:
        raise SystemExit(1)
    if set(manifest) != {"schema_version", "binding_sha256", "transaction_authority_service_account", "secret_version_mounts", "execution_versions", "route_evidence_bundle"}:

        raise SystemExit(1)
    if manifest["schema_version"] != "recova-g008-sealed-bootstrap-manifest-v1" or manifest["binding_sha256"] != expected_binding:
        raise SystemExit(1)
    route = manifest["route_evidence_bundle"]
    route_required = {"numeric_version_resource_name", "content_sha256", "schema_version", "organization_id", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest"}
    if not isinstance(route, dict) or set(route) != route_required or REFERENCE.fullmatch(route["numeric_version_resource_name"] or "") is None or route["schema_version"] != "recova-onnuri-route-evidence-bundle-v1" or not isinstance(route["organization_id"], int) or route["organization_id"] <= 0 or any(re.fullmatch(r"[0-9a-f]{64}", route.get(name, "") or "") is None for name in ("content_sha256", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest")):
        raise SystemExit(1)
    return manifest
# END G008_BOOTSTRAP_MANIFEST_PARSER

manifest = parse_bootstrap_manifest(payload(manifest_handle, runtime_token), expected_binding)
mounts = manifest["secret_version_mounts"]
execution = manifest["execution_versions"]
transaction_authority = manifest["transaction_authority_service_account"]
route_evidence_bundle = manifest["route_evidence_bundle"]
route_required = {"numeric_version_resource_name", "content_sha256", "schema_version", "organization_id", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest"}
if not isinstance(route_evidence_bundle, dict) or set(route_evidence_bundle) != route_required or REFERENCE.fullmatch(route_evidence_bundle["numeric_version_resource_name"]) is None or route_evidence_bundle["schema_version"] != "recova-onnuri-route-evidence-bundle-v1" or not isinstance(route_evidence_bundle["organization_id"], int) or route_evidence_bundle["organization_id"] <= 0 or any(re.fullmatch(r"[0-9a-f]{64}", route_evidence_bundle.get(name, "") or "") is None for name in ("content_sha256", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest")):
    raise SystemExit(1)

if not isinstance(mounts, dict) or set(mounts) != set(EXPECTED_MOUNTS) or not isinstance(execution, dict) or set(execution) != EXECUTION_KEYS:
    raise SystemExit(1)
if SERVICE_ACCOUNT.fullmatch(transaction_authority) is None:
    raise SystemExit(1)

# The bootstrap binding covers the canonical inventory without exposing it.
binding_input = dict(manifest)
binding_input.pop("binding_sha256")
actual_binding = hashlib.sha256(json.dumps(binding_input, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
if actual_binding != expected_binding:
    raise SystemExit(1)

token_request = urllib.request.Request(
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
    + urllib.parse.quote(transaction_authority, safe="@.") + ":generateAccessToken",
    data=json.dumps({"scope": ["https://www.googleapis.com/auth/secretmanager"], "lifetime": "300s"}).encode("ascii"),
    headers={"Authorization": "Bearer " + runtime_token, "Content-Type": "application/json"},
    method="POST",
)
with urllib.request.urlopen(token_request, timeout=10, context=context) as response:
    transaction_token = json.load(response)["accessToken"]
if not isinstance(transaction_token, str) or not transaction_token:
    raise SystemExit(1)

def write_secret(reference, target, token):
    value = payload(reference, token)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    try:
        os.write(descriptor, value)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

seen_transaction = set()
for purpose, mount in mounts.items():
    if (
        not isinstance(mount, dict)
        or set(mount) != {"version_resource_name", "target", "consumer", "read_only"}
        or mount["read_only"] is not True
        or (mount["target"], mount["consumer"]) != EXPECTED_MOUNTS[purpose]
        or REFERENCE.fullmatch(mount["version_resource_name"]) is None
    ):
        raise SystemExit(1)
    target = mount["target"]
    is_transaction = purpose in TRANSACTION_PURPOSES
    destination = transaction_dir if is_transaction else runtime_dir
    if is_transaction:
        seen_transaction.add(purpose)
    write_secret(mount["version_resource_name"], os.path.join(destination, os.path.basename(target)), transaction_token if is_transaction else runtime_token)
if seen_transaction != TRANSACTION_PURPOSES:
    raise SystemExit(1)

del transaction_token
for name, filename in (
    ("request", "execution-request"),
    ("sip_username", "execution-sip-username"),
    ("sip_password", "execution-sip-password"),
    ("sip_realm", "execution-sip-realm"),
    ("target", "execution-target"),
    ("execution_nonce", "execution-nonce"),
    ("operator_credential", "operator-credential"),
):
    write_secret(execution[name], os.path.join(runtime_dir, filename), runtime_token)
# The opaque tenant-scoped route evidence bundle remains backend-only. It is
# fetched once from its numeric Secret Manager version and never mounted raw.
route_bundle = payload(route_evidence_bundle["numeric_version_resource_name"], runtime_token)
if hashlib.sha256(route_bundle).hexdigest() != route_evidence_bundle["content_sha256"]:
    raise SystemExit(1)
route_root = os.path.join(runtime_dir, "route-evidence-source")
os.mkdir(route_root, 0o700)
route_binding_path = os.path.join(route_root, "binding.json")
route_binding = json.dumps(route_evidence_bundle, sort_keys=True, separators=(",", ":")).encode()
descriptor = os.open(route_binding_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
try:
    os.write(descriptor, route_binding); os.fsync(descriptor)
finally:
    os.close(descriptor)
route_bundle_path = os.path.join(route_root, "bundle.json")
descriptor = os.open(route_bundle_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
try:
    os.write(descriptor, route_bundle); os.fsync(descriptor)
finally:
    os.close(descriptor)
del route_bundle
del runtime_token


PY
# The ingress trust anchor is public material; copy it out without exposing either
# the transaction client key or the transaction attestation private key.
/usr/bin/install -m 0400 "$TRANSACTION_DIR/g008-f12-mtls-ca-certificate" \
  "$RUNTIME_DIR/g008-f12-mtls-ca-certificate"

# Revoke the only bootstrap exception and prove that even its UID can no longer
# obtain metadata tokens before Docker/containerd are allowed to start.
/usr/sbin/iptables -D OUTPUT -d "$METADATA_IP/32" -m owner --uid-owner "$BOOTSTRAP_UID" -j ACCEPT
if bootstrap_curl "$METADATA_ROOT/instance/service-accounts/default/token" >/dev/null 2>&1; then
  exit 1
fi
/usr/sbin/iptables -C OUTPUT -d "$METADATA_IP/32" -j REJECT
/usr/sbin/iptables -C FORWARD -d "$METADATA_IP/32" -j REJECT
/usr/bin/chown -R root:root "$RUNTIME_DIR" "$TRANSACTION_DIR"
/usr/bin/chmod 0700 "$RUNTIME_DIR" "$TRANSACTION_DIR"
/usr/bin/python3 - "$RUNTIME_DIR" "$TRANSACTION_DIR" <<'PY'
import os
import stat
import sys

runtime_dir, transaction_dir = sys.argv[1:]
runtime_files = {
    "g008-recova-postgres-password", "g008-recova-redis-password",
    "g008-f12-tls-private-key", "g008-f12-tls-certificate", "g008-f12-mtls-ca-certificate",
    "g008-dispatch-es256-private-key", "g008-dispatch-es256-public-key",
    "g008-media-es256-private-key", "g008-media-es256-public-key",
    "g008-execution-evidence-es256-private-key", "g008-execution-evidence-es256-public-key",
    "g008-registration-attestation-es256-public-key", "g008-authority-recovery-key",
    "g009-mariadb-root-password", "g009-webhook-secret", "g009-account-api-token",
    "g009-registration-egress-proof", "g008-f12-endpoint-credential", "g008-stock-api-token",
    "g009-jambones-mysql-password", "g009-jwt-secret", "g009-encryption-secret",
    "g009-drachtio-feature-secret", "g009-drachtio-sip-secret", "g009-freeswitch-esl-password",
}
transaction_files = {
    "g008-f12-mtls-private-key", "g008-f12-mtls-certificate",
    "g008-registration-attestation-es256-private-key", "g008-registration-f12-endpoint-credential",
}
for directory, filenames in ((runtime_dir, runtime_files), (transaction_dir, transaction_files)):
    directory_info = os.lstat(directory)
    if not stat.S_ISDIR(directory_info.st_mode) or stat.S_IMODE(directory_info.st_mode) != 0o700 or directory_info.st_uid != 0 or directory_info.st_gid != 0:
        raise SystemExit(1)
    for filename in filenames:
        descriptor = os.open(os.path.join(directory, filename), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or info.st_uid != 0 or info.st_gid != 0:
                raise SystemExit(1)
        finally:
            os.close(descriptor)
PY
# BEGIN G008_ROUTE_EVIDENCE_STAGING
/usr/bin/python3 - "$RUNTIME_DIR/route-evidence-source/bundle.json" "$RUNTIME_DIR/route-evidence-source/binding.json" "$EVIDENCE_ROOT/$nonce_digest/route-evidence" <<'PY'
import base64, hashlib, json, os, re, stat, sys
from datetime import datetime, timedelta, timezone
source, binding_source, destination = sys.argv[1:]
NAMES = ("provider_fact_packet", "provider_fact_packet_signatures", "route_decision", "route_decision_signatures", "route_conformance", "route_conformance_signatures", "trusted_keyset", "revocations")
def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise SystemExit(1)
        result[key] = value
    return result
def canon(value): return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd); value = os.read(fd, 262145)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or info.st_uid or info.st_gid or len(value) > 262144: raise SystemExit(1)
        return value
    finally: os.close(fd)
def decode(value):
    if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) is None: raise SystemExit(1)
    try: raw = base64.b64decode(value, validate=True)
    except Exception: raise SystemExit(1)
    if base64.b64encode(raw).decode() != value or len(raw) > 262144: raise SystemExit(1)
    return raw
def write(name, value, mode):
    fd = os.open(os.path.join(destination, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try: os.write(fd, value); os.fsync(fd)
    finally: os.close(fd)
raw = read(source)
binding_raw = read(binding_source)
try:
    binding = json.loads(binding_raw, object_pairs_hook=pairs)
except (UnicodeDecodeError, json.JSONDecodeError): raise SystemExit(1)
binding_required = {"numeric_version_resource_name", "content_sha256", "schema_version", "organization_id", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest"}
if canon(binding) != binding_raw or set(binding) != binding_required or binding["schema_version"] != "recova-onnuri-route-evidence-bundle-v1" or not isinstance(binding["organization_id"], int) or binding["organization_id"] <= 0 or any(re.fullmatch(r"[0-9a-f]{64}", binding.get(name, "") or "") is None for name in ("content_sha256", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle_digest")): raise SystemExit(1)
if not raw.endswith(b"\n") or raw.endswith(b"\n\n"): raise SystemExit(1)
try: bundle = json.loads(raw[:-1], object_pairs_hook=pairs)
except (UnicodeDecodeError, json.JSONDecodeError): raise SystemExit(1)
required = {"schema_version", "numeric_version_resource_name", "organization_id", "request_digest", "candidate_digest", "route_profile_digest", "opaque_handle", "approved_root_locator_digest", "inventory_locator_digest", "inventory_version", "adapter_sha256", "adapter_execution_mode", "adapter_stdin_schema", "adapter_stdin_exactly_one_lf", "adapter_stdout_schema", "adapter_stdout_max_bytes", "adapter_stderr_max_bytes", "adapter_timeout_ms", "adapter", *NAMES}
if canon(bundle) + b"\n" != raw or set(bundle) != required or bundle["schema_version"] != "recova-onnuri-route-evidence-bundle-v1": raise SystemExit(1)
if any(bundle.get(name) != binding[name] for name in ("numeric_version_resource_name", "schema_version", "organization_id", "request_digest", "candidate_digest", "route_profile_digest")) or not isinstance(bundle["opaque_handle"], str) or not bundle["opaque_handle"] or re.fullmatch(r"[0-9a-f]{64}", bundle["opaque_handle"]) or hashlib.sha256(bundle["opaque_handle"].encode()).hexdigest() != binding["opaque_handle_digest"]: raise SystemExit(1)
if not all(isinstance(bundle[name], str) and re.fullmatch(r"[0-9a-f]{64}", bundle[name]) for name in ("approved_root_locator_digest", "inventory_locator_digest", "adapter_sha256", *(f"{name}_sha256" for name in NAMES))) or not isinstance(bundle["inventory_version"], str) or not bundle["inventory_version"] or bundle["adapter_execution_mode"] != "fixed-executable-v1" or bundle["adapter_stdin_schema"] != "recova-onnuri-restricted-inventory-adapter-invocation-v1" or bundle["adapter_stdin_exactly_one_lf"] is not True or bundle["adapter_stdout_schema"] != "recova-onnuri-restricted-inventory-adapter-v1" or type(bundle["adapter_stdout_max_bytes"]) is not int or not 0 < bundle["adapter_stdout_max_bytes"] <= 262144 or type(bundle["adapter_stderr_max_bytes"]) is not int or not 0 <= bundle["adapter_stderr_max_bytes"] <= 262144 or type(bundle["adapter_timeout_ms"]) is not int or not 0 < bundle["adapter_timeout_ms"] <= 5000: raise SystemExit(1)
os.mkdir(destination, 0o700)
for name in NAMES:
    write(name, decode(bundle[name]), 0o400)
adapter = decode(bundle["adapter"])
if hashlib.sha256(adapter).hexdigest() != bundle["adapter_sha256"]: raise SystemExit(1)
write("adapter", adapter, 0o500)
manifest = {key: value for key, value in bundle.items() if key not in {*NAMES, "adapter", "adapter_path"}}
write("manifest.json", canon(manifest), 0o400)
if set(os.listdir(destination)) != set(NAMES) | {"adapter", "manifest.json"}: raise SystemExit(1)
for name in NAMES + ("manifest.json",):
    path = os.path.join(destination, name)
    os.chown(path, 65532, 65532); os.chmod(path, 0o400)
os.chown(os.path.join(destination, "adapter"), 65532, 65532); os.chmod(os.path.join(destination, "adapter"), 0o500)
os.chown(destination, 65532, 65532); os.chmod(destination, 0o500)
PY
# END G008_ROUTE_EVIDENCE_STAGING
/usr/bin/python3 - \
  "$RUNTIME_DIR" "$request_digest" "$nonce_digest" "$operator_credential_digest" \
  "$RUNNER_SOURCE" "$runner_digest" "$TRUSTED_KEYSET_SOURCE" "$keyset_digest" \
  "$PROVIDER_SCRIPT_SOURCE" "$provider_script_digest" <<'PY'
import hashlib
import json
import os
import stat
import sys

(runtime_dir, request_digest, nonce_digest, operator_digest,
 runner_path, runner_digest, keyset_path, keyset_digest,
 provider_path, provider_digest) = sys.argv[1:]

def checked_bytes(path, expected_digest, expected_uid=None, expected_gid=None):
    if os.path.realpath(path) != path:
        raise SystemExit(1)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) not in (0o400, 0o444, 0o555):
            raise SystemExit(1)
        if expected_uid is not None and (info.st_uid != expected_uid or info.st_gid != expected_gid):
            raise SystemExit(1)
        raw = b""
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            raw += chunk
            if len(raw) > 1048576:
                raise SystemExit(1)
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != expected_digest:
        raise SystemExit(1)
    return raw

request_raw = checked_bytes(os.path.join(runtime_dir, "execution-request"), request_digest, 0, 0)
try:
    request = json.loads(request_raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
if not isinstance(request, dict) or json.dumps(request, sort_keys=True, separators=(",", ":")).encode() != request_raw:
    raise SystemExit(1)
checked_bytes(os.path.join(runtime_dir, "execution-nonce"), nonce_digest, 0, 0)
checked_bytes(os.path.join(runtime_dir, "operator-credential"), operator_digest, 0, 0)
checked_bytes(runner_path, runner_digest)
checked_bytes(keyset_path, keyset_digest)
checked_bytes(provider_path, provider_digest)
PY
# Exactly seven host-prefetched runner inputs are immutable UID/GID 1000 files.
for execution_file in \
  "$RUNTIME_DIR/execution-request" \
  "$RUNTIME_DIR/execution-sip-username" \
  "$RUNTIME_DIR/execution-sip-password" \
  "$RUNTIME_DIR/execution-sip-realm" \
  "$RUNTIME_DIR/execution-target" \
  "$RUNTIME_DIR/execution-nonce" \
  "$RUNTIME_DIR/operator-credential"
do
  [ -f "$execution_file" ] && [ ! -L "$execution_file" ]
  /usr/bin/chown 1000:1000 "$execution_file"
  /usr/bin/chmod 0400 "$execution_file"
  [ "$(/usr/bin/stat -c '%F:%u:%g:%a' "$execution_file")" = "regular file:1000:1000:400" ]
done
# The sealed, image-bound non-secret binding file plus fixed paths are the entire Compose input.
# The file is atomically sealed; Compose receives no host environment or implicit .env.
/usr/bin/python3 - "$COMPOSE_ROOT/g008-compose-nonsecret-bindings.json" "$COMPOSE_ENV_FILE" "$RUNTIME_DIR" "$TRANSACTION_DIR" "$EVIDENCE_ROOT/$nonce_digest" "$EVIDENCE_ROOT/$nonce_digest/route-evidence" "$request_digest" <<'PY'
import json
import os
import re
import sys

binding_path, destination, runtime_dir, transaction_dir, evidence_dir, route_evidence_dir, request_digest = sys.argv[1:]
required = {
    "G008_F12_INGRESS_IMAGE", "G008_POSTGRES_IMAGE", "G008_RECOVA_BACKEND_IMAGE", "G008_REDIS_IMAGE", "G009_API_SERVER_IMAGE", "G009_DRACHTIO_IMAGE", "G009_FACADE_IMAGE", "G009_FEATURE_SERVER_IMAGE", "G009_FREESWITCH_ESL_PORT", "G009_FREESWITCH_IMAGE", "G009_JAMBONES_MYSQL_USER", "G009_MARIADB_IMAGE", "G009_REDIS_IMAGE", "G009_REGISTRATION_CARRIER_SID", "G009_REGISTRATION_GATEWAY_IPV4", "G009_REGISTRATION_GATEWAY_SID", "G009_RTPENGINE_IMAGE", "G009_SBC_CALL_ROUTER_IMAGE", "G009_SBC_INBOUND_IMAGE", "G009_SBC_OUTBOUND_IMAGE", "G009_SBC_RTPENGINE_SIDECAR_IMAGE", "G009_SBC_SIP_SIDECAR_IMAGE", "G009_UPSTREAM_SCHEMA_FILE", "ONNURI_SMOKE_DISPATCH_KEY_ID", "ONNURI_SMOKE_EXECUTION_EVIDENCE_KEY_ID", "ONNURI_SMOKE_F12_ALLOWED_MTLS_IDENTITIES", "ONNURI_SMOKE_F12_CREDENTIAL_SHA256", "ONNURI_SMOKE_F12_TRUSTED_MTLS_ISSUER", "ONNURI_SMOKE_MEDIA_KEY_ID", "ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID", "ONNURI_SMOKE_REGISTRATION_UPSTREAM_ENDPOINT_SHA256", "RECOVA_F12_VERIFIED_IDENTITY", "RECOVA_F12_VERIFIED_ISSUER", "RECOVA_REGISTRATION_F12_BASE_URL", "RECOVA_STOCK_ACCOUNT_ID",
    "ONNURI_REQUEST_DIGEST", "ONNURI_CANDIDATE_DIGEST", "ONNURI_ROUTE_PROFILE_DIGEST",
}
fixed = {
    "G008_EXECUTION_REQUEST_FILE": runtime_dir + "/execution-request", "G008_EXECUTION_SIP_USERNAME_FILE": runtime_dir + "/execution-sip-username", "G008_EXECUTION_SIP_PASSWORD_FILE": runtime_dir + "/execution-sip-password", "G008_EXECUTION_SIP_REALM_FILE": runtime_dir + "/execution-sip-realm", "G008_EXECUTION_TARGET_FILE": runtime_dir + "/execution-target", "G008_EXECUTION_NONCE_FILE": runtime_dir + "/execution-nonce", "G008_OPERATOR_CREDENTIAL_FILE": runtime_dir + "/operator-credential", "G008_EXECUTION_OUTPUT_DIRECTORY": evidence_dir, "G008_EXECUTION_REQUEST_SHA256": request_digest,
    "ONNURI_SMOKE_F12_ROUTE_EVIDENCE_ROOT": route_evidence_dir,
    "G008_RECOVA_POSTGRES_PASSWORD_FILE": runtime_dir + "/g008-recova-postgres-password", "G008_RECOVA_REDIS_PASSWORD_FILE": runtime_dir + "/g008-recova-redis-password", "G008_F12_SERVER_KEY_FILE": runtime_dir + "/g008-f12-tls-private-key", "G008_F12_SERVER_CERTIFICATE_FILE": runtime_dir + "/g008-f12-tls-certificate", "G008_F12_CLIENT_CA_CERTIFICATE_FILE": runtime_dir + "/g008-f12-mtls-ca-certificate", "G009_MARIADB_ROOT_PASSWORD_FILE": runtime_dir + "/g009-mariadb-root-password", "G009_WEBHOOK_SECRET_FILE": runtime_dir + "/g009-webhook-secret", "G009_ACCOUNT_API_TOKEN_FILE": runtime_dir + "/g009-account-api-token", "G009_REGISTRATION_EGRESS_PROOF_FILE": runtime_dir + "/g009-registration-egress-proof", "G009_JAMBONES_MYSQL_PASSWORD_FILE": runtime_dir + "/g009-jambones-mysql-password", "G009_JWT_SECRET_FILE": runtime_dir + "/g009-jwt-secret", "G009_ENCRYPTION_SECRET_FILE": runtime_dir + "/g009-encryption-secret", "G009_DRACHTIO_FEATURE_SECRET_FILE": runtime_dir + "/g009-drachtio-feature-secret", "G009_DRACHTIO_SIP_SECRET_FILE": runtime_dir + "/g009-drachtio-sip-secret", "G009_FREESWITCH_ESL_PASSWORD_FILE": runtime_dir + "/g009-freeswitch-esl-password",
    "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE": runtime_dir + "/g008-dispatch-es256-private-key", "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE": runtime_dir + "/g008-dispatch-es256-public-key", "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE": runtime_dir + "/g008-media-es256-private-key", "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE": runtime_dir + "/g008-media-es256-public-key", "ONNURI_SMOKE_EXECUTION_EVIDENCE_PRIVATE_KEY_FILE": runtime_dir + "/g008-execution-evidence-es256-private-key", "ONNURI_SMOKE_EXECUTION_EVIDENCE_PUBLIC_KEY_FILE": runtime_dir + "/g008-execution-evidence-es256-public-key", "ONNURI_SMOKE_RECOVERY_KEY_FILE": runtime_dir + "/g008-authority-recovery-key", "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PRIVATE_KEY_FILE": transaction_dir + "/g008-registration-attestation-es256-private-key", "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PUBLIC_KEY_FILE": runtime_dir + "/g008-registration-attestation-es256-public-key", "RECOVA_F12_ENDPOINT_CREDENTIAL_FILE": runtime_dir + "/g008-f12-endpoint-credential", "RECOVA_REGISTRATION_F12_CLIENT_CERTIFICATE_FILE": transaction_dir + "/g008-f12-mtls-certificate", "RECOVA_REGISTRATION_F12_CLIENT_KEY_FILE": transaction_dir + "/g008-f12-mtls-private-key", "RECOVA_REGISTRATION_F12_CA_CERTIFICATE_FILE": runtime_dir + "/g008-f12-mtls-ca-certificate", "RECOVA_REGISTRATION_F12_ENDPOINT_CREDENTIAL_FILE": transaction_dir + "/g008-registration-f12-endpoint-credential", "RECOVA_STOCK_API_TOKEN_FILE": runtime_dir + "/g008-stock-api-token", "RECOVA_SIP_ENABLED": "true", "RECOVA_RTP_ENABLED": "true", "RECOVA_REGISTER_ENABLED": "true", "RECOVA_OUTBOUND_CALLS_ENABLED": "true", "RECOVA_INBOUND_CALLS_ENABLED": "true",
}
try:
    raw = open(binding_path, "rb").read()
    bindings = json.loads(raw)
except (OSError, UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
if json.dumps(bindings, sort_keys=True, separators=(',', ':')).encode() != raw or set(bindings) != required:
    raise SystemExit(1)
for key in ("ONNURI_REQUEST_DIGEST", "ONNURI_CANDIDATE_DIGEST", "ONNURI_ROUTE_PROFILE_DIGEST"):
    if not re.fullmatch(r"[0-9a-f]{64}", bindings.get(key, "")):
        raise SystemExit(1)
env = {**bindings, **fixed}
if set(env) != required | set(fixed) or any(
    not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
    or not isinstance(value, str)
    or not value
    or value != value.strip()
    or "\n" in value
    or "\r" in value
    for key, value in env.items()
):
    raise SystemExit(1)
payload = "".join(f"{key}={env[key]}\n" for key in sorted(env)).encode()
temporary = destination + ".tmp"
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
try:
    os.write(fd, payload)
    os.fsync(fd)
finally:
    os.close(fd)
os.replace(temporary, destination)
os.chmod(destination, 0o600)
if os.stat(destination).st_mode & 0o777 != 0o600:
    raise SystemExit(1)
PY

whole_run_seconds=$(/usr/bin/python3 - "$live_window_end" "$watchdog_cutoff" "$cost_ceiling" <<'PY'
import datetime
import decimal
import sys

def instant(value):
    parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError
    return parsed

try:
    now = datetime.datetime.now(datetime.timezone.utc)
    remaining = min((instant(value) - now).total_seconds() for value in sys.argv[1:3])
    cost = decimal.Decimal(sys.argv[3])
    if not cost.is_finite() or cost <= 0:
        raise ValueError
except (ValueError, decimal.InvalidOperation):
    raise SystemExit(1)
seconds = min(360, int(remaining))
if seconds <= 0:
    raise SystemExit(1)
print(seconds)
PY
)

/usr/bin/systemctl unmask --runtime docker.service docker.socket containerd.service containerd.socket
/usr/bin/systemctl start containerd.service docker.service
/usr/sbin/iptables -I DOCKER-USER 1 -d "$METADATA_IP/32" -j REJECT
/usr/sbin/iptables -C DOCKER-USER -d "$METADATA_IP/32" -j REJECT

# Compose receives only the sealed file generated above; host .env and Compose
# environment overrides are removed before rendering or execution.
/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent \
  /usr/bin/timeout --signal=TERM --kill-after=5s "${whole_run_seconds}s" \
  /usr/bin/docker compose --env-file "$COMPOSE_ENV_FILE" --project-directory "$COMPOSE_ROOT" \
    -f "$COMPOSE_FILE" --profile g008-live-smoke up \
    --no-build --pull never --no-recreate --abort-on-container-exit --exit-code-from g008-live-smoke-runner

/usr/bin/python3 - "$EVIDENCE_ROOT/$nonce_digest/execution-bundle.json" "$nonce_digest" "$keyset_digest" <<'PY'
import json
import os
import stat
import sys

path, nonce_digest, keyset_digest = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
try:
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 1000 or info.st_gid != 1000:
        raise SystemExit(1)
    raw = b""
    while True:
        chunk = os.read(descriptor, 65536)
        if not chunk:
            break
        raw += chunk
        if len(raw) > 1048576:
            raise SystemExit(1)
finally:
    os.close(descriptor)
try:
    bundle = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit(1)
if json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode() != raw:
    raise SystemExit(1)
if set(bundle) != {"schema_version", "trusted_keyset_digest", "nonce", "seal", "stages", "final"}:
    raise SystemExit(1)
if bundle["schema_version"] != "recova-g008-execution-bundle-v2" or bundle["trusted_keyset_digest"] != keyset_digest:
    raise SystemExit(1)
stages = bundle["stages"]
if not isinstance(stages, list) or [item.get("payload", {}).get("stage") for item in stages] != [
    "register", "outbound_call", "inbound_call", "unregister"
]:
    raise SystemExit(1)
for item in stages:
    if set(item) != {"payload", "signature"}:
        raise SystemExit(1)
nonce_payload = bundle.get("nonce", {}).get("payload", {})
if nonce_payload.get("execution_nonce_digest") != nonce_digest:
    raise SystemExit(1)
PY
/usr/bin/chown root:root "$EVIDENCE_ROOT/$nonce_digest/execution-bundle.json" "$EVIDENCE_ROOT/$nonce_digest"
/usr/bin/chmod 0400 "$EVIDENCE_ROOT/$nonce_digest/execution-bundle.json"
/usr/bin/chmod 0500 "$EVIDENCE_ROOT/$nonce_digest"
/bin/sync "$EVIDENCE_ROOT/$nonce_digest"
