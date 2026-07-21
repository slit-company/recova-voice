"""Offline-only contract tests for the G009 Compose topology.

These tests never invoke `docker compose up`; config rendering is the only Docker
operation and uses synthetic image digests plus temporary, non-secret files.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import os
import re
import shutil
import subprocess
import tempfile
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
import unittest

ROOT = Path(__file__).parents[1]
COMPOSE = ROOT / "compose.yaml"
ENV_EXAMPLE = ROOT / "candidate.env.example"
BOOTSTRAP = ROOT / "bootstrap-database.sh"
SEALED_SECRET_WRAPPER = ROOT / "sealed-secret-wrapper.sh"
BACKEND_DOCKERFILE = ROOT / "Dockerfile.recova-backend"
FACADE_DOCKERFILE = ROOT.parent / "onnuri-jambonz-facade" / "Dockerfile"
POSTGRES_DOCKERFILE = ROOT / "Dockerfile.postgres-support"
API_REQUIREMENTS = ROOT.parents[1] / "api" / "requirements.txt"
REGISTRATION_GUARD = ROOT / "verify-registration-egress-proof.js"
REGISTRATION_RUNNER = ROOT / "run-registration-transaction.js"
REGISTRATION_ATTESTOR = ROOT / "registration-sip-attestor.js"
INGRESS_CONFIG = ROOT / "f12-ingress-nginx.conf"
PHASE_C_ROOT = ROOT.parents[1] / "infra" / "onnuri-seoul-staging-phase-c-smoke"
G008_STARTUP = PHASE_C_ROOT / "startup-g008.sh"
G008_IAM = PHASE_C_ROOT / "iam.tf"
G008_WORKLOAD = PHASE_C_ROOT / "workload.tf"
DIGEST = "example.invalid/test@sha256:" + "0" * 64
EXPECTED_SERVICES = {
    "mariadb", "redis", "database-bootstrap", "api",
    "feature-server", "drachtio-feature", "freeswitch", "rtpengine",
    "rtpengine-sidecar", "drachtio-sip", "registration-authority",
    "sip-sidecar-register", "sip-sidecar-unregister",
    "inbound", "outbound", "call-router", "facade", "recova-postgres",
    "recova-redis", "recova-migrate", "recova-backend", "f12-ingress",
    "registration-bootstrap", "g008-live-smoke-runner",
}
CANDIDATE_IMAGES = {
    "G009_FEATURE_SERVER_IMAGE", "G009_API_SERVER_IMAGE",
    "G009_SBC_INBOUND_IMAGE", "G009_SBC_OUTBOUND_IMAGE", "G009_SBC_CALL_ROUTER_IMAGE",
    "G009_SBC_SIP_SIDECAR_IMAGE", "G009_SBC_RTPENGINE_SIDECAR_IMAGE",
    "G009_DRACHTIO_IMAGE", "G009_FREESWITCH_IMAGE", "G009_RTPENGINE_IMAGE",
}
BASE_IMAGES = {"G009_MARIADB_IMAGE", "G009_REDIS_IMAGE", "G009_FACADE_IMAGE"}
PRIVATE_IMAGES = {
    "G008_RECOVA_BACKEND_IMAGE", "G008_POSTGRES_IMAGE",
    "G008_REDIS_IMAGE", "G008_F12_INGRESS_IMAGE",
}
ALL_IMAGES = CANDIDATE_IMAGES | BASE_IMAGES | PRIVATE_IMAGES


class OfflineComposeTests(unittest.TestCase):
    def test_g008_external_binding_and_host_prefetch_are_fail_closed(self) -> None:
        startup = G008_STARTUP.read_text()
        iam = G008_IAM.read_text()
        workload = G008_WORKLOAD.read_text()

        self.assertNotIn(
            'resource "google_secret_manager_secret_iam_member" "g008_',
            iam,
        )
        self.assertIn("g008-exact-binding-receipt-sha256", workload)
        self.assertIn(
            '[ "$binding_receipt" = "$manifest_binding" ]',
            startup,
        )
        self.assertIn(
            "request.time >= timestamp('%s') && request.time < timestamp('%s') && request.time < timestamp('%s')",
            iam,
        )
        self.assertIn(
            """[ "$(/usr/bin/stat -c '%F:%u:%g:%a' "$execution_file")" = "regular file:1000:1000:400" ]""",
            startup,
        )
        for filename in (
            "execution-request",
            "execution-sip-username",
            "execution-sip-password",
            "execution-sip-realm",
            "execution-target",
            "execution-nonce",
            "operator-credential",
        ):
            self.assertIn(f'"$RUNTIME_DIR/{filename}"', startup)

    def test_g008_compose_uses_only_sealed_interpolations_and_canonical_mount_paths(self) -> None:
        content = COMPOSE.read_text(encoding="utf-8")
        startup = G008_STARTUP.read_text(encoding="utf-8")
        runner = content[content.index("  g008-live-smoke-runner:"):content.index("\nnetworks:")]
        self.assertNotRegex(runner, r"\$\{G008_(?:EXECUTION_SEAL_UUID|CANDIDATE_DIGEST|GATE_ENVELOPE_DIGEST|OUTBOUND_PATH|INBOUND_PATH)")
        self.assertNotIn("G008_TRUSTED_KEYSET_FILE", startup)
        self.assertNotIn("G008_PROVIDER_SCRIPT_FILE", startup)
        self.assertIn('file: /opt/g008/run-g008-live-smoke.py', content)
        self.assertIn('file: /opt/g008/trusted/phase_c_live_preflight_v1.json', content)
        self.assertIn('file: /opt/g009/run-registration-transaction.js', content)
        self.assertIn('COMPOSE_ENV_FILE=/opt/recova/g008-compose.env', startup)
        self.assertIn('set(bindings) != required', startup)
        self.assertIn('os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600', startup)
        self.assertIn('/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent', startup)
        self.assertIn('--env-file "$COMPOSE_ENV_FILE" --project-directory "$COMPOSE_ROOT"', startup)
        self.assertIn('/usr/bin/rm -f "$COMPOSE_ENV_FILE"', startup)


    def test_g008_startup_shell_and_route_evidence_identity_contract(self) -> None:
        startup = G008_STARTUP.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        completed = subprocess.run(["sh", "-n", str(G008_STARTUP)], check=False, capture_output=True)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        self.assertIn("source: ${ONNURI_SMOKE_F12_ROUTE_EVIDENCE_ROOT:?ONNURI_SMOKE_F12_ROUTE_EVIDENCE_ROOT must be sealed}/route-evidence", compose)
        self.assertIn("ONNURI_SMOKE_F12_ROUTE_EVIDENCE_UID: '65532'", compose)
        self.assertIn("ONNURI_SMOKE_F12_ROUTE_EVIDENCE_GID: '65532'", compose)
        self.assertIn("os.chown(path, 65532, 65532); os.chmod(path, 0o400)", startup)
        self.assertIn("os.chown(os.path.join(destination, \"adapter\"), 65532, 65532); os.chmod(os.path.join(destination, \"adapter\"), 0o500)", startup)
        self.assertIn('"request_digest"', startup)
        self.assertIn('"route_profile_digest"', startup)
    def test_g008_startup_seals_the_exact_compose_environment_and_mount_contract(self) -> None:
        startup = G008_STARTUP.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        required = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", compose))
        required_start = startup.index("required = {", startup.index("binding_path, destination"))
        required_end = startup.index("\n}", required_start)
        fixed_start = startup.index("fixed = {", required_end)
        fixed_end = startup.index("\n}", fixed_start)
        startup_required = set(re.findall(r'"([A-Z][A-Z0-9_]*)"', startup[required_start:required_end]))
        startup_fixed = set(re.findall(r'"([A-Z][A-Z0-9_]*)"\s*:', startup[fixed_start:fixed_end]))
        self.assertEqual(required, startup_required | startup_fixed)
        self.assertIn('set(mounts) != set(EXPECTED_MOUNTS)', startup)
        self.assertIn('(mount["target"], mount["consumer"]) != EXPECTED_MOUNTS[purpose]', startup)
        self.assertIn('REFERENCE.fullmatch(mount["version_resource_name"]) is None', startup)
        self.assertIn('set(env) != required | set(fixed)', startup)
        self.assertNotIn("${G009_REGISTRATION_CARRIER_SID:-}", compose)
        self.assertNotIn("${G009_REGISTRATION_GATEWAY_SID:-}", compose)
        self.assertNotIn("RECOVA_STOCK_API_TOKEN: ${RECOVA_STOCK_API_TOKEN", compose)
        self.assertIn("RECOVA_STOCK_API_TOKEN_FILE: /run/secrets/g008-stock-api-token", compose)

        expected_mounts = {
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
        }
        expected_mounts.update({
            "mariadb_root_password": ("/run/secrets/g009-mariadb-root-password", "backend"),
            "webhook_secret": ("/run/secrets/g009-webhook-secret", "backend"),
            "account_api_token": ("/run/secrets/g009-account-api-token", "backend"),
            "registration_egress_proof": ("/run/secrets/g009-registration-egress-proof", "backend"),
            "f12_endpoint_credential": ("/run/secrets/g008-f12-endpoint-credential", "backend"),
            "registration_f12_endpoint_credential": ("/run/secrets/g008-registration-f12-endpoint-credential", "transaction_authority"),
            "stock_api_token": ("/run/secrets/g008-stock-api-token", "backend"),
        })
        for purpose, (target, consumer) in expected_mounts.items():
            self.assertIn(f'"{purpose}": ("{target}", "{consumer}")', startup)

    def test_g008_startup_rejects_missing_extra_or_substituted_compose_bindings(self) -> None:
        startup = G008_STARTUP.read_text(encoding="utf-8")
        self.assertIn("set(bindings) != required", startup)
        self.assertIn("set(mounts) != set(EXPECTED_MOUNTS)", startup)
        self.assertIn("(mount[\"target\"], mount[\"consumer\"]) != EXPECTED_MOUNTS[purpose]", startup)
        self.assertIn("os.open(os.path.join(directory, filename), os.O_RDONLY | os.O_NOFOLLOW)", startup)
    def test_example_requires_only_immutable_candidate_and_private_images(self) -> None:
        values = dict(
            line.split("=", 1) for line in ENV_EXAMPLE.read_text().splitlines()
            if line.startswith(("G008_", "G009_")) and "=" in line
        )
        self.assertEqual(
            {key for key in values if key.endswith("_IMAGE")},
            ALL_IMAGES,
        )
        for key in ALL_IMAGES:
            self.assertRegex(values[key], r"^.+@sha256:[0-9a-f]{64}$")
        authority_values = dict(
            line.split("=", 1) for line in ENV_EXAMPLE.read_text().splitlines()
            if line.startswith("ONNURI_SMOKE_") and "=" in line
        )
        for key in (
            "ONNURI_SMOKE_DISPATCH_KEY_ID",
            "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_KEY_ID",
            "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_RECOVERY_KEY_FILE",
        ):
            self.assertIn(key, authority_values)
            self.assertTrue(authority_values[key])

    def test_recova_backend_recipe_is_pinned_offline_and_non_root(self) -> None:
        content = BACKEND_DOCKERFILE.read_text(encoding="utf-8")
        from_lines = re.findall(r"(?m)^FROM .+$", content)
        self.assertEqual(len(from_lines), 3)
        for line in from_lines[:2]:
            self.assertRegex(line, r"^FROM --platform=linux/amd64 \S+:\S+@sha256:[0-9a-f]{64} AS \S+$")
        self.assertEqual(from_lines[2], "FROM builder AS runtime")
        self.assertNotIn(":latest", content)
        self.assertNotRegex(content, r"(?i)\b(?:curl|wget)\b")
        self.assertNotIn("git clone", content)
        self.assertNotIn("apt-get", content)
        self.assertIn("ghcr.io/astral-sh/uv:0.8.15@sha256:", content)
        self.assertIn("COPY api/requirements.txt", content)
        self.assertIn("COPY pipecat /build/pipecat", content)
        self.assertNotIn(",webrtc]", content)
        self.assertIn(
            "transformers==5.5.0 python-multipart==0.0.30 msgpack==1.2.1",
            content,
        )
        self.assertIn("COPY --chown=65532:65532 api /app/api", content)
        self.assertIn("test -x /opt/venv/bin/alembic", content)
        self.assertIn("test -d /opt/venv/lib/python3.13/site-packages/pipecat", content)
        self.assertIn("HEALTHCHECK", content)
        self.assertIn("USER 65532:65532", content)
        self.assertIn("test -f /app/api/services/telephony/onnuri_route_receipts.py", content)
        self.assertIn("from api.services.telephony.onnuri_route_receipts import verify_route_chain", content)
        facade = FACADE_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("test ! -e /srv/recova/api/services/telephony/onnuri_route_receipts.py", facade)
        self.assertIn("! grep -R -E 'onnuri_route_receipts|verify_route_chain'", facade)
        self.assertIn("PIP_NO_INDEX=1", content)
        self.assertIn("UV_OFFLINE=1", content)
        self.assertNotRegex(content, r"(?i)(?:private[_-]?key|password|credential)\s*=")
        requirements = [
            line for line in API_REQUIREMENTS.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertTrue(requirements)
        for requirement in requirements:
            self.assertRegex(requirement, r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+-]+$")
            self.assertNotIn("://", requirement)

    def test_postgres_support_recipe_removes_unused_gosu(self) -> None:
        content = POSTGRES_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("FROM --platform=linux/amd64 ${BASE_IMAGE}", content)
        self.assertIn("rm -f /usr/local/bin/gosu", content)
        self.assertIn("test ! -e /usr/local/bin/gosu", content)
        self.assertIn("test -x /usr/local/bin/docker-entrypoint.sh", content)
        self.assertIn("test -x /usr/local/bin/pg_isready", content)
        self.assertIn('org.recova.base.digest="$BASE_IMAGE"', content)
        self.assertNotRegex(content, r"(?i)\b(?:curl|wget|apk|apt-get)\b")
    def test_backend_migration_and_smoke_runner_share_one_immutable_image(self) -> None:
        content = COMPOSE.read_text(encoding="utf-8")
        image_ref = (
            "image: ${G008_RECOVA_BACKEND_IMAGE:?"
            "G008_RECOVA_BACKEND_IMAGE must be name@sha256}"
        )
        self.assertEqual(content.count(image_ref), 3)
        self.assertEqual(content.count("platform: linux/amd64"), 3)
        self.assertNotIn("build:", content)

    def test_static_default_deny_and_secret_contract(self) -> None:
        content = COMPOSE.read_text(encoding="utf-8")
        self.assertEqual(content.count("internal: true"), 6)
        self.assertNotIn("ports:", content)
        self.assertNotRegex(content, r"(?m)^\s*-?\s*['\"]?(?:0\.0\.0\.0|\[::\])")
        self.assertNotIn("privileged:", content)
        self.assertIn("pull_policy: never", content)
        self.assertNotIn("network_mode: host", content)
        self.assertIn("g008-live-smoke-secrets:", content)
        self.assertIn("type: tmpfs", content)
        self.assertIn("noexec,nosuid,nodev", content)
        self.assertNotIn("external: true", content)
        self.assertEqual(content.count("- g008-live-smoke-secrets:/run/g008-secrets"), 2)
        self.assertNotRegex(content.lower(), r"(?:record|cdr|backup|export|telemetry)_")
        self.assertNotRegex(content.lower(), r"(?:aws|twilio|telnyx|plivo|license|activation|trial)")
        for key in ALL_IMAGES:
            self.assertIn("${" + key + ":?", content)
        self.assertIn("profiles: [registration, g008-live-smoke]", content)
        self.assertNotIn("network_mode: none", content)
        authority_block = content[
            content.index("  registration-authority:"):
            content.index("  sip-sidecar-register:")
        ]
        sip_block = content[
            content.index("  sip-sidecar-register:"):content.index("  inbound:")
        ]
        self.assertIn("profiles: [registration, g008-live-smoke]", authority_block)
        self.assertIn("user: \"1000:1000\"", authority_block)
        self.assertIn(
            "image: ${G009_SBC_SIP_SIDECAR_IMAGE:?"
            "G009_SBC_SIP_SIDECAR_IMAGE must be name@sha256}",
            authority_block,
        )
        self.assertIn("command: [node, /opt/g009/run-registration-transaction.js]", authority_block)
        self.assertIn("registration-supplier-egress:", authority_block)
        self.assertIn("f12-client:", authority_block)
        self.assertIn("registration-internal:", authority_block)
        self.assertIn("transaction-control:", authority_block)
        self.assertNotIn("G009_REGISTRATION_EGRESS_PROOF_PATH", authority_block)
        self.assertNotIn("/run/secrets/registration-egress-proof", authority_block)
        self.assertIn("registration-attestation-es256-private-key", authority_block)
        self.assertIn("mode: 0400", authority_block)
        self.assertNotIn("privileged:", authority_block)
        self.assertNotIn("cap_add:", authority_block)
        self.assertNotIn("docker.sock", authority_block)
        self.assertEqual(sip_block.count("profiles: [g008-live-smoke]"), 2)
        self.assertEqual(sip_block.count("network_mode: service:drachtio-sip"), 2)
        self.assertEqual(sip_block.count("node app.js"), 2)
        self.assertEqual(sip_block.count("registration-authority:"), 2)
        for forbidden in (
            "f12-client", "registration-supplier-egress", "registration-egress-proof",
            "dispatch-es256-public-key", "f12-", "endpoint-credential",
            "attestation", "authorization", "run-registration-transaction",
        ):
            self.assertNotIn(forbidden, sip_block.lower(), forbidden)
        self.assertNotIn("privileged:", sip_block)
        self.assertNotIn("cap_add:", sip_block)
        self.assertNotIn("docker.sock", sip_block)
        self.assertEqual(
            sip_block.count(
                "secrets: [g009-drachtio-sip-secret, g009-jambones-mysql-password, "
                "g009-jwt-secret, g009-encryption-secret]"
            ),
            2,
        )
        bootstrap_block = content[
            content.index("  registration-bootstrap:"):content.index("\nnetworks:")
        ]
        self.assertIn("profiles: [registration, g008-live-smoke]", bootstrap_block)
        self.assertIn("G009_REGISTRATION_BOOTSTRAP: '1'", bootstrap_block)
        self.assertIn("g009-registration-template", bootstrap_block)
        self.assertNotIn("registration-egress-guard", content)
        self.assertNotIn("/usr/local/bin/drachtio", content)
        self.assertNotIn("--config", content)
        self.assertEqual(content.count("command: [--file,"), 2)
        for setting in (
            "JAMBONES_MYSQL_USER", "JAMBONES_MYSQL_PASSWORD_FILE", "JWT_SECRET_FILE",
            "ENCRYPTION_SECRET_FILE", "JAMBONES_TIME_SERIES_HOST", "DRACHTIO_HOST",
            "DRACHTIO_PORT", "DRACHTIO_SECRET_FILE", "JAMBONES_FREESWITCH_HOST",
            "JAMBONES_FREESWITCH_PORT", "JAMBONES_FREESWITCH_PASSWORD_FILE",
            "FREESWITCH_EVENT_SOCKET_PASSWORD_FILE", "RECOVA_REGISTRATION_F12_BASE_URL",
            "RECOVA_F12_ENDPOINT_CREDENTIAL_PATH", "RECOVA_STOCK_BASE_URL",
            "RECOVA_STOCK_API_TOKEN_FILE", "RECOVA_DISPATCH_PUBLIC_KEY_PATH",
            "RECOVA_MEDIA_PUBLIC_KEY_PATH",
        ):
            self.assertIn(setting + ":", content)
        self.assertNotRegex(content, r"(?m)^\s*(?:G009_)?(?:JAMBONES_MYSQL_PASSWORD|JWT_SECRET|ENCRYPTION_SECRET|DRACHTIO_SECRET|FREESWITCH_EVENT_SOCKET_PASSWORD):")
        self.assertNotIn("--secret,", content)
        self.assertEqual(content.count("--secret-file,"), 2)
        for name in (
            "g009-jambones-mysql-password", "g009-jwt-secret", "g009-encryption-secret",
            "g009-drachtio-feature-secret", "g009-drachtio-sip-secret",
            "g009-freeswitch-esl-password",
        ):
            self.assertIn(f"{name}:\n    file: ${{", content)
        self.assertIn("registration-egress-proof:", content)
        self.assertIn("G009_REGISTRATION_EGRESS_PROOF_FILE", content)
        self.assertIn("f12-endpoint-credential:", content)
        self.assertIn("RECOVA_F12_ENDPOINT_CREDENTIAL_FILE", content)
        self.assertIn("RECOVA_STOCK_BASE_URL: http://api:3000", content)
        self.assertIn("recova-backend:", content)
        for setting in (
            "ONNURI_SMOKE_DISPATCH_KEY_ID",
            "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_KEY_ID",
            "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_RECOVERY_KEY_FILE",
        ):
            self.assertIn(setting + ":", content)
        for target in (
            "g008-dispatch-es256-private-key",
            "g008-dispatch-es256-public-key",
            "g008-media-es256-private-key",
            "g008-media-es256-public-key",
            "g008-authority-recovery-key",
        ):
            self.assertIn("target: " + target, content)
        for file_ref in (
            "ONNURI_SMOKE_DISPATCH_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_DISPATCH_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_PRIVATE_KEY_FILE",
            "ONNURI_SMOKE_MEDIA_PUBLIC_KEY_FILE",
            "ONNURI_SMOKE_RECOVERY_KEY_FILE",
        ):
            self.assertIn("${" + file_ref + ":?", content)
        self.assertIn("RTPENGINE_DTMF_LOG_PORT: '22223'", content)
        self.assertIn("DTMF_ONLY: '1'", content)

    def test_private_f12_topology_is_segmented_authenticated_and_fail_closed(self) -> None:
        content = COMPOSE.read_text(encoding="utf-8")
        ingress = INGRESS_CONFIG.read_text(encoding="utf-8")
        facade_start = content.index("\n  facade:") + 1
        postgres_start = content.index("\n  recova-postgres:", facade_start) + 1
        redis_start = content.index("\n  recova-redis:", postgres_start) + 1
        migration_start = content.index("\n  recova-migrate:", redis_start) + 1
        backend_start = content.index("\n  recova-backend:", migration_start) + 1
        ingress_start = content.index("\n  f12-ingress:", backend_start) + 1
        registration_start = content.index("\n  registration-bootstrap:", ingress_start) + 1
        facade = content[facade_start:postgres_start]
        postgres = content[postgres_start:redis_start]
        redis = content[redis_start:migration_start]
        migration = content[migration_start:backend_start]
        backend = content[backend_start:ingress_start]
        proxy = content[ingress_start:registration_start]

        self.assertIn(
            "FACADE_APP_FACTORY: "
            "api.services.telephony.providers.jambonz.facade.app:create_facade_app",
            facade,
        )
        self.assertIn("RECOVA_STOCK_BASE_URL: http://api:3000", facade)
        self.assertIn(
            "RECOVA_F12_BASE_URL: "
            "https://f12-ingress:8443/api/v1/internal/onnuri-smoke",
            facade,
        )
        self.assertIn(
            "RECOVA_MEDIA_WEBSOCKET_URL: "
            "wss://f12-ingress:8443/api/v1/telephony/jambonz/onnuri-smoke/media",
            facade,
        )
        self.assertIn("networks: [g009-internal, f12-client]", facade)
        self.assertNotIn("f12-backend", facade)
        self.assertNotIn("f12-data", facade)
        self.assertNotIn("transaction-control", facade)
        self.assertNotIn("onnuri_route_receipts", facade)
        self.assertNotIn("verify_route_chain", facade)
        self.assertIn("networks: [f12-backend, f12-data]", backend)
        self.assertNotIn("f12-client", backend)
        self.assertNotIn("transaction-control", backend)
        self.assertIn("networks: [f12-client, f12-backend]", proxy)
        self.assertNotIn("transaction-control", proxy)
        self.assertEqual(postgres.count("networks: [f12-data]"), 1)
        self.assertEqual(redis.count("networks: [f12-data]"), 1)
        self.assertIn("POSTGRES_PASSWORD_FILE: /run/secrets/recova-postgres-password", postgres)
        self.assertIn("sealed-secret-wrapper.sh, redis, /run/secrets/recova-redis-password", redis)
        self.assertIn("sealed-secret-wrapper.sh, redis-health, /run/secrets/recova-redis-password", redis)
        self.assertIn("sealed-secret-wrapper.sh, migrate, /run/secrets/g008-recova-postgres-password", migration)
        self.assertIn("sealed-secret-wrapper.sh, backend, /run/secrets/g008-recova-postgres-password, /run/secrets/g008-recova-redis-password", backend)
        self.assertNotIn("DATABASE_URL=", migration)
        self.assertNotIn("DATABASE_URL=", backend)
        self.assertNotIn("REDIS_URL=", backend)
        self.assertIn("recova-migrate:", backend)
        self.assertIn("condition: service_completed_successfully", backend)
        for gate in (
            "RECOVA_SIP_ENABLED", "RECOVA_RTP_ENABLED", "RECOVA_REGISTER_ENABLED",
            "RECOVA_OUTBOUND_CALLS_ENABLED", "RECOVA_INBOUND_CALLS_ENABLED",
        ):
            required_gate = f"{gate}: ${{{gate}:?{gate} must be gate-derived}}"
            self.assertEqual(content.count(required_gate), 3)
            self.assertNotIn(f"{gate}: '${{{gate}:-true}}'", content)
            self.assertNotIn(f"{gate}: true", content)
        self.assertIn("ssl_verify_client optional;", ingress)
        self.assertIn("ssl_protocols TLSv1.3;", ingress)
        self.assertIn("X-Recova-Verified-Mtls-Identity $ssl_client_s_dn", ingress)
        self.assertIn("X-Recova-Verified-Mtls-Issuer $ssl_client_i_dn", ingress)
        for header in ("Authorization", "Cookie", "X-Api-Key"):
            self.assertIn(f'proxy_set_header {header} "";', ingress)
        self.assertIn("location = /api/v1/internal/onnuri-smoke/ready", ingress)
        self.assertEqual(ingress.count("if ($ssl_client_verify != SUCCESS)"), 2)
        self.assertIn(
            "location = /api/v1/telephony/jambonz/onnuri-smoke/media", ingress
        )
        media_start = ingress.index(
            "location = /api/v1/telephony/jambonz/onnuri-smoke/media"
        )
        media = ingress[media_start:ingress.index("location / {")]
        self.assertIn("proxy_set_header Authorization $http_authorization;", media)
        self.assertIn('proxy_set_header X-Recova-Verified-Mtls-Identity "";', media)
        self.assertIn('proxy_set_header X-Recova-Verified-Mtls-Issuer "";', media)
        self.assertIn('proxy_set_header X-Recova-Onnuri-Endpoint-Credential "";', media)

    def test_database_credential_transport_is_file_only(self) -> None:
        content = BOOTSTRAP.read_text(encoding="utf-8")
        wrapper = SEALED_SECRET_WRAPPER.read_text(encoding="utf-8")
        self.assertIn("set -eu", content)
        self.assertNotIn("set -x", content)
        self.assertNotIn("echo ", content)
        self.assertIn("G009_WEBHOOK_SECRET_FILE", content)
        self.assertIn("G009_ACCOUNT_API_TOKEN_FILE", content)
        self.assertIn("G009_JAMBONES_MYSQL_PASSWORD_FILE", content)
        self.assertIn("SET @g009_webhook_secret", content)
        self.assertIn("SET @g009_account_api_token", content)
        self.assertIn("--defaults-extra-file=\"$g009_mysql_defaults_file\"", content)
        self.assertIn("trap 'rm -f \"$g009_mysql_defaults_file\"' EXIT HUP INT TERM", content)
        self.assertNotIn("MYSQL_PWD", content)
        self.assertNotIn("--password=", content)
        self.assertIn('cat "$G009_UPSTREAM_SCHEMA_FILE"', content)
        self.assertIn("10-g009-minimal-seed.sql", content)
        self.assertEqual(content.count("cat /bootstrap/20-g009-registration-template.sql"), 1)
        self.assertIn("G009_REGISTRATION_BOOTSTRAP", content)
        self.assertIn("g009_require_empty_registration_rows", content)
        self.assertIn("g009_require_registration_cardinality", content)
        self.assertIn("CREATE USER IF NOT EXISTS", content)
        self.assertIn("CONVERT(0x%s USING utf8mb4)", content)
        self.assertIn("requirepass ", wrapper)
        self.assertIn("exec redis-server \"$redis_config\"", wrapper)
        self.assertNotIn("--requirepass", wrapper)
        self.assertNotIn("redis-cli", wrapper)
        self.assertIn("os.environ = environment", wrapper)
        self.assertIn('environment.pop("DATABASE_URL")', wrapper)
        self.assertIn('environment.pop("REDIS_URL")', wrapper)

    def test_candidate_example_has_no_secret_values(self) -> None:
        values = dict(
            line.split("=", 1)
            for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        )
        for name, value in values.items():
            if re.search(r"(?:PASSWORD|SECRET|TOKEN|CREDENTIAL)(?:_FILE)?$", name):
                self.assertTrue(name.endswith("_FILE"), name)
                self.assertTrue(value.startswith("/"), name)
        for obsolete in (
            "G009_JAMBONES_MYSQL_PASSWORD",
            "G009_JWT_SECRET",
            "G009_ENCRYPTION_SECRET",
            "G009_DRACHTIO_FEATURE_SECRET",
            "G009_DRACHTIO_SIP_SECRET",
            "G009_FREESWITCH_ESL_PASSWORD",
            "RECOVA_F12_ENDPOINT_CREDENTIAL",
            "RECOVA_STOCK_API_TOKEN",
        ):
            self.assertNotIn(obsolete, values)
        self.assertNotIn("G009_REGISTRATION_NONCE", values)
        self.assertNotRegex(ENV_EXAMPLE.read_text(encoding="utf-8"), r"(?m)^G009_REGISTRATION_NONCE=")

    def test_credential_adapter_does_not_publish_secret_to_child_argv_or_environment(self) -> None:
        secret = "hermetic-credential-value"
        program = r'''
import os
import subprocess
import sys
import time

private = dict(os.environ)
private["DATABASE_URL"] = "postgresql://recova:" + sys.argv[1] + "@database/recova"
os.environ = private
private.pop("DATABASE_URL")
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"])
print(child.pid, flush=True)
time.sleep(2)
'''
        process = subprocess.Popen(
            [sys.executable, "-c", program, secret],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            self.assertIsNotNone(process.stdout)
            child_pid = int(process.stdout.readline().strip())
            proc = Path("/proc") / str(child_pid)
            if not proc.exists():
                self.skipTest("procfs is unavailable")
            self.assertNotIn(secret.encode(), (proc / "cmdline").read_bytes())
            self.assertNotIn(secret.encode(), (proc / "environ").read_bytes())
        finally:
            process.terminate()
            process.wait(timeout=5)

    def test_compose_config_renders_with_synthetic_digests_without_starting(self) -> None:
        standalone = shutil.which("docker-compose")
        docker = shutil.which("docker")
        if standalone is not None:
            compose_command = [standalone]
        elif docker is not None:
            compose_command = [docker, "compose"]
        else:
            self.skipTest("Docker Compose is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = root / "jambones-sql.sql"
            schema.write_text("SELECT 1;\n")
            env = {}
            for key in ALL_IMAGES:
                env[key] = DIGEST
            secret_names = (
                "MARIADB_ROOT_PASSWORD", "WEBHOOK_SECRET", "ACCOUNT_API_TOKEN",
                "JAMBONES_MYSQL_PASSWORD", "JWT_SECRET", "ENCRYPTION_SECRET",
                "DRACHTIO_FEATURE_SECRET", "DRACHTIO_SIP_SECRET", "FREESWITCH_ESL_PASSWORD",
            )
            for name in secret_names:
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["G009_" + name + "_FILE"] = str(secret)
            for name in (
                "F12_CLIENT_CERTIFICATE", "F12_CLIENT_KEY", "F12_CA_CERTIFICATE",
            ):
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["RECOVA_" + name + "_FILE"] = str(secret)
            for name in (
                "DISPATCH_PUBLIC_KEY", "MEDIA_PUBLIC_KEY", "DISPATCH_PRIVATE_KEY",
                "MEDIA_PRIVATE_KEY", "RECOVERY_KEY",
            ):
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["ONNURI_SMOKE_" + name + "_FILE"] = str(secret)
            for name in (
                "RECOVA_POSTGRES_PASSWORD", "RECOVA_REDIS_PASSWORD",
                "F12_SERVER_CERTIFICATE", "F12_SERVER_KEY",
                "F12_CLIENT_CA_CERTIFICATE",
            ):
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["G008_" + name + "_FILE"] = str(secret)
            endpoint_credential = root / "f12-endpoint-credential"
            endpoint_credential.write_text("credential\n")
            env["RECOVA_F12_ENDPOINT_CREDENTIAL_FILE"] = str(endpoint_credential)
            for name in (
                "REGISTRATION_F12_CLIENT_CERTIFICATE",
                "REGISTRATION_F12_CLIENT_KEY",
                "REGISTRATION_F12_CA_CERTIFICATE",
                "REGISTRATION_F12_ENDPOINT_CREDENTIAL",
            ):
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["RECOVA_" + name + "_FILE"] = str(secret)
            for name in (
                "REGISTRATION_ATTESTATION_PRIVATE_KEY",
                "REGISTRATION_ATTESTATION_PUBLIC_KEY",
                "EXECUTION_EVIDENCE_PRIVATE_KEY",
                "EXECUTION_EVIDENCE_PUBLIC_KEY",
            ):
                secret = root / name.lower()
                secret.write_text("synthetic-value\n")
                env["ONNURI_SMOKE_" + name + "_FILE"] = str(secret)
            execution_inputs = {
                "G008_EXECUTION_REQUEST_FILE": root / "execution-request",
                "G008_EXECUTION_SIP_USERNAME_FILE": root / "execution-sip-username",
                "G008_EXECUTION_SIP_PASSWORD_FILE": root / "execution-sip-password",
                "G008_EXECUTION_SIP_REALM_FILE": root / "execution-sip-realm",
                "G008_EXECUTION_TARGET_FILE": root / "execution-target",
                "G008_EXECUTION_NONCE_FILE": root / "execution-nonce",
                "G008_OPERATOR_CREDENTIAL_FILE": root / "operator-credential",
            }
            for key, payload in execution_inputs.items():
                payload.write_text("synthetic-execution-payload\n")
                env[key] = str(payload)
            output_directory = root / "execution-output"
            output_directory.mkdir()
            env["G008_EXECUTION_OUTPUT_DIRECTORY"] = str(output_directory)
            env["G008_EXECUTION_REQUEST_SHA256"] = "b" * 64
            env.update(
                {
                    "G009_JAMBONES_MYSQL_USER": "jambones",
                }
            )
            required_substitutions = set(
                re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?", COMPOSE.read_text())
            )
            for key in required_substitutions:
                self.assertNotIn(
                    key,
                    {
                        "G009_JAMBONES_MYSQL_PASSWORD", "G009_JWT_SECRET",
                        "G009_ENCRYPTION_SECRET", "G009_DRACHTIO_FEATURE_SECRET",
                        "G009_DRACHTIO_SIP_SECRET", "G009_FREESWITCH_ESL_PASSWORD",
                    },
                )
                env.setdefault(key, "synthetic-bound-value")
            (root / "registration-proof").write_text("reviewed-narrow-egress-only\n")
            env["G009_UPSTREAM_SCHEMA_FILE"] = str(schema)
            base_command = compose_command + ["-f", str(COMPOSE)]
            completed = subprocess.run(
                base_command + ["config", "--format", "json"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            completed_profile = subprocess.run(
                base_command
                + [
                    "--profile", "registration",
                    "--profile", "g008-live-smoke",
                    "config", "--format", "json",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
        rendered = json.loads(completed.stdout)
        base_services = rendered["services"]
        self.assertEqual(
            set(base_services),
            EXPECTED_SERVICES - {
                "registration-authority", "sip-sidecar-register",
                "sip-sidecar-unregister", "registration-bootstrap",
                "g008-live-smoke-runner",
            },
        )
        rendered = json.loads(completed_profile.stdout)
        services = rendered["services"]
        self.assertEqual(set(services), EXPECTED_SERVICES)
        expected_networks = {
            "g009-internal",
            "registration-internal",
            "registration-supplier-egress",
            "f12-client",
            "f12-backend",
            "f12-data",
            "transaction-control",
        }
        self.assertEqual(set(rendered["networks"]), expected_networks)
        self.assertEqual(
            {
                network for network, config in rendered["networks"].items()
                if config.get("internal", False)
            },
            expected_networks - {"registration-supplier-egress"},
        )
        expected_service_networks = {
            "mariadb": {"g009-internal"},
            "redis": {"g009-internal"},
            "database-bootstrap": {"g009-internal"},
            "api": {"g009-internal"},
            "feature-server": {"g009-internal"},
            "rtpengine": {"g009-internal"},
            "drachtio-sip": {"g009-internal", "registration-internal"},
            "call-router": {"g009-internal"},
            "facade": {"g009-internal", "f12-client"},
            "recova-postgres": {"f12-data"},
            "recova-redis": {"f12-data"},
            "recova-migrate": {"f12-data"},
            "recova-backend": {"f12-backend", "f12-data"},
            "f12-ingress": {"f12-client", "f12-backend"},
            "registration-authority": {
                "registration-internal",
                "registration-supplier-egress",
                "f12-client",
                "transaction-control",
            },
            "registration-bootstrap": {"g009-internal"},
            "g008-live-smoke-runner": {
                "g009-internal", "f12-client", "transaction-control",
            },
        }
        self.assertEqual(
            {
                name: set(service["networks"])
                for name, service in services.items()
                if "networks" in service
            },
            expected_service_networks,
        )
        self.assertEqual(
            {
                name for name, networks in expected_service_networks.items()
                if "transaction-control" in networks
            },
            {"registration-authority", "g008-live-smoke-runner"},
        )
        self.assertEqual(
            {
                name for name, networks in expected_service_networks.items()
                if "f12-client" in networks
            },
            {
                "facade", "registration-authority", "f12-ingress",
                "g008-live-smoke-runner",
            },
        )
        for service_name in ("recova-backend", "drachtio-sip"):
            networks = expected_service_networks[service_name]
            self.assertNotIn("transaction-control", networks, service_name)
            self.assertNotIn("f12-client", networks, service_name)
        authority_networks = services["registration-authority"]["networks"]
        runner_networks = services["g008-live-smoke-runner"]["networks"]
        self.assertEqual(
            authority_networks["transaction-control"]["ipv4_address"], "172.32.0.2"
        )
        self.assertEqual(
            runner_networks["transaction-control"]["ipv4_address"], "172.32.0.3"
        )
        self.assertEqual(
            services["registration-authority"]["environment"][
                "G008_TRANSACTION_CONTROL_HOST"
            ],
            "172.32.0.2",
        )
        self.assertEqual(
            services["g008-live-smoke-runner"]["environment"][
                "G008_TRANSACTION_BROKER_HOST"
            ],
            "172.32.0.2",
        )
        runner = services["g008-live-smoke-runner"]
        runner_environment = runner["environment"]
        self.assertEqual(
            runner_environment["G008_AUTHORITY_BASE_URL"],
            "https://f12-ingress:8443/api/v1/internal/onnuri-smoke",
        )
        for obsolete in (
            "G008_SIP_USERNAME_SECRET_VERSION",
            "G008_SIP_PASSWORD_SECRET_VERSION",
            "G008_SIP_REALM_SECRET_VERSION",
            "G008_OWNED_TARGET_SECRET_VERSION",
        ):
            self.assertNotIn(obsolete, runner_environment)
        expected_execution_mounts = {
            "/run/g008-execution/request",
            "/run/g008-execution/sip-username",
            "/run/g008-execution/sip-password",
            "/run/g008-execution/sip-realm",
            "/run/g008-execution/target",
            "/run/g008-execution/execution-nonce",
            "/run/g008-execution/operator-credential",
        }
        execution_mounts = {
            volume["target"]: volume
            for volume in runner["volumes"]
            if volume["target"].startswith("/run/g008-execution/")
        }
        self.assertEqual(set(execution_mounts), expected_execution_mounts)
        for target, volume in execution_mounts.items():
            self.assertEqual(volume["type"], "bind", target)
            self.assertTrue(volume["read_only"], target)
            self.assertFalse(volume["bind"]["create_host_path"], target)
        output_mount = next(
            volume for volume in runner["volumes"]
            if volume["target"] == "/run/g008-output"
        )
        self.assertEqual(output_mount["type"], "bind")
        self.assertFalse(output_mount.get("read_only", False))
        self.assertFalse(output_mount["bind"]["create_host_path"])
        runner_configs = {
            config["target"]: config for config in runner["configs"]
        }
        self.assertEqual(
            set(runner_configs),
            {
                "/opt/g008/run-g008-live-smoke.py",
                "/opt/g008/trusted/phase_c_live_preflight_v1.json",
            },
        )
        self.assertEqual(
            runner_configs["/opt/g008/run-g008-live-smoke.py"]["mode"], "0555"
        )
        self.assertEqual(
            runner_configs[
                "/opt/g008/trusted/phase_c_live_preflight_v1.json"
            ]["mode"],
            "0444",
        )
        runner_secret_sources = {
            secret["source"] if isinstance(secret, dict) else secret
            for secret in runner.get("secrets", [])
        }
        self.assertTrue(
            {
                "registration-f12-client-key",
                "registration-f12-client-certificate",
                "registration-f12-ca-certificate",
                "registration-f12-endpoint-credential",
                "registration-attestation-es256-public-key",
            }.issubset(runner_secret_sources)
        )
        self.assertNotIn(
            "registration-attestation-es256-private-key", runner_secret_sources
        )
        raw_route_authority = (
            "route-packet", "route-decision", "route-conformance", "route-adapter",
            "route-keyset", "route-revocation", "route_chain",
        )
        for service_name in ("g008-live-smoke-runner", "facade"):
            rendered_service = json.dumps(services[service_name], sort_keys=True)
            for marker in raw_route_authority:
                self.assertNotIn(marker, rendered_service, service_name)
        self.assertEqual(
            services["recova-backend"]["depends_on"]["recova-migrate"]["condition"],
            "service_completed_successfully",
        )
        self.assertEqual(services["recova-migrate"]["platform"], "linux/amd64")
        self.assertEqual(services["recova-backend"]["platform"], "linux/amd64")
        facade_environment = services["facade"]["environment"]
        self.assertEqual(
            facade_environment["FACADE_APP_FACTORY"],
            "api.services.telephony.providers.jambonz.facade.app:create_facade_app",
        )
        self.assertEqual(facade_environment["RECOVA_STOCK_BASE_URL"], "http://api:3000")
        self.assertEqual(
            facade_environment["RECOVA_F12_BASE_URL"],
            "https://f12-ingress:8443/api/v1/internal/onnuri-smoke",
        )
        self.assertEqual(
            facade_environment["RECOVA_MEDIA_WEBSOCKET_URL"],
            "wss://f12-ingress:8443/api/v1/telephony/jambonz/onnuri-smoke/media",
        )
        facade_secret_sources = {
            secret["source"] if isinstance(secret, dict) else secret
            for secret in services["facade"]["secrets"]
        }
        self.assertTrue(
            {
                "registration-f12-client-certificate",
                "registration-f12-client-key",
                "registration-f12-ca-certificate",
                "registration-f12-endpoint-credential",
            }.issubset(facade_secret_sources)
        )
        for name, service in services.items():
            self.assertEqual(service["pull_policy"], "never", name)
            self.assertNotIn("ports", service)
        self.assertEqual(services["drachtio-feature"]["network_mode"], "service:feature-server")
        self.assertEqual(services["freeswitch"]["network_mode"], "service:feature-server")
        self.assertEqual(services["rtpengine-sidecar"]["network_mode"], "service:rtpengine")
        providers = {
            "register": services["sip-sidecar-register"],
            "unregister": services["sip-sidecar-unregister"],
        }
        for operation, provider in providers.items():
            self.assertEqual(set(provider["profiles"]), {"g008-live-smoke"})
            provider_environment = provider["environment"]
            self.assertEqual(
                provider_environment["RECOVA_ONE_SHOT_OPERATION_KIND"], operation
            )
            for identifier in (
                "RECOVA_ONE_SHOT_OPERATION_UUID",
                "RECOVA_ONE_SHOT_ORGANIZATION_ID",
                "RECOVA_ONE_SHOT_REGISTRATION_GATE_ID",
                "RECOVA_ONE_SHOT_REQUEST_DIGEST",
                "RECOVA_ONE_SHOT_CANDIDATE_DIGEST",
                "RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST",
                "RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST",
            ):
                self.assertNotIn(identifier, provider_environment)
            self.assertEqual(provider["network_mode"], "service:drachtio-sip")
            self.assertEqual(provider["deploy"]["replicas"], 1)
            self.assertEqual(provider["restart"], "no")
            self.assertEqual(
                {
                    secret["source"] if isinstance(secret, dict) else secret
                    for secret in provider["secrets"]
                },
                {
                    "g009-drachtio-sip-secret",
                    "g009-jambones-mysql-password",
                    "g009-jwt-secret",
                    "g009-encryption-secret",
                },
            )
            self.assertNotIn("configs", provider)
            self.assertIn(
                f"/run/g008-registration-control/{operation}.ready",
                provider["command"][2],
            )
        private_authority_environment = {
            "RECOVA_REGISTRATION_F12_BASE_URL",
            "RECOVA_F12_CLIENT_CERTIFICATE_PATH",
            "RECOVA_F12_CLIENT_KEY_PATH",
            "RECOVA_F12_CA_CERTIFICATE_PATH",
            "RECOVA_F12_ENDPOINT_CREDENTIAL_PATH",
            "G009_DISPATCH_PUBLIC_KEY_PATH",
            "G009_DISPATCH_KEY_ID",
            "ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID",
            "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PRIVATE_KEY_FILE",
            "G009_REGISTRATION_EGRESS_PROOF_PATH",
            "G008_TRANSACTION_CONTROL_HOST",
            "G008_TRANSACTION_CONTROL_PORT",
        }
        for provider in providers.values():
            self.assertEqual(
                set(provider["environment"]) & private_authority_environment,
                set(),
            )
        authority = services["registration-authority"]
        for identifier in (
            "RECOVA_ONE_SHOT_OPERATION_UUID",
            "RECOVA_ONE_SHOT_ORGANIZATION_ID",
            "RECOVA_ONE_SHOT_REGISTRATION_GATE_ID",
            "RECOVA_ONE_SHOT_REQUEST_DIGEST",
            "RECOVA_ONE_SHOT_CANDIDATE_DIGEST",
            "RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST",
            "RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST",
        ):
            self.assertNotIn(identifier, authority["environment"])
        self.assertEqual(
            set(authority["profiles"]), {"registration", "g008-live-smoke"}
        )
        self.assertEqual(authority["user"], "1000:1000")
        self.assertEqual(
            set(authority["networks"]),
            {
                "registration-internal",
                "registration-supplier-egress",
                "f12-client",
                "transaction-control",
            },
        )
        self.assertEqual(len(authority["secrets"]), 6)
        self.assertEqual(
            authority["volumes"][0]["source"], "g008-registration-control"
        )
        self.assertEqual(
            {secret["target"] for secret in authority["secrets"]},
            {
                "dispatch-es256-public-key",
                "registration-f12-client-certificate",
                "registration-f12-client-key",
                "registration-f12-ca-certificate",
                "registration-f12-endpoint-credential",
                "registration-attestation-es256-private-key",
            },
        )
        bootstrap_volume = services["registration-bootstrap"]["volumes"][0]
        self.assertEqual(bootstrap_volume["type"], "volume")
        self.assertEqual(bootstrap_volume["source"], "g008-live-smoke-secrets")
        self.assertEqual(bootstrap_volume["target"], "/run/g008-secrets")
        self.assertTrue(bootstrap_volume["read_only"])
        self.assertEqual(
            authority["depends_on"]["registration-bootstrap"]["condition"],
            "service_completed_successfully",
        )
        for provider in providers.values():
            self.assertEqual(
                provider["depends_on"]["registration-authority"]["condition"],
                "service_healthy",
            )
        self.assertEqual(
            set(services["registration-bootstrap"]["profiles"]),
            {"registration", "g008-live-smoke"},
        )
        for provider in providers.values():
            self.assertEqual(
                provider["depends_on"]["registration-bootstrap"]["condition"],
                "service_completed_successfully",
            )
        self.assertEqual(
            services["facade"]["environment"]["RECOVA_STOCK_BASE_URL"],
            "http://api:3000",
        )
        self.assertEqual(services["mariadb"]["user"], "999:999")
        self.assertEqual(services["redis"]["user"], "redis")
        self.assertIn("--socket=/tmp/mariadb.sock", services["mariadb"]["command"])
        self.assertEqual(
            services["freeswitch"]["environment"]["FREESWITCH_EVENT_SOCKET_PASSWORD_FILE"],
            "/run/secrets/g009-freeswitch-esl-password",
        )
        self.assertEqual(
            json.loads(services["facade"]["environment"]["FACADE_ASGI_COMMAND_JSON"])[:3],
            ["python", "-m", "uvicorn"],
        )
        for name, service in services.items():
            self.assertTrue(service["read_only"], name)
            self.assertEqual(service["cap_drop"], ["ALL"], name)
            self.assertIn("no-new-privileges:true", service["security_opt"], name)
            self.assertEqual(service["logging"]["driver"], "none", name)
            self.assertTrue(service["tmpfs"], name)

    @unittest.skipUnless(shutil.which("node"), "Node is required for proof verification")
    def test_registration_authorization_is_exact_short_lived_and_linked(self) -> None:
        def canonical(value: object) -> bytes:
            return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

        def authorization(
            private_key: ec.EllipticCurvePrivateKey, claims: dict
        ) -> str:
            unsigned = {
                "algorithm": "ES256",
                "claims": claims,
                "key_id": "dispatch",
                "verification_domain": "recova.onnuri.smoke.registration.v1",
            }
            der = private_key.sign(canonical(unsigned), ec.ECDSA(hashes.SHA256()))
            r_value, s_value = decode_dss_signature(der)
            signature = base64.urlsafe_b64encode(
                r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
            ).rstrip(b"=").decode()
            return base64.urlsafe_b64encode(
                canonical({**unsigned, "signature": signature})
            ).rstrip(b"=").decode()

        def db_time(epoch: int) -> str:
            return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))

        now = int(time.time())
        values = {
            "candidate_digest": "2" * 64,
            "concurrency_count": 1,
            "envelope_digest": "3" * 64,
            "expires_at": db_time(now + 59),
            "gate_envelope_digest": "3" * 64,
            "issued_at": db_time(now - 1),
            "max_elapsed_seconds": 60,
            "nonce_digest": "4" * 64,
            "operation_kind": "register",
            "operation_uuid": "70090000-0000-4000-8000-000000000010",
            "organization_id": 7,
            "prior_register_gate_id": None,
            "prior_register_operation_uuid": None,
            "registration_gate_id": 11,
            "request_digest": "1" * 64,
            "retry_count": 0,
            "transaction_count": 1,
            "verification_domain": "recova.onnuri.smoke.registration.v1",
        }
        private_key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            proof = root / "proof.authorization"
            public_key = root / "public.pem"
            public_key.write_bytes(
                private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            environment = {
                **os.environ,
                "G009_REGISTRATION_EGRESS_PROOF_PATH": str(proof),
                "G009_DISPATCH_PUBLIC_KEY_PATH": str(public_key),
                "G009_DISPATCH_KEY_ID": "dispatch",
                "RECOVA_ONE_SHOT_ORGANIZATION_ID": "7",
                "RECOVA_ONE_SHOT_REGISTRATION_GATE_ID": "11",
                "RECOVA_ONE_SHOT_OPERATION_KIND": "register",
                "RECOVA_ONE_SHOT_OPERATION_UUID": values["operation_uuid"],
                "RECOVA_ONE_SHOT_REQUEST_DIGEST": values["request_digest"],
                "RECOVA_ONE_SHOT_CANDIDATE_DIGEST": values["candidate_digest"],
                "RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST": values[
                    "gate_envelope_digest"
                ],
                "RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST": values[
                    "nonce_digest"
                ],
            }
            environment.pop("RECOVA_ONE_SHOT_PRIOR_REGISTER_GATE_ID", None)
            environment.pop("RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID", None)
            unregister = {
                **values,
                "operation_kind": "unregister",
                "prior_register_gate_id": 9,
                "prior_register_operation_uuid":
                    "70090000-0000-4000-8000-000000000009",
            }
            unregister_environment = {
                **environment,
                "RECOVA_ONE_SHOT_OPERATION_KIND": "unregister",
                "RECOVA_ONE_SHOT_PRIOR_REGISTER_GATE_ID": "9",
                "RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID": unregister[
                    "prior_register_operation_uuid"
                ],
            }
            cases = [
                ("valid-register", values, environment, 0),
                ("valid-unregister", unregister, unregister_environment, 0),
                (
                    "expired",
                    {
                        **values,
                        "issued_at": db_time(now - 121),
                        "expires_at": db_time(now - 61),
                    },
                    environment,
                    64,
                ),
                ("extra-claim", {**values, "unexpected": True}, environment, 64),
                (
                    "wrong-candidate",
                    values,
                    {
                        **environment,
                        "RECOVA_ONE_SHOT_CANDIDATE_DIGEST": "9" * 64,
                    },
                    64,
                ),
                (
                    "wrong-transaction-count",
                    {**values, "transaction_count": 2},
                    environment,
                    64,
                ),
                (
                    "wrong-concurrency",
                    {**values, "concurrency_count": 0},
                    environment,
                    64,
                ),
                (
                    "missing-operation-environment",
                    values,
                    {
                        key: value for key, value in environment.items()
                        if key != "RECOVA_ONE_SHOT_OPERATION_UUID"
                    },
                    64,
                ),
                (
                    "unregister-missing-prior",
                    unregister,
                    environment | {"RECOVA_ONE_SHOT_OPERATION_KIND": "unregister"},
                    64,
                ),
            ]
            for name, claims, case_environment, expected in cases:
                with self.subTest(name=name):
                    proof.write_text(authorization(private_key, claims) + "\n")
                    result = subprocess.run(
                        [shutil.which("node"), str(REGISTRATION_GUARD)],
                        env=case_environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, "")

    def test_registration_runner_is_single_use_fail_closed_and_redacted(self) -> None:
        runner = REGISTRATION_RUNNER.read_text(encoding="utf-8")
        attestor = REGISTRATION_ATTESTOR.read_text(encoding="utf-8")
        self.assertEqual(runner.count("registration/consume"), 1)
        self.assertEqual(runner.count("registration/finalize"), 1)
        self.assertNotIn("spawn", runner)
        self.assertNotIn("app.js", runner)
        self.assertNotIn("process.stdout", runner)
        self.assertNotIn("process.stderr", runner)
        self.assertIn("{opaque_execution_attestation: opaque}", runner)
        self.assertLess(
            runner.index("exactObject(consume, consumeBinding(claims))"),
            runner.index("startRegistrationProxy({"),
        )
        self.assertLess(
            runner.index("startRegistrationProxy({"),
            runner.index("const opaque = signExecutionAttestation("),
        )
        self.assertLess(
            runner.index("const opaque = signExecutionAttestation("),
            runner.index("registration/finalize"),
        )
        self.assertIn("dsaEncoding: 'ieee-p1363'", attestor)
        self.assertIn("recova.onnuri.smoke.registration.execution.v1", attestor)
        self.assertNotIn("console.", attestor)
        self.assertNotIn("process.stdout", attestor)
        self.assertNotRegex(
            attestor, r"(?i)\b(?:password|credential|nonce)\b.*(?:log|write)"
        )
        patch = (ROOT / "patch_one_shot_regbot.py").read_text(encoding="utf-8")
        self.assertNotIn("process.stdout.write", patch)
        self.assertNotIn("receiptFields", patch)

    @unittest.skipUnless(shutil.which("node"), "Node is required for attestor tests")
    def test_sip_attestor_signs_only_bounded_observed_supplier_exchanges(self) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "attestation.pem"
            key_path.write_bytes(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            harness = r"""
const fs = require('fs');
const a = require(process.env.ATTESTOR);
const actions = JSON.parse(process.env.ACTIONS);
const claims = {
  candidate_digest: '2'.repeat(64), gate_envelope_digest: '3'.repeat(64),
  nonce_digest: '4'.repeat(64), operation_kind: 'register',
  operation_uuid: '70090000-0000-4000-8000-000000000010',
  organization_id: 7, prior_register_gate_id: null,
  prior_register_operation_uuid: null, registration_gate_id: 11,
  request_digest: '1'.repeat(64)
};
let terminal = null;
let upstreamCount = 0;
let providerCount = 0;
const machine = new a.RegistrationSipAttestor({
  claims, startedAt: 0, deadlineMs: 1000, endpointDigest: '5'.repeat(64),
  providerIpv4: '172.31.0.3',
  now: () => 100, sendUpstream: () => { upstreamCount += 1; },
  sendProvider: () => { providerCount += 1; },
  onTerminal: (value) => { terminal = value; }
});
for (const action of actions) {
  if (action.side === 'deadline') {
    machine.contain();
    continue;
  }
  const packet = Buffer.from(action.packet, 'base64');
  if (action.side === 'provider') machine.observeProvider(packet, {address: '172.31.0.3', port: 5060});
  else machine.observeSupplier(packet);
}
if (!terminal) machine.contain();
const opaque = a.signExecutionAttestation(
  claims, terminal, 'registration-attestation-v1', fs.readFileSync(process.env.KEY)
);
process.stdout.write(JSON.stringify({opaque, upstreamCount, providerCount}));
"""
            def wire(lines: list[str]) -> str:
                return "\r\n".join(lines) + "\r\n\r\n"

            initial = wire([
                "REGISTER sip:carrier.example SIP/2.0",
                "Via: SIP/2.0/UDP 172.31.0.3:5060;branch=z9hG4bKone",
                "From: <sip:user@carrier.example>;tag=a",
                "To: <sip:user@carrier.example>",
                "Call-ID: call-1",
                "CSeq: 1 REGISTER",
                "Contact: <sip:user@172.31.0.3>;expires=3600",
                "Expires: 3600",
                "Content-Length: 0",
            ])
            direct = wire([
                "SIP/2.0 200 OK",
                "Via: SIP/2.0/UDP 172.31.0.3:5060;branch=z9hG4bKone",
                "Call-ID: call-1",
                "CSeq: 1 REGISTER",
                "Contact: <sip:user@172.31.0.3>;expires=3600",
                "Expires: 3600",
                "Content-Length: 0",
            ])

            def challenge(status: int, branch_name: str = "one", cseq_value: int = 1,
                          stale: bool = False) -> str:
                header = "WWW-Authenticate" if status == 401 else "Proxy-Authenticate"
                return wire([
                    f"SIP/2.0 {status} Authentication Required",
                    f"Via: SIP/2.0/UDP 172.31.0.3:5060;branch=z9hG4bK{branch_name}",
                    "Call-ID: call-1",
                    f"CSeq: {cseq_value} REGISTER",
                    f'{header}: Digest realm="carrier",nonce="opaque",stale={"true" if stale else "false"}',
                    "Content-Length: 0",
                ])

            def followup(call_id: str = "call-1") -> str:
                return wire([
                    "REGISTER sip:carrier.example SIP/2.0",
                    "Via: SIP/2.0/UDP 172.31.0.3:5060;branch=z9hG4bKtwo",
                    "From: <sip:user@carrier.example>;tag=a",
                    "To: <sip:user@carrier.example>",
                    f"Call-ID: {call_id}",
                    "CSeq: 2 REGISTER",
                    "Contact: <sip:user@172.31.0.3>;expires=3600",
                    "Expires: 3600",
                    'Authorization: Digest username="redacted",response="redacted"',
                    "Content-Length: 0",
                ])

            final_retry = direct.replace("z9hG4bKone", "z9hG4bKtwo").replace(
                "CSeq: 1 REGISTER", "CSeq: 2 REGISTER"
            )
            redirect = direct.replace("200 OK", "302 Moved")
            malformed = initial.replace("\r\n\r\n", "\n\n")
            cases = {
                "direct-200": ([("provider", initial), ("supplier", direct)], "succeeded", 1),
                "401-then-200": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup()), ("supplier", final_retry)],
                    "succeeded", 2,
                ),
                "407-then-200": (
                    [("provider", initial), ("supplier", challenge(407)),
                     ("provider", followup().replace("Authorization:", "Proxy-Authorization:")),
                     ("supplier", final_retry)],
                    "succeeded", 2,
                ),
                "internal-fake-200": ([("provider", direct)], "contained", 0),
                "malformed": ([("provider", malformed)], "contained", 0),
                "extra-request": ([("provider", initial), ("provider", initial)], "contained", 1),
                "changed-call-id": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup("forged"))],
                    "contained", 1,
                ),
                "changed-aor": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup().replace(
                         "To: <sip:user@carrier.example>",
                         "To: <sip:other@carrier.example>",
                     ))],
                    "contained", 1,
                ),
                "changed-uri": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup().replace(
                         "REGISTER sip:carrier.example",
                         "REGISTER sip:alternate.example",
                     ))],
                    "contained", 1,
                ),
                "changed-cseq": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup().replace("CSeq: 2", "CSeq: 3"))],
                    "contained", 1,
                ),
                "replayed-branch": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup().replace("z9hG4bKtwo", "z9hG4bKone"))],
                    "contained", 1,
                ),
                "third-request": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup()), ("provider", followup())],
                    "contained", 2,
                ),
                "deadline": ([("deadline", "")], "contained", 0),
                "redirect": ([("provider", initial), ("supplier", redirect)], "contained", 1),
                "stale": (
                    [("provider", initial), ("supplier", challenge(401, stale=True))],
                    "contained", 1,
                ),
                "repeated-challenge": (
                    [("provider", initial), ("supplier", challenge(401)),
                     ("provider", followup()), ("supplier", challenge(401, "two", 2))],
                    "contained", 2,
                ),
            }
            for name, (packets, expected_outcome, expected_wire_count) in cases.items():
                with self.subTest(name=name):
                    actions = [
                        {"side": side, "packet": base64.b64encode(packet.encode()).decode()}
                        for side, packet in packets
                    ]
                    result = subprocess.run(
                        [shutil.which("node"), "-e", harness],
                        env={
                            **os.environ,
                            "ATTESTOR": str(REGISTRATION_ATTESTOR),
                            "ACTIONS": json.dumps(actions),
                            "KEY": str(key_path),
                        },
                        capture_output=True, text=True, check=True,
                    )
                    output = json.loads(result.stdout)
                    envelope_bytes = base64.urlsafe_b64decode(
                        output["opaque"] + "=" * (-len(output["opaque"]) % 4)
                    )
                    envelope = json.loads(envelope_bytes)
                    self.assertEqual(
                        envelope_bytes,
                        json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode(),
                    )
                    claims = envelope["claims"]
                    self.assertEqual(claims["outcome"], expected_outcome)
                    self.assertEqual(claims["wire_request_count"], expected_wire_count)
                    self.assertNotIn("carrier.example", envelope_bytes.decode())
                    self.assertNotIn("Authorization", envelope_bytes.decode())
                    signature = base64.urlsafe_b64decode(
                        envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
                    )
                    self.assertEqual(len(signature), 64)
                    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
                    r_value = int.from_bytes(signature[:32], "big")
                    s_value = int.from_bytes(signature[32:], "big")
                    private_key.public_key().verify(
                        encode_dss_signature(r_value, s_value),
                        json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
                        ec.ECDSA(hashes.SHA256()),
                    )

    def test_registration_compose_has_unique_authority_environment_and_mounts(self) -> None:
        content = COMPOSE.read_text(encoding="utf-8")
        authority = content[
            content.index("  registration-authority:"):
            content.index("  sip-sidecar-register:")
        ]
        provider = content[
            content.index("  sip-sidecar-register:"):content.index("  inbound:")
        ]
        sealed_request_identifiers = (
            "RECOVA_ONE_SHOT_OPERATION_UUID",
            "RECOVA_ONE_SHOT_ORGANIZATION_ID",
            "RECOVA_ONE_SHOT_REGISTRATION_GATE_ID",
            "RECOVA_ONE_SHOT_REQUEST_DIGEST",
            "RECOVA_ONE_SHOT_CANDIDATE_DIGEST",
            "RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST",
            "RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST",
        )
        for name in sealed_request_identifiers:
            self.assertNotIn(name, authority)
            self.assertNotIn(name, provider)
        for name in (
            "RECOVA_REGISTRATION_F12_BASE_URL",
            "ONNURI_SMOKE_REGISTRATION_ATTESTATION_PRIVATE_KEY_FILE",
        ):
            self.assertEqual(
                len(re.findall(rf"(?m)^\s+{name}:", authority)), 1, name
            )
            self.assertNotIn(name, provider)
        runner = REGISTRATION_RUNNER.read_text(encoding="utf-8")
        self.assertIn("base.protocol !== 'https:'", runner)
        self.assertIn("base.hostname !== 'f12-ingress'", runner)
        self.assertIn("exactObject(consume, consumeBinding(claims))", runner)
        self.assertIn("schema_version: CONTROL_SCHEMA", runner)
        self.assertIn("Object.fromEntries(HANDOFF_KEYS.map", runner)
        self.assertIn("process.exitCode = 64", runner)
        self.assertIn(
            "readyPath(operation), 'operation-bound\\n', {flag: 'wx', mode: 0o444}",
            runner,
        )
        self.assertNotIn("registration-authority-ready", runner)
        self.assertIn("const path = require('path');", runner)
        self.assertIn("rejectAmbientSecretEnvironment", runner)

    @unittest.skipUnless(shutil.which("node"), "Node is required for transaction runner tests")
    def test_registration_runner_rejects_ambient_secret_environment(self) -> None:
        harness = r"""
const runner = require(process.env.RUNNER);
process.env.G009_JWT_SECRET = 'x';
runner.main({
  startControlServerFn: async () => { throw new Error('must not start'); },
  runTransactionFn: async () => { throw new Error('must not transact'); },
}).then(() => process.exit(process.exitCode === 64 ? 0 : 1));
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness],
            env={"RUNNER": str(REGISTRATION_RUNNER)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which("node"), "Node is required for transaction runner tests")
    def test_registration_runner_entrypoint_reaches_control_setup_without_provider_network(self) -> None:
        harness = r"""
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const runner = require(process.env.RUNNER);
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'g008-entrypoint-'));
const write = (name, value) => {
  const target = path.join(directory, name);
  fs.writeFileSync(target, value, {mode: 0o400});
  return target;
};
const key = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'}).privateKey
  .export({type: 'pkcs8', format: 'pem'});
const endpoint = '{"ipv4":"127.0.0.1","port":5060,"transport":"udp"}';
process.env = {
  RECOVA_F12_CA_CERTIFICATE_PATH: write('ca', 'ca'),
  RECOVA_F12_CLIENT_CERTIFICATE_PATH: write('certificate', 'certificate'),
  RECOVA_F12_CLIENT_KEY_PATH: write('client-key', 'key'),
  RECOVA_F12_ENDPOINT_CREDENTIAL_PATH: write('credential', 'credential\n'),
  RECOVA_REGISTRATION_F12_BASE_URL: 'https://f12-ingress/',
  RECOVA_F12_VERIFIED_IDENTITY: 'identity',
  RECOVA_F12_VERIFIED_ISSUER: 'issuer',
  ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID: 'registration-attestation-test',
  ONNURI_SMOKE_REGISTRATION_ATTESTATION_PRIVATE_KEY_FILE: write('attestation-key', key),
  G009_REGISTRATION_SUPPLIER_IPV4: '127.0.0.1',
  G009_REGISTRATION_AUTHORITY_INGRESS_IPV4: '127.0.0.1',
  G009_REGISTRATION_PROVIDER_IPV4: '127.0.0.1',
  G009_REGISTRATION_SUPPLIER_PORT: '5060',
  G009_REGISTRATION_AUTHORITY_INGRESS_PORT: '5060',
  G009_REGISTRATION_SUPPLIER_TRANSPORT: 'udp',
  ONNURI_SMOKE_REGISTRATION_UPSTREAM_ENDPOINT_SHA256:
    crypto.createHash('sha256').update(endpoint).digest('hex'),
  G008_TRANSACTION_CONTROL_HOST: '172.32.0.2',
  G008_TRANSACTION_CONTROL_PORT: '8079',
};
const operations = [];
let controlStarted = 0;
runner.main({
  startControlServerFn: async () => ({close() { controlStarted += 1; }}),
  runTransactionFn: async (operation) => operations.push(operation),
}).then(() => {
  fs.rmSync(directory, {recursive: true, force: true});
  process.exit(controlStarted === 1 && operations.join(',') === 'register,unregister' &&
    process.exitCode === 0 ? 0 : 1);
});
"""
        result = subprocess.run(
            [shutil.which("node"), "-e", harness],
            env={"RUNNER": str(REGISTRATION_RUNNER)},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
if __name__ == "__main__":
    unittest.main()
