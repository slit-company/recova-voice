import base64
import copy
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_g007_disabled_runtime_evidence.py"
SPEC = importlib.util.spec_from_file_location("g007_evidence", SCRIPT)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)

NOW = "2026-07-16T12:00:35Z"
WINDOW = {"started_at": "2026-07-16T12:00:00Z", "ended_at": "2026-07-16T12:00:30Z"}
PROJECT = "test-project"
RUN = "g007-test-run"
IMAGE_LINK = f"https://compute.example/projects/{PROJECT}/global/images/g009"
NETWORK_LINK = f"https://compute.example/projects/{PROJECT}/global/networks/phase-b"
SUBNET_LINK = f"https://compute.example/projects/{PROJECT}/regions/asia-northeast3/subnetworks/phase-b"
RUNTIME_DIGEST = "sha256:" + "1" * 64
FACADE_IMAGE_DIGEST = "sha256:" + "2" * 64
HASH = "a" * 64
SERVICE_ACCOUNT = f"runtime@{PROJECT}.iam.gserviceaccount.com"


class EvidenceFixture:
    def __init__(self, tmp_path: Path):
        self.path = tmp_path
        self.evidence = tmp_path / "evidence"
        self.evidence.mkdir(parents=True)
        self.private = Ed25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._write_root("trusted.json", {
            "key_id": "g007-offline-authority",
            "public_key_b64": base64.b64encode(public).decode("ascii"),
        })
        self._create_evidence()

    def _write_root(self, name: str, value: object) -> Path:
        path = self.path / name
        path.write_bytes(verifier.canonical_json(value))
        return path

    def write_evidence(self, name: str, value: object, newline: bool = False) -> Path:
        path = self.evidence / name
        path.write_bytes(verifier.canonical_json(value) + (b"\n" if newline else b""))
        return path

    def read(self, name: str) -> dict:
        return verifier.parse_json((self.evidence / name).read_bytes(), name)

    def _create_evidence(self) -> None:
        manifest = {
            "candidate": "g009-approved",
            "support_images": [{"image": f"registry.example/facade@{FACADE_IMAGE_DIGEST}", "name": "facade"}],
        }
        manifest_path = self.write_evidence("candidate-manifest.json", manifest, newline=True)
        manifest_sha = verifier.hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.compute_private = Ed25519PrivateKey.generate()
        compute_public = self.compute_private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        (self.evidence / "g009-compute-receipt-public-key.pem").write_bytes(compute_public)
        compute_payload = {
            "schema_version": "recova-g009-compute-image-receipt/v1",
            "project_id": PROJECT,
            "image_self_link": IMAGE_LINK,
            "image_id": 987654321,
            "image_generation": 1,
            "candidate_manifest_sha256": manifest_sha,
            "source_sha256": "4" * 64,
            "export_sha256": "5" * 64,
            "derivative_sha256": "6" * 64,
            "runtime_image_digest": RUNTIME_DIGEST,
            "facade_image_digest": FACADE_IMAGE_DIGEST,
            "private_probe": {
                "bytes_sent": 0, "instance_id": 123, "registration_profile_absent": True,
                "rtp_flow_records": 0, "services": 13, "sip_flow_records": 0,
            },
            "candidate_receipt_signer_key_id": "g009-test",
            "candidate_receipt_verification_key_sha256": verifier.hashlib.sha256(compute_public).hexdigest(),
            "candidate_receipt_issued_at_utc": "2026-07-16T08:00:00Z",
            "candidate_receipt_expires_at_utc": "2026-07-17T08:00:00Z",
        }
        compute_sha, receipt_sha = self.write_compute_receipt(compute_payload)
        image = {
            "archiveSizeBytes": "1", "candidate_manifest_sha256": manifest_sha,
            "compute_receipt_sha256": receipt_sha, "diskSizeGb": "30",
            "family": "recova-jambonz-g009-disabled",
            "guestOsFeatures": [{"type": "UEFI_COMPATIBLE"}],
            "image_generation": 1, "id": "987654321", "name": "g009",
            "runtime_image_digest": RUNTIME_DIGEST, "selfLink": IMAGE_LINK,
            "status": "READY", "storageLocations": ["asia"],
        }
        facade = {
            "candidate_manifest_sha256": manifest_sha, "compute_receipt_sha256": receipt_sha,
            "image_digest": FACADE_IMAGE_DIGEST, "name": "facade",
        }
        self.write_evidence("image-redacted.json", image)
        self.write_evidence("facade-binding.json", facade)
        labels = {
            "application": "recova", "calls": "disabled", "compute": "running",
            "dispatch": "disabled", "environment": "staging", "goog-terraform-provisioned": "true",
            "managed_by": "terraform", "phase": "c-smoke", "region": "asia-northeast3",
            "rtp": "disabled", "run_id": RUN, "sip": "disabled", "workload": "candidate",
        }
        gates = {
            "inbound-call-enabled": "FALSE", "media-enabled": "FALSE",
            "outbound-call-enabled": "FALSE", "sip-register-enabled": "FALSE",
            "workload-dispatch-enabled": "FALSE",
        }
        instance = {
            "boot_source_image_self_link": IMAGE_LINK, "external_access_config_count": 0,
            "id": "123", "labels": labels,
            "metadata": {**gates, "serial-port-enable": "FALSE", "g009-image-generation": "1",
                         "g009-image-id": "987654321", "g009-image-receipt-sha256": compute_sha},
            "name": "candidate-vm", "network_ip_sha256": HASH, "network_self_link": NETWORK_LINK,
            "service_account_sha256": verifier.hashlib.sha256(SERVICE_ACCOUNT.encode()).hexdigest(),
            "shieldedInstanceConfig": {"enableIntegrityMonitoring": True, "enableSecureBoot": True, "enableVtpm": True},
            "status": "RUNNING", "subnetwork_self_link": SUBNET_LINK,
        }
        self.write_evidence("instance-redacted.json", instance)
        prefix = instance["name"].removesuffix("-vm")
        self.write_evidence("tenant-scope.json", {"binding": "none-before-g3", "project_id": PROJECT, "run_id": RUN})
        self.write_evidence("application-state.json", {
            "boot_marker": "POST_STOP_OK", "gates": gates, "observation_window": WINDOW,
            "product_status": "Waiting", "project_id": PROJECT, "registration_profile_absent": True,
            "run_id": RUN, "services": 13,
        })
        deny_in = {"allowed": None, "denied": [{"IPProtocol": "all"}], "destinationRanges": None,
                   "direction": "INGRESS", "disabled": False, "id": "1",
                   "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"},
                   "name": f"{prefix}-deny-in", "priority": 65534,
                   "sourceRanges": ["0.0.0.0/0"], "targetServiceAccounts": [SERVICE_ACCOUNT]}
        deny_out = {**deny_in, "direction": "EGRESS", "id": "2",
                    "name": f"{prefix}-deny-out", "sourceRanges": None,
                    "destinationRanges": ["0.0.0.0/0"]}
        allow_in = {"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "denied": None,
                    "direction": "INGRESS", "disabled": True, "id": "3", "logConfig": {"enable": False},
                    "name": f"{prefix}-recova-in", "priority": 1100,
                    "sourceRanges_sha256": HASH, "targetServiceAccounts": [SERVICE_ACCOUNT]}
        allow_sip = {**allow_in, "allowed": [{"IPProtocol": "udp", "ports": ["5060"]}],
                     "id": "4", "name": f"{prefix}-sip-in", "priority": 1110}
        allow_out = {**allow_sip, "direction": "EGRESS", "id": "5",
                     "name": f"{prefix}-sip-out"}
        allow_out.pop("sourceRanges_sha256")
        allow_out["destinationRanges_sha256"] = HASH
        self.write_evidence("effective-firewalls.json", {"rules": [deny_in, deny_out, allow_in, allow_sip, allow_out]})
        self.write_evidence("flow-summary.json", {
            "bytes_sent": 0, "destination_ip_sha256_counts": {HASH: 1}, "destination_ports": {"443": 1},
            "packets_attempted": 16, "protocols": {"6": 1}, "records": 1,
            "rtp_records": 0, "sip_records": 0, "window": WINDOW,
        })
        self.write_evidence("provider-zero-traffic.json", {
            "bytes_sent": 0, "call_flow_records": 0, "observation_window": WINDOW,
            "register_events": 0, "registration_profile_absent": True,
            "rtp_flow_records": 0, "sip_flow_records": 0,
        })
        containment_principal = (
            f"{instance['name'].removesuffix('-vm')}-contain@{PROJECT}.iam.gserviceaccount.com"
        )
        self.write_evidence("containment-stop.json", {
            "count": 1, "instance_name": "candidate-vm", "method": "v1.compute.instances.stop",
            "observed": True, "post_restart_marker": "POST_STOP_OK",
            "principal_sha256": verifier.hashlib.sha256(containment_principal.encode()).hexdigest(),
        })
        resources = [
            {"actions": ["delete"], "address": address, "type": resource_type}
            for address, resource_type in sorted(verifier.EXPECTED_DESTROY_RESOURCES)
        ]
        self.write_evidence("destroy-plan-summary.json", {
            "action_counts": {"create": 0, "delete": 32, "no-op": 0, "update": 0},
            "phase_b_resource_count": 0, "resource_count": 32, "resources": resources,
            "schema_version": "recova-phase-c-destroy-plan-summary/v1", "source_plan_sha256": HASH,
        })
        deadline = "2026-07-17T07:00:00Z"
        schedule_time = "2026-07-17T06:00:00Z"
        cleanup = f"onnuri-phase-c-cleanup@{PROJECT}.iam.gserviceaccount.com"
        job_name = f"projects/{PROJECT}/locations/asia-northeast3/jobs/onnuri-{RUN}-destroy"
        self.write_evidence("durable-destroy.json", {
            "cleanup_bundle_sha256": HASH, "destroy_before_deadline": True,
            "dry_run_build_id": "build-id", "dry_run_status": "SUCCESS",
            "job_name": job_name, "phase_c_deadline": deadline,
            "schedule": "0 6 17 7 *", "scheduleTime": schedule_time,
            "state": "ENABLED", "timeZone": "UTC",
        })
        condition = f"request.time < timestamp('{deadline}')"
        service_account = f"projects/{PROJECT}/serviceAccounts/{cleanup}"
        bundle_uri = (
            f"gs://{PROJECT}-onnuri-phase-c-tfstate/cleanup/{RUN}/"
            "phase-c-cleanup-bundle.tar.gz"
        )
        init_args = [
            "init", "-reconfigure", "-input=false",
            "-backend-config=phase-c-backend.hcl",
        ]
        destroy_args = [
            "destroy", "-auto-approve", "-input=false", "-lock-timeout=300s",
            "-var-file=phase-c.tfvars.json",
        ]
        plan_args = [
            "plan", "-destroy", "-input=false", "-lock=false",
            "-var-file=phase-c.tfvars.json",
        ]
        scheduled_request = verifier._expected_build_request(
            service_account, bundle_uri, HASH, destroy_args
        )
        dry_run_request = verifier._expected_build_request(
            service_account, bundle_uri, HASH, plan_args
        )
        scheduled_path = self.write_evidence("destroy-build-request.json", scheduled_request)
        dry_run_path = self.write_evidence("destroy-dry-run-request.json", dry_run_request)
        scheduled_sha = verifier.hashlib.sha256(scheduled_path.read_bytes()).hexdigest()
        dry_run_sha = verifier.hashlib.sha256(dry_run_path.read_bytes()).hexdigest()
        build_result = {
            "build_id": "build-id",
            "cleanup_bundle_sha256": HASH,
            "create_time": "2026-07-16T12:00:31Z",
            "finish_time": "2026-07-16T12:00:34Z",
            "init_args": init_args,
            "plan_args": plan_args,
            "request_sha256": dry_run_sha,
            "scheduled_request_sha256": scheduled_sha,
            "schema_version": "recova-phase-c-cleanup-build-result/v1",
            "service_account": service_account,
            "start_time": "2026-07-16T12:00:32Z",
            "status": "SUCCESS",
            "step_statuses": ["SUCCESS", "SUCCESS", "SUCCESS"],
        }
        result_path = self.write_evidence("destroy-build-result.json", build_result)
        result_sha = verifier.hashlib.sha256(result_path.read_bytes()).hexdigest()
        iam_principal_sha = verifier.hashlib.sha256(cleanup.encode()).hexdigest()
        self.write_evidence("destroy-execution.json", {
            "backend": {
                "bucket": f"{PROJECT}-onnuri-phase-c-tfstate",
                "prefix": f"onnuri-seoul-staging-phase-c-smoke/{RUN}",
            },
            "build_request_sha256": scheduled_sha,
            "build_service_account": service_account,
            "cleanup_bundle_sha256": HASH,
            "cleanup_bundle_uri": bundle_uri,
            "destroy_args": destroy_args,
            "dry_run_request_sha256": dry_run_sha,
            "dry_run_result_sha256": result_sha,
            "iam": {
                "condition_expression_sha256": verifier.hashlib.sha256(condition.encode()).hexdigest(),
                "condition_title": "phase-c-destroy-before-expiry",
                "principal_sha256": iam_principal_sha,
                "project_roles": [
                    "roles/cloudbuild.builds.editor", "roles/compute.admin",
                    "roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin",
                    "roles/logging.admin", "roles/logging.logWriter",
                    "roles/monitoring.admin", "roles/resourcemanager.projectIamAdmin",
                    "roles/secretmanager.admin",
                ],
                "service_account_act_as_principal_sha256": iam_principal_sha,
                "service_account_act_as_role": "roles/iam.serviceAccountUser",
                "storage_bucket": f"{PROJECT}-onnuri-phase-c-tfstate",
                "storage_role": "roles/storage.objectAdmin",
            },
            "init_args": init_args,
            "phase_c_deadline": deadline,
            "project_id": PROJECT,
            "run_id": RUN,
            "scheduler": {
                "attempt_deadline": "180s",
                "body_sha256": scheduled_sha,
                "http_method": "POST",
                "name": job_name,
                "oauth_service_account": cleanup,
                "schedule": "0 6 17 7 *",
                "schedule_time": schedule_time,
                "state": "ENABLED",
                "time_zone": "UTC",
                "uri": (
                    f"https://cloudbuild.googleapis.com/v1/projects/{PROJECT}/"
                    "locations/global/builds"
                ),
            },
            "schema_version": "recova-phase-c-destroy-execution/v1",
        })
        purposes = ["callback_hmac_key", "f12_endpoint_credential", "f12_mtls_certificate",
                    "facade_adapter_credential", "sip_password", "stock_local_api_credential", "tls_private_key"]
        bindings = [{"condition_expression_sha256": HASH, "condition_title": "numeric-version-before-phase-c-expiry",
                     "member_sha256": HASH, "numeric_version_only": True, "purpose": purpose,
                     "role_sha256": HASH, "secret_reference_sha256": HASH} for purpose in purposes]
        self.write_evidence("secret-references.json", {
            "bindings": bindings, "numeric_versions_only": True, "reference_count": 7,
            "secret_values_read": False,
        })
        phase_b = {
            "network": {"selfLink": NETWORK_LINK},
            "rules": [
                {"denied": [{"IPProtocol": "all"}], "direction": "INGRESS", "disabled": False,
                 "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"}},
                {"denied": [{"IPProtocol": "all"}], "direction": "EGRESS", "disabled": False,
                 "logConfig": {"enable": True, "metadata": "INCLUDE_ALL_METADATA"}},
            ],
            "subnet": {"ipCidrRange": "10.73.96.0/24", "privateIpGoogleAccess": True,
                       "selfLink": SUBNET_LINK, "logConfig": {"aggregationInterval": "INTERVAL_5_SEC",
                       "enable": True, "filterExpr": "true", "flowSampling": 1.0,
                       "metadata": "INCLUDE_ALL_METADATA"}},
        }
        self.write_evidence("phase-b-before.json", phase_b)
        self.write_evidence("phase-b-after.json", phase_b)

    def write_compute_receipt(self, payload: dict) -> tuple[str, str]:
        signed = verifier.canonical_json(payload) + b"\n"
        payload_sha = verifier.hashlib.sha256(signed).hexdigest()
        receipt = {"candidate_receipt_sha256": payload_sha,
                   "candidate_receipt_signature_base64": base64.b64encode(self.compute_private.sign(signed)).decode("ascii"),
                   "payload": payload}
        path = self.write_evidence("g009-compute-image-receipt.json", receipt)
        return payload_sha, verifier.hashlib.sha256(path.read_bytes()).hexdigest()

    def payload(self) -> dict:
        payload = {
            "contract_version": verifier.CONTRACT_VERSION, "signer_key_id": "g007-offline-authority",
            "issued_at": "2026-07-16T12:00:31Z", "expires_at": "2026-07-16T12:30:31Z",
            "observation_window": WINDOW, "counters": {"sip": 0, "rtp": 0, "register": 0, "call": 0},
            "product_status": "Waiting", "redaction_assertion": "redacted-digests-only", "destroyer_armed": True,
        }
        payload.update({field: verifier.hashlib.sha256((self.evidence / filename).read_bytes()).hexdigest()
                        for field, filename in verifier.DIGEST_FILES.items()})
        return payload

    def signed_receipt(self) -> Path:
        payload = self.payload()
        return self._write_root("receipt.json", {"payload": payload,
            "signature_b64": base64.b64encode(self.private.sign(verifier.canonical_json(payload))).decode("ascii")})

    def verify(self, now: str = NOW) -> str:
        return verifier.verify(str(self.signed_receipt()), str(self.path / "trusted.json"), str(self.evidence), now)

    def tamper(self, filename: str, mutate) -> None:
        value = self.read(filename)
        mutate(value)
        self.write_evidence(filename, value)


def test_valid_evidence_and_cli(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    expected = fixture.verify()
    result = subprocess.run([sys.executable, str(SCRIPT), "--receipt", str(fixture.signed_receipt()),
        "--trusted-key", str(tmp_path / "trusted.json"), "--evidence-dir", str(fixture.evidence), "--now", NOW],
        capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert result.stdout.strip() == expected


@pytest.mark.parametrize(("filename", "mutate", "message"), [
    ("tenant-scope.json", lambda x: x.update(binding="other"), "tenant binding"),
    ("instance-redacted.json", lambda x: x.update(status="STOPPED"), "not RUNNING"),
    ("application-state.json", lambda x: x.update(services=12), "application services"),
    ("flow-summary.json", lambda x: x.update(bytes_sent=1), "flow bytes_sent"),
    ("provider-zero-traffic.json", lambda x: x.update(register_events=1), "provider register_events"),
    ("effective-firewalls.json", lambda x: x["rules"][0].update(allowed=[{"IPProtocol": "tcp"}]), "not logged deny-all"),
    ("effective-firewalls.json", lambda x: x["rules"][0].update(sourceRanges=["10.0.0.0/8"]), "ranges are not blanket"),
    ("effective-firewalls.json", lambda x: x["rules"][4].update(destinationRanges_sha256="b" * 64), "range digests differ"),
    ("containment-stop.json", lambda x: x.update(observed=False), "not observed"),
    ("containment-stop.json", lambda x: x.update(principal_sha256=HASH), "dedicated service account"),
    ("destroy-plan-summary.json", lambda x: x["resources"][0].update(actions=["create"]), "not exactly delete"),
    ("durable-destroy.json", lambda x: x.update(state="DISABLED"), "scheduler"),
    ("durable-destroy.json", lambda x: x.update(schedule="0 0 * * *"), "cron"),
    ("destroy-execution.json", lambda x: x["iam"]["project_roles"].pop(), "IAM roles"),
    ("destroy-execution.json", lambda x: x["iam"].update(service_account_act_as_role="roles/viewer"), "actAs"),
    ("secret-references.json", lambda x: x["bindings"][0].update(numeric_version_only=False), "numeric secret"),
])
def test_resigned_semantic_tampering_is_rejected(tmp_path: Path, filename, mutate, message):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper(filename, mutate)
    with pytest.raises(verifier.EvidenceError, match=message):
        fixture.verify()


def test_rejects_rehashed_scheduled_request_semantic_tamper(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    request = fixture.read("destroy-build-request.json")
    request["steps"][2]["args"][0] = "plan"
    path = fixture.write_evidence("destroy-build-request.json", request)
    request_sha = verifier.hashlib.sha256(path.read_bytes()).hexdigest()
    fixture.tamper(
        "destroy-execution.json",
        lambda x: (
            x.update(build_request_sha256=request_sha),
            x["scheduler"].update(body_sha256=request_sha),
        ),
    )
    with pytest.raises(verifier.EvidenceError, match="scheduled build request semantics"):
        fixture.verify()


def test_rejects_rehashed_build_result_tamper(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    result = fixture.read("destroy-build-result.json")
    result["status"] = "FAILURE"
    path = fixture.write_evidence("destroy-build-result.json", result)
    result_sha = verifier.hashlib.sha256(path.read_bytes()).hexdigest()
    fixture.tamper(
        "destroy-execution.json",
        lambda x: x.update(dry_run_result_sha256=result_sha),
    )
    with pytest.raises(verifier.EvidenceError, match="dry-run result binding"):
        fixture.verify()


def test_rejects_instance_boot_source_mismatch(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper("instance-redacted.json", lambda x: x.update(boot_source_image_self_link="redacted-other-image"))
    with pytest.raises(verifier.EvidenceError, match="boot source image mismatch"):
        fixture.verify()


def test_rejects_application_waiting_mismatch(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper("application-state.json", lambda x: x.update(product_status="Running"))
    with pytest.raises(verifier.EvidenceError, match="product status is not Waiting"):
        fixture.verify()


def test_rejects_phase_b_difference(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper("phase-b-after.json", lambda x: x["subnet"].update(privateIpGoogleAccess=False))
    with pytest.raises(verifier.EvidenceError, match="before/after evidence differs"):
        fixture.verify()


def test_rejects_bool_as_integer_in_resigned_artifact(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper("application-state.json", lambda x: x.update(services=True))
    with pytest.raises(verifier.EvidenceError, match="application services"):
        fixture.verify()


def test_rejects_g009_cross_binding_with_recomputed_outer_hashes(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    fixture.tamper("image-redacted.json", lambda x: x.update(id="111"))
    with pytest.raises(verifier.EvidenceError, match="image id mismatch"):
        fixture.verify()


def test_rejects_invalid_g009_signature_with_recomputed_outer_hashes(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    compute = fixture.read("g009-compute-image-receipt.json")
    compute["candidate_receipt_signature_base64"] = base64.b64encode(b"x" * 64).decode("ascii")
    path = fixture.write_evidence("g009-compute-image-receipt.json", compute)
    receipt_sha = verifier.hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ("image-redacted.json", "facade-binding.json"):
        fixture.tamper(name, lambda x, receipt_sha=receipt_sha: x.update(compute_receipt_sha256=receipt_sha))
    with pytest.raises(verifier.EvidenceError, match="compute receipt signature"):
        fixture.verify()

@pytest.mark.parametrize(("issued", "expires", "message"), [
    ("2026-07-16T13:00:00Z", "2026-07-17T13:00:00Z", "outside G009"),
    ("2026-07-15T08:00:00Z", "2026-07-16T08:00:00Z", "outside G009"),
    ("2026-07-16T08:00:00Z", "2026-07-17T08:00:01Z", "timestamps are invalid"),
    ("2026-07-16T08:00:00Z", "2026-07-16T12:00:34Z", "outside G009"),
])
def test_rejects_future_expired_or_overlong_resigned_g009_receipt(tmp_path: Path, issued, expires, message):
    fixture = EvidenceFixture(tmp_path)
    compute = fixture.read("g009-compute-image-receipt.json")
    compute["payload"]["candidate_receipt_issued_at_utc"] = issued
    compute["payload"]["candidate_receipt_expires_at_utc"] = expires
    payload_sha, receipt_sha = fixture.write_compute_receipt(compute["payload"])
    for name in ("image-redacted.json", "facade-binding.json"):
        fixture.tamper(name, lambda x, receipt_sha=receipt_sha: x.update(compute_receipt_sha256=receipt_sha))
    fixture.tamper("instance-redacted.json", lambda x: x["metadata"].update(**{"g009-image-receipt-sha256": payload_sha}))
    with pytest.raises(verifier.EvidenceError, match=message):
        fixture.verify()


def test_canonical_json_newline_g009_contract_remains_supported(tmp_path: Path):
    fixture = EvidenceFixture(tmp_path)
    path = fixture.evidence / "g009-compute-image-receipt.json"
    path.write_bytes(path.read_bytes() + b"\n")
    receipt_sha = verifier.hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ("image-redacted.json", "facade-binding.json"):
        fixture.tamper(name, lambda x, receipt_sha=receipt_sha: x.update(compute_receipt_sha256=receipt_sha))
    assert fixture.verify()
