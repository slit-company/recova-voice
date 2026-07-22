#!/usr/bin/env python3
"""Hermetic source-policy audit for the ordered G008 Phase C contract.

This checker uses only the Python standard library and reads local source. It
must not invoke Terraform, a provider, a network endpoint, or a cloud API.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TF_FILES = tuple(sorted(ROOT.glob("*.tf")))
SOURCE = "\n".join(path.read_text(encoding="utf-8") for path in TF_FILES)

GATES = (
    "dependency_manifest_gate",
    "candidate_gate",
    "endpoint_identity_gate",
    "cost_gate",
    "live_window_gate",
    "sip_register_gate",
    "sip_ip_to_ip_gate",
    "rtp_gate",
    "outbound_call_gate",
    "inbound_call_gate",
)
G008_NULLABLE_INPUTS = (
    "g008_derivative_receipt",
    "g008_authority_binding",
    "g008_f12_contract",
    "g008_secret_version_resource_names",
)


def fail(message: str) -> None:
    raise AssertionError(message)


def require(source: str, snippet: str, message: str) -> None:
    if snippet not in source:
        fail(message)


def top_level_blocks(source: str, keyword: str) -> dict[str, str]:
    """Return named top-level HCL blocks using deterministic brace matching."""
    pattern = re.compile(rf'^\s*{re.escape(keyword)}\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{{', re.MULTILINE)
    blocks: dict[str, str] = {}
    for match in pattern.finditer(source):
        depth = 1
        cursor = match.end()
        quoted = False
        escaped = False
        while cursor < len(source) and depth:
            char = source[cursor]
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            cursor += 1
        if depth:
            fail(f"unterminated {keyword} block near byte {match.start()}")
        name = ".".join(part for part in match.groups() if part is not None)
        blocks[name] = source[match.start():cursor]
    return blocks


def audit() -> None:
    if not TF_FILES:
        fail("no Phase C Terraform source files found")

    forbidden_patterns = {
        "Terraform remote state": r"terraform_remote_state",
        "module call": r'^\s*module\s+"',
        "import block": r"^\s*import\s*\{",
        "moved block": r"^\s*moved\s*\{",
        "removed/destroy block": r"^\s*removed\s*\{",
        "provisioner": r'^\s*provisioner\s+"',
        "public access_config": r"^\s*access_config\s*\{",
        "Cloud NAT": r'resource\s+"google_compute_router_nat"',
        "Phase B network mutation": r'resource\s+"google_compute_(?:network|subnetwork)"',
        "Phase B-labelled resource": r'resource\s+"[^"]+"\s+"phase_b',
        "secret payload lookup": r"secret_data|secretmanager\.versions\.accessSecretVersion",
        "obsolete SIP proxy contract": r"\b(?:var|variable)\.?(?:\s*\")?sip_proxy_(?:cidr|udp_port)",
    }
    for label, pattern in forbidden_patterns.items():
        if re.search(pattern, SOURCE, re.MULTILINE):
            fail(f"forbidden {label} found")

    data_blocks = top_level_blocks(SOURCE, "data")
    approved_data_sources = {
        "external.phase_c_live_plan": "plan",
        "external.phase_c_live_apply": "apply",
    }
    data_declarations = re.findall(
        r'^\s*data\s+"([^"]+)"\s+"([^"]+)"\s*\{',
        SOURCE,
        re.MULTILINE,
    )
    if len(data_declarations) != len(approved_data_sources) or {
        ".".join(declaration) for declaration in data_declarations
    } != set(approved_data_sources):
        fail("only the two approved local external verifier data sources are permitted")
    for name, stage in approved_data_sources.items():
        block = data_blocks.get(name, "")
        if not re.search(
            r'^\s*program\s*=\s*\["python3", "\$\{path\.module\}/\.\./\.\./scripts/verify_phase_c_live_preflight\.py"\]\s*$',
            block,
            re.MULTILINE,
        ):
            fail(f"{name} does not use the fixed local trusted-keyset verifier")
        require(block, "count = local.phase_c_live_crypto_enabled ? 1 : 0", f"{name} bypasses the crypto enable gate")
        require(block, f'verification_stage     = "{stage}"', f"{name} does not fix the {stage} verification stage")

    variable_blocks = top_level_blocks(SOURCE, "variable")
    for gate in GATES:
        block = variable_blocks.get(gate, "")
        if not block:
            fail(f"missing traffic gate variable {gate}")
        if not re.search(r"^\s*default\s*=\s*false\s*$", block, re.MULTILINE):
            fail(f"traffic gate {gate} does not default false")

    signaling_cidr = variable_blocks.get("supplier_signaling_ipv4_cidr", "")
    signaling_port = variable_blocks.get("supplier_signaling_remote_udp_port", "")
    for name, block in (
        ("supplier_signaling_ipv4_cidr", signaling_cidr),
        ("supplier_signaling_remote_udp_port", signaling_port),
    ):
        if not re.search(r"^\s*default\s*=\s*null\s*$", block, re.MULTILINE):
            fail(f"{name} must default null")
        if not re.search(r"^\s*nullable\s*=\s*true\s*$", block, re.MULTILINE):
            fail(f"{name} must remain nullable")
    require(signaling_cidr, '/32$", var.supplier_signaling_ipv4_cidr', "supplier signaling host is not strict /32")
    require(signaling_cidr, "cidrhost(var.supplier_signaling_ipv4_cidr, 0)", "supplier signaling host is not canonical")
    require(signaling_cidr, '!startswith(var.supplier_signaling_ipv4_cidr, "0.")', "supplier signaling permits the unspecified network")
    require(signaling_cidr, '!startswith(var.supplier_signaling_ipv4_cidr, "127.")', "supplier signaling permits loopback")
    require(signaling_cidr, '!startswith(var.supplier_signaling_ipv4_cidr, "169.254.")', "supplier signaling permits link-local")
    require(signaling_port, "(var.supplier_signaling_remote_udp_port == null) == (var.supplier_signaling_ipv4_cidr == null)", "supplier signaling host and port nullability are not paired")
    require(signaling_port, "floor(var.supplier_signaling_remote_udp_port) == var.supplier_signaling_remote_udp_port", "supplier signaling port need not be an integer")
    require(signaling_port, "var.supplier_signaling_remote_udp_port >= 1 && var.supplier_signaling_remote_udp_port <= 65535", "supplier signaling port is not bounded")
    mode = variable_blocks.get("sip_connection_mode", "")
    require(mode, 'default     = "registration"', "legacy registration mode is not the default")
    require(mode, '["registration", "ip_to_ip"]', "SIP mode is not closed to registration and ip_to_ip")
    ip_gate = variable_blocks.get("sip_ip_to_ip_gate", "")
    require(ip_gate, "default     = false", "IP-to-IP live gate does not default false")
    require(ip_gate, "var.supplier_signaling_remote_udp_port == 5060", "IP-to-IP gate does not pin peer UDP/5060")
    activation = variable_blocks.get("activation_receipt", "")
    for field in ("source_external_ipv4", "peer_signaling_ipv4_cidr", "peer_signaling_udp_port", "owned_target_sha256"):
        require(activation, field, f"IP-to-IP activation omits {field}")
    require(activation, '["outbound_call", "inbound_call", "peer_detach"]', "IP-to-IP activation omits peer-detach sequence")
    require(SOURCE, 'owned_target_sha256 == var.g008_execution_trigger.target_sha256', "IP-to-IP owned target is not bound to the sealed target digest")
    require(SOURCE, 'source_external_ipv4 == var.supplier_endpoint_binding.customer_external_ipv4', "IP-to-IP source is not bound to the reserved external IPv4")
    require(SOURCE, 'peer_signaling_udp_port == 5060', "IP-to-IP peer signaling is not fixed to UDP/5060")
    require(SOURCE, 'cutoff_action                   = var.sip_connection_mode == "registration" ? "terminate_media_and_unregister" : "terminate_media_and_detach_peer"', "IP-to-IP containment does not detach the peer")

    candidate_port_variables = (
        ("candidate_local_rtp_port_min", None),
        ("candidate_local_rtp_port_max", "candidate_local_rtp_port_min"),
        ("candidate_local_rtcp_port_min", None),
        ("candidate_local_rtcp_port_max", "candidate_local_rtcp_port_min"),
    )
    for name, minimum_name in candidate_port_variables:
        block = variable_blocks.get(name, "")
        if not re.search(r"^\s*default\s*=\s*null\s*$", block, re.MULTILINE):
            fail(f"{name} must default null")
        if not re.search(r"^\s*nullable\s*=\s*true\s*$", block, re.MULTILINE):
            fail(f"{name} must remain nullable")

    baked_pool = ("40000", "40099")
    for name, expected in zip(candidate_port_variables, (*baked_pool, *baked_pool), strict=True):
        require(variable_blocks[name[0]], f"var.{name[0]} == {expected}", f"{name[0]} can diverge from the baked 40000-40099 runtime pool")
    host_policy = variable_blocks.get("host_policy_receipt", "")
    for field, expected in (
        ("candidate_local_rtp_port_min", "40000"),
        ("candidate_local_rtp_port_max", "40099"),
        ("candidate_local_rtcp_port_min", "40000"),
        ("candidate_local_rtcp_port_max", "40099"),
    ):
        require(host_policy, f"var.host_policy_receipt.{field} == {expected}", f"host-policy receipt can diverge from the baked runtime {field}")
    require(SOURCE, "baked_local_media_udp_port_min = 40000", "Terraform does not pin the baked local media pool start")
    require(SOURCE, "baked_local_media_udp_port_max = 40099", "Terraform does not pin the baked local media pool end")


    for name in G008_NULLABLE_INPUTS:
        block = variable_blocks.get(name, "")
        if not block:
            fail(f"missing G008 compatibility input {name}")
        if not re.search(r"^\s*default\s*=\s*null\s*$", block, re.MULTILINE):
            fail(f"{name} must default null for G007 compatibility")
        if not re.search(r"^\s*nullable\s*=\s*true\s*$", block, re.MULTILINE):
            fail(f"{name} must be nullable for G007 compatibility")
    require(variable_blocks["g008_derivative_receipt"], 'schema_version == "recova-g008-derivative-v3"', "G008 derivative validation is not v3-only")
    require(variable_blocks["g008_secret_version_resource_names"], "versions/[1-9][0-9]*", "G008 secret references are not numeric-version pinned")
    derivative = variable_blocks["g008_derivative_receipt"]
    require(derivative, "^sha256:[0-9a-f]{64}$", "G008 derivative images are not immutable digests")
    require(derivative, "candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256", "G008 derivative is not bound to the candidate manifest")
    authority = variable_blocks["g008_authority_binding"]
    if any(raw in authority.lower() for raw in ("phone", "username", "password", "provider_endpoint")):
        fail("G008 authority binding permits raw supplier identifiers")
    require(authority, "candidate_digest", "G008 authority binding omits the candidate digest")
    require(SOURCE, "candidate_digest == sha256(jsonencode({", "Authority candidate digest is not derived from the exact reviewed candidate")
    for field in ("review_payload_digest", "candidate_manifest_sha256", "runtime_image_digest", "candidate_receipt_sha256"):
        require(SOURCE, field, f"Authority candidate digest omits {field}")
    execution = variable_blocks["g008_execution_trigger"]
    for field in ("sip_username_sha256", "sip_password_sha256", "sip_realm_sha256", "target_sha256"):
        require(execution, field, f"Execution trigger omits exact content digest for {field}")
    require(SOURCE, "content_sha256 = {", "Signed preflight context omits execution content digests")
    require(SOURCE, "versions = {", "Signed preflight context omits execution versions")
    f12 = variable_blocks["g008_f12_contract"]
    require(f12, "\\.internal", "G008 F12 endpoints are not private-only")
    require(f12, 'dispatch_algorithm == "ES256"', "G008 dispatch signing is not fixed to ES256")
    require(f12, 'media_algorithm == "ES256"', "G008 media signing is not fixed to ES256")
    for endpoint_name, scheme in (
        ("recova_f1_mtls_endpoint_path", "https://"),
        ("recova_f2_https_endpoint_path", "https://"),
        ("recova_f3_wss_endpoint_path", "wss://"),
        ("recova_f4_https_endpoint_path", "https://"),
        ("recova_f5_https_endpoint_path", "https://"),
        ("recova_f12_mtls_endpoint_path", "https://"),
    ):
        endpoint = variable_blocks.get(endpoint_name, "")
        require(endpoint, f"^{scheme}", f"{endpoint_name} does not enforce its private scheme")
        require(endpoint, "\\.internal", f"{endpoint_name} permits a public endpoint")

    resource_blocks = top_level_blocks(SOURCE, "resource")
    firewall_blocks = {
        name: block for name, block in resource_blocks.items()
        if name.startswith("google_compute_firewall.")
    }
    for resource_name, count, range_line, gate in (
        ("google_compute_firewall.sip_ingress", "count = local.bound_supplier_endpoint == null ? 0 : 1", "source_ranges           = [local.bound_supplier_endpoint.signaling_ipv4_cidr]", "disabled  = !local.bounded_live_ready"),
        ("google_compute_firewall.sip_egress", "count = local.bound_supplier_endpoint == null ? 0 : 1", "destination_ranges      = [local.bound_supplier_endpoint.signaling_ipv4_cidr]", "disabled  = !local.bounded_live_ready"),
        ("google_compute_firewall.rtp_ingress", "count = local.bound_supplier_endpoint == null || local.bound_host_policy == null ? 0 : 1", "source_ranges           = local.supplier_rtp_cidrs", "disabled  = !local.bounded_live_ready"),
        ("google_compute_firewall.rtp_egress", "count = local.bound_supplier_endpoint == null || local.bound_host_policy == null ? 0 : 1", "destination_ranges      = local.supplier_rtp_cidrs", "disabled  = !local.bounded_live_ready"),
    ):
        block = firewall_blocks.get(resource_name, "")
        require(block, count, f"{resource_name} is not absent without exact verified input")
        require(block, range_line, f"{resource_name} bypasses its receipt-bound range")
        require(block, gate, f"{resource_name} bypasses ordered live readiness")
        require(block, 'protocol = "udp"', f"{resource_name} is not UDP-only")
    require(firewall_blocks["google_compute_firewall.sip_ingress"], "local.bound_supplier_endpoint.candidate_sip_listen_udp_port", "SIP ingress bypasses the candidate listen port")
    require(firewall_blocks["google_compute_firewall.sip_egress"], "local.bound_supplier_endpoint.signaling_remote_udp_port", "SIP egress bypasses the supplier remote port")
    require(SOURCE, "var.supplier_signaling_ipv4_cidr == var.supplier_rtp_evidence.signaling_ipv4_cidr", "SIP host is not exactly supplier-receipt-bound")
    require(SOURCE, "var.supplier_signaling_remote_udp_port == var.supplier_rtp_evidence.signaling_udp_port", "SIP port is not exactly supplier-receipt-bound")
    rtp_ingress = firewall_blocks["google_compute_firewall.rtp_ingress"]
    require(rtp_ingress, '"${local.baked_local_media_udp_port_min}-${local.baked_local_media_udp_port_max}"', "RTP ingress does not use the pinned baked local media pool")
    if "bound_host_policy.candidate_local" in rtp_ingress:
        fail("RTP ingress may not derive local ports from a signed host policy")
    runtime_config = (ROOT.parents[1] / "deploy/onnuri-jambonz-oss/freeswitch-conf/autoload_configs/sofia.conf.xml").read_text(encoding="utf-8")
    rtpengine_runtime = (ROOT.parents[1] / "deploy/onnuri-jambonz-oss/Dockerfile.rtpengine").read_text(encoding="utf-8")
    for source, start, end, label in (
        (runtime_config, '<param name="rtp-start-port" value="40000"/>', '<param name="rtp-end-port" value="40099"/>', "FreeSWITCH"),
        (rtpengine_runtime, "--port-min=40000", "--port-max=40099", "rtpengine"),
    ):
        require(source, start, f"{label} runtime does not pin local media start to 40000")
        require(source, end, f"{label} runtime does not pin local media end to 40099")
    for resource_name, direction_field in (
        ("google_compute_firewall.deny_all_ingress", 'source_ranges           = ["0.0.0.0/0"]'),
        ("google_compute_firewall.deny_all_egress", 'destination_ranges      = ["0.0.0.0/0"]'),
    ):
        block = firewall_blocks.get(resource_name, "")
        require(block, "priority  = 65534", f"{resource_name} is not the terminal-priority deny")
        require(block, "disabled  = false", f"{resource_name} is not permanently enabled")
        require(block, direction_field, f"{resource_name} does not cover the complete IPv4 range")
        require(block, 'protocol = "all"', f"{resource_name} does not deny every protocol")

    supplier = variable_blocks.get("supplier_rtp_evidence", "")
    for field in (
        "signaling_ipv4_cidr", "signaling_udp_port", "remote_ipv4_cidrs",
        "remote_rtp_udp_port_min", "remote_rtp_udp_port_max",
        "remote_rtcp_udp_port_min", "remote_rtcp_udp_port_max",
        "max_concurrent_calls", "calls_per_second", "canonical_receipt_sha256",
        "verification_receipt_sha256", "issued_at_utc", "expires_at_utc",
    ):
        require(supplier, field, f"supplier receipt is missing {field}")
    for obsolete_field in ("signature_base64", "signer_key_id", "verification_key_sha256"):
        if obsolete_field in supplier:
            fail(f"supplier receipt retains obsolete raw trust field {obsolete_field}")
    require(supplier, "can(regex(\"^[0-9a-f]{64}$\", var.supplier_rtp_evidence.canonical_receipt_sha256))", "supplier canonical receipt digest is not strict SHA-256")
    require(supplier, "can(regex(\"^[0-9a-f]{64}$\", var.supplier_rtp_evidence.verification_receipt_sha256))", "supplier verification receipt digest is not strict SHA-256")
    require(supplier, "length(var.supplier_rtp_evidence.remote_ipv4_cidrs) <= 8", "supplier receipt permits too many media CIDRs")
    require(supplier, 'can(regex("/(2[4-9]|3[0-2])$", cidr))', "supplier receipt permits broad media CIDRs")
    require(supplier, 'try(cidrhost(cidr, 0), "invalid") == try(split("/", cidr)[0], "")', "supplier receipt permits noncanonical media CIDRs")
    for prefix in ("remote_rtp", "remote_rtcp"):
        require(
            supplier,
            f"var.supplier_rtp_evidence.{prefix}_udp_port_max - var.supplier_rtp_evidence.{prefix}_udp_port_min + 1 <= 100",
            f"supplier receipt permits a broad {prefix} port pool",
        )
    require(supplier, "var.supplier_rtp_evidence.max_concurrent_calls == 1", "supplier concurrency is not exactly one")
    require(supplier, "var.supplier_rtp_evidence.calls_per_second == 1", "supplier rate is not exactly one per second")
    require(SOURCE, "supplier_rtp_evidence_valid", "supplier receipt currency is not required")

    instance = resource_blocks.get("google_compute_instance.candidate", "")
    require(instance, 'machine_type              = "n2-standard-2"', "candidate VM is not Local-SSD-capable")
    require(instance, 'desired_status            = local.g2_compute_ready ? "RUNNING" : "TERMINATED"', "candidate status does not follow the sole ordered compute gate")
    require(instance, "can_ip_forward            = false", "candidate VM permits IP forwarding")
    require(instance, "image  = var.g009_candidate_receipt.image_self_link", "candidate VM does not use the exact receipted image")
    metadata_gates = {
        "workload-dispatch-enabled": "local.bounded_live_ready",
        "sip-register-enabled": "local.bounded_live_ready",
        "media-enabled": "local.bounded_live_ready",
        "outbound-call-enabled": "local.bounded_live_ready",
        "inbound-call-enabled": "local.bounded_live_ready",
        "f12-origin-enabled": "local.bounded_live_ready",
        "f12-readiness-enabled": "local.bounded_live_ready",
        "f12-media-wss-enabled": "local.bounded_live_ready",
    }
    for key, gate in metadata_gates.items():
        require(instance, f'{key}', f"candidate metadata is missing {key}")
        if not re.search(rf'{re.escape(key)}\s*=\s*{re.escape(gate)}\s*\?\s*"TRUE"\s*:\s*"FALSE"', instance):
            fail(f"candidate metadata {key} does not exactly track {gate}")
    for key in ("source-download-enabled", "image-download-enabled"):
        if not re.search(rf'{re.escape(key)}\s*=\s*"FALSE"', instance):
            fail(f"candidate metadata {key} is not permanently false")

    require(SOURCE, "g2_compute_ready = local.bounded_live_ready", "compute readiness must remain disabled until complete bounded-live readiness")
    sip_ready = re.search(r"\bsip_ready\s*=\s*\((.*?)\n\s*\)", SOURCE, re.DOTALL)
    if sip_ready is None:
        fail("missing sip_ready expression")
    for predicate in (
        "var.sip_register_gate", "local.g2_boot_prerequisites_ready", "local.cost_ready",
        "local.time_ready", "local.supplier_signaling_ready", "local.g008_derivative_ready",
        "local.g008_authority_ready", "local.g008_f12_ready", "local.g008_secrets_ready",
    ):
        require(sip_ready.group(1), predicate, f"live SIP readiness omits {predicate}")
    for predicate in (
        'schema_version == "recova-g008-derivative-v3"',
        "candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256",
        "receipt_expires_at_utc, plantimestamp()) > 0",
        "origin_https_endpoint_path == var.recova_f12_mtls_endpoint_path",
        "length(toset(values(var.g008_authority_binding))) == 4",
        "g008_secrets_ready = nonsensitive(",
        "var.g008_secret_version_resource_names != null &&",
    ):
        require(SOURCE, predicate, f"live G008 readiness omits exact predicate {predicate}")

    require(SOURCE, "outbound_live_enabled = var.outbound_call_gate && local.rtp_ready", "outbound direction bypasses its distinct gate")
    require(SOURCE, "inbound_live_enabled  = var.inbound_call_gate && local.rtp_ready", "inbound direction bypasses its distinct gate")
    require(SOURCE, "var.outbound_call_gate &&\n    var.inbound_call_gate", "simultaneous call directions are not rejected")
    for ordering in (
        "(!local.sip_ready || local.g2_prerequisites_ready)",
        "(!local.rtp_ready || local.sip_ready)",
        "(!local.outbound_live_enabled || local.rtp_ready)",
        "(!local.inbound_live_enabled || local.rtp_ready)",
    ):
        require(SOURCE, ordering, f"ordered prerequisite assertion is missing: {ordering}")

    iam_runtime = resource_blocks.get("google_secret_manager_secret_iam_member.runtime", "")
    for deleted_resource in (
        "google_secret_manager_secret_iam_member.g008_runtime",
        "google_secret_manager_secret_iam_member.g008_execution",
        "google_secret_manager_secret_iam_member.g008_transaction_authority",
    ):
        if deleted_resource in resource_blocks:
            fail(f"externally provisioned G008 exact-version IAM remains Terraform-managed: {deleted_resource}")
    require(iam_runtime, "for_each = local.bounded_live_ready ? local.runtime_secret_keys : toset([])", "legacy secret IAM does not follow bounded-live readiness")
    require(iam_runtime, 'secret_id = split("/", local.bound_legacy_secret_versions[each.value])[3]', "legacy secret IAM is not per supplied secret")
    require(iam_runtime, "resource.name == '%s'", "legacy secret IAM lacks exact numeric-version resource binding")
    require(iam_runtime, "local.bound_legacy_secret_versions[each.value]", "legacy secret IAM does not bind the supplied version")
    require(iam_runtime, "member    = google_service_account.runtime.member", "legacy secret IAM is not bound to the runtime identity")
    for deadline in (
        "var.live_window_start_utc",
        "var.live_window_end_utc",
        "var.destroy_deadline_utc",
    ):
        require(iam_runtime, deadline, f"legacy secret IAM omits bounded condition {deadline}")

    token_minter = resource_blocks.get("google_service_account_iam_member.runtime_mints_transaction_token", "")
    require(token_minter, "count = local.bounded_live_ready ? 1 : 0", "transaction-token minter does not follow bounded-live readiness")
    require(token_minter, "member             = google_service_account.runtime.member", "transaction-token minter is not bound to the runtime identity")
    for deadline in (
        "var.live_window_start_utc",
        "var.live_window_end_utc",
        "var.destroy_deadline_utc",
    ):
        require(token_minter, deadline, f"transaction-token minter omits bounded condition {deadline}")

    require(SOURCE, "g008-exact-binding-receipt-sha256    = local.g008_bootstrap_manifest_binding_sha256", "redacted G008 exact-binding receipt metadata is absent")

    for snippet, message in (
        ('traffic_authority             = local.bounded_live_ready ? "separately-approved-live" : "disabled"', "traffic authority is not bounded-live ordered"),
        ('phase_b_mutation_authority    = "none"', "Phase B mutation authority is not denied"),
        ('phase_b_destroy_authority     = "none"', "Phase B destroy authority is not denied"),
        ("call_retry_budget               = 0", "automatic retries are not disabled"),
        ("total_call_attempt_budget       = 3", "call attempts are not bounded to one explicit contingency"),
        ("contingency_call_budget         = 1", "exactly one contingency is not bounded"),
        ("contingency_authority_required  = true", "contingency is not operator-authority triggered"),
        ("maximum_active_calls            = 1", "active attempts are not bounded to one"),
        ("maximum_media_seconds_per_call  = 60", "media is not bounded to 60 seconds"),
        ("automatic_application_retries = local.activation_contract.call_retry_budget", "containment bypasses the sealed retry budget"),
        ("maximum_attempts              = local.activation_contract.total_call_attempt_budget", "containment bypasses the sealed attempt budget"),
        ("maximum_active_attempts       = local.activation_contract.maximum_active_calls", "containment bypasses the sealed active-call budget"),
        ("maximum_media_seconds         = local.activation_contract.maximum_media_seconds_per_call", "containment bypasses the sealed media budget"),
        ("ttl_hours                     = 24", "TTL is not bounded to 24 hours"),
        ("cost_ceiling_krw              = 50000", "cost is not bounded to KRW 50,000"),
        ("restricted_google_api_reachability_validated = local.phase_b_private_google_access_ready", "private-Google-access authority is not bound to Phase B"),
    ):
        require(SOURCE, snippet, message)

    output_blocks = top_level_blocks(SOURCE, "output")
    network_output = output_blocks.get("network_policy_redacted", "")
    for field in ("sip_peer_is_supplier_receipt_bound", "sip_rules_present", "rtp_rules_present"):
        require(network_output, field, f"redacted network output is missing {field}")
    for name, block in output_blocks.items():
        if re.search(r"=\s*(?:nonsensitive\(\s*)?var\.(?:g008_)?secret_version_resource_names(?:\s*\))?\s*$", block, re.MULTILINE):
            fail(f"secret identifiers are exposed by output {name}")
        if any(identifier in block for identifier in (
            "supplier_signaling_ipv4_cidr",
            "supplier_endpoint_binding",
            "g008_f12_contract",
        )):
            fail(f"endpoint identifiers are exposed by output {name}")
        if not re.search(r"^\s*sensitive\s*=\s*false\s*$", block, re.MULTILINE):
            fail(f"redacted output {name} is not explicitly non-sensitive")
    require(SOURCE, "secret_values_read    = false", "redacted output does not deny secret reads")
    require(SOURCE, "identifiers_output    = false", "redacted output does not deny identifier exposure")
    require(SOURCE, 'destroy_execution             = "external-leader-required"', "output implies automatic destruction")


if __name__ == "__main__":
    try:
        audit()
    except AssertionError as exc:
        print(f"static policy failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"static policy passed: {len(TF_FILES)} Terraform files audited offline")
