locals {
  phase_name = "onnuri-seoul-staging-phase-c-smoke"
  run_slug   = substr(var.run_id, 0, 12)
  name_stem  = "onnuri-c-${local.run_slug}"

  baked_local_media_udp_port_min = 40000
  baked_local_media_udp_port_max = 40099

  labels = {
    application = "recova"
    environment = "staging"
    phase       = "c-smoke"
    region      = var.region
    run_id      = var.run_id
    managed_by  = "terraform"
  }

  immutable_names = {
    address                               = "${local.name_stem}-address"
    instance                              = "${local.name_stem}-vm"
    boot_disk                             = "${local.name_stem}-boot"
    runtime_service_account               = "${local.name_stem}-runtime"
    transaction_authority_service_account = "${local.name_stem}-txn-auth"
    logging_service_account               = "${local.name_stem}-logging"
    evidence_service_account              = "${local.name_stem}-evidence"
    boot_service_account                  = "${local.name_stem}-boot"
    watchdog_service_account              = "${local.name_stem}-watchdog"
    deny_all_ingress_firewall             = "${local.name_stem}-deny-in"
    deny_all_egress_firewall              = "${local.name_stem}-deny-out"
    sip_ingress_firewall                  = "${local.name_stem}-sip-in"
    sip_egress_firewall                   = "${local.name_stem}-sip-out"
    rtp_ingress_firewall                  = "${local.name_stem}-rtp-in"
    rtp_egress_firewall                   = "${local.name_stem}-rtp-out"
    recova_ingress_firewall               = "${local.name_stem}-recova-in"
    recova_egress_firewall                = "${local.name_stem}-recova-out"
    recova_control_egress_firewall        = "${local.name_stem}-f2-f12-out"
    recova_media_egress_firewall          = "${local.name_stem}-wss-out"
    google_out_firewall                   = "${local.name_stem}-google-out"
  }
  service_account_emails = {
    boot                  = "${local.immutable_names.boot_service_account}@${var.project_id}.iam.gserviceaccount.com"
    runtime               = "${local.immutable_names.runtime_service_account}@${var.project_id}.iam.gserviceaccount.com"
    transaction_authority = "${local.immutable_names.transaction_authority_service_account}@${var.project_id}.iam.gserviceaccount.com"
    watchdog              = "${local.immutable_names.watchdog_service_account}@${var.project_id}.iam.gserviceaccount.com"
  }
  bound_supplier_endpoint  = var.supplier_endpoint_binding
  bound_host_policy        = var.host_policy_receipt
  bound_recova_destination = var.recova_destination_receipt
  bound_recova_f1_cidrs    = sort(tolist(var.recova_f1_source_cidrs))
  bound_legacy_secret_versions = {
    for key in sort(tolist(keys(var.secret_version_resource_names))) :
    key => var.secret_version_resource_names[key]
  }
  bound_g008_secret_versions = var.g008_secret_version_resource_names == null ? null : {
    for key in sort(tolist(keys(var.g008_secret_version_resource_names))) :
    key => var.g008_secret_version_resource_names[key]
  }

  phase_b_manifest_time_valid = (
    timecmp(var.phase_b_dependency.expires_at_utc, var.phase_b_dependency.issued_at_utc) > 0 &&
    timecmp(var.phase_b_dependency.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.phase_b_dependency.expires_at_utc, plantimestamp()) > 0
  )
  destroy_deadline_valid = var.destroy_deadline_utc == timeadd(var.apply_timestamp_utc, "24h")

  live_window_supplied                 = var.live_window_start_utc != null && var.live_window_end_utc != null
  live_window_max_duration             = "2h"
  live_window_minimum_remaining_runway = "15m"
  live_window_valid = local.live_window_supplied ? (
    timecmp(var.live_window_start_utc, var.apply_timestamp_utc) >= 0 &&
    timecmp(var.live_window_end_utc, var.live_window_start_utc) > 0 &&
    timecmp(var.live_window_end_utc, timeadd(var.live_window_start_utc, local.live_window_max_duration)) <= 0 &&
    timecmp(var.live_window_end_utc, var.destroy_deadline_utc) <= 0
  ) : false
  live_window_active = local.live_window_valid ? (
    timecmp(plantimestamp(), var.live_window_start_utc) >= 0 &&
    timecmp(plantimestamp(), timeadd(var.live_window_end_utc, "-${local.live_window_minimum_remaining_runway}")) <= 0 &&
    timecmp(plantimestamp(), var.destroy_deadline_utc) < 0
  ) : false

  cost_evidence_valid = var.cost_evidence != null ? (
    var.cost_evidence.estimated_total_krw <= var.cost_ceiling_krw &&
    var.cost_evidence.observed_total_krw <= var.cost_ceiling_krw &&
    timecmp(var.cost_evidence.recorded_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.cost_evidence.expires_at_utc, var.cost_evidence.recorded_at_utc) > 0 &&
    timecmp(var.cost_evidence.expires_at_utc, plantimestamp()) > 0 &&
    timecmp(var.cost_evidence.expires_at_utc, var.destroy_deadline_utc) <= 0
  ) : false
  cost_evidence_watchdog_valid_until_utc = var.cost_evidence != null ? var.cost_evidence.expires_at_utc : var.destroy_deadline_utc
  cost_evidence_fresh = var.cost_evidence != null ? (
    timecmp(var.cost_evidence.expires_at_utc, plantimestamp()) > 0
  ) : false

  candidate_manifest_valid = (
    timecmp(var.candidate_manifest.approved_at_utc, var.apply_timestamp_utc) <= 0 &&
    var.candidate_manifest.image_digest != var.candidate_manifest.facade_image_digest &&
    timecmp(var.candidate_manifest.approved_at_utc, plantimestamp()) <= 0
  )
  g009_candidate_receipt_current = (
    timecmp(var.g009_candidate_receipt.candidate_receipt_expires_at_utc, var.g009_candidate_receipt.candidate_receipt_issued_at_utc) > 0 &&
    timecmp(var.g009_candidate_receipt.candidate_receipt_issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.g009_candidate_receipt.candidate_receipt_expires_at_utc, plantimestamp()) > 0
  )
  g009_candidate_receipt_valid = (
    local.g009_candidate_receipt_current &&
    var.g009_candidate_receipt.source_sha256 == var.candidate_manifest.source_sha256 &&
    var.g009_candidate_receipt.runtime_image_digest == var.candidate_manifest.image_digest &&
    var.g009_candidate_receipt.facade_image_digest == var.candidate_manifest.facade_image_digest &&
    var.g009_candidate_receipt.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256 &&
    var.g009_candidate_receipt.image_self_link == "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/images/${split("/", var.g009_candidate_receipt.image_self_link)[length(split("/", var.g009_candidate_receipt.image_self_link)) - 1]}"
  )

  supplier_rtp_evidence_valid = var.supplier_rtp_evidence != null ? (
    timecmp(var.supplier_rtp_evidence.expires_at_utc, var.supplier_rtp_evidence.issued_at_utc) > 0 &&
    timecmp(var.supplier_rtp_evidence.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.supplier_rtp_evidence.expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.supplier_rtp_evidence.issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.supplier_rtp_evidence.expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false

  dependency_ready = var.dependency_manifest_gate && local.phase_b_manifest_time_valid
  candidate_ready  = var.candidate_gate && local.candidate_manifest_valid
  endpoints_ready = var.endpoint_identity_gate && length(var.recova_f1_source_cidrs) > 0 && alltrue([
    for endpoint in [
      var.recova_f1_mtls_endpoint_path,
      var.recova_f2_https_endpoint_path,
      var.recova_f3_wss_endpoint_path,
      var.recova_f4_https_endpoint_path,
      var.recova_f5_https_endpoint_path,
      var.recova_f12_mtls_endpoint_path,
    ] : length(endpoint) > 0
  ])
  phase_c_backend_receipt_valid = (
    timecmp(var.phase_c_backend_receipt.recorded_at_utc, var.apply_timestamp_utc) <= 0 &&
    timecmp(var.phase_c_backend_receipt.recorded_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.phase_c_backend_receipt.recorded_at_utc, var.destroy_deadline_utc) <= 0
  )
  g2_prerequisites_ready      = local.dependency_ready && local.candidate_ready && local.endpoints_ready && local.g009_candidate_receipt_valid && local.phase_c_backend_receipt_valid
  g2_boot_prerequisites_ready = local.g2_prerequisites_ready && local.phase_b_private_google_access_ready && local.destroy_deadline_valid && !local.destroy_due
  g2_boot_requested           = var.dependency_manifest_gate || var.candidate_gate || var.endpoint_identity_gate
  g2_live_gates_disabled      = !var.external_ip_reservation_gate && !var.network_path_arm_gate && !var.control_readiness_gate && !var.cost_gate && !var.live_window_gate && !var.sip_register_gate && !var.sip_ip_to_ip_gate && !var.rtp_gate && !var.outbound_call_gate && !var.inbound_call_gate
  g2_disabled_boot_ready = (
    local.g2_boot_requested &&
    local.g2_boot_prerequisites_ready &&
    local.g2_live_gates_disabled
  )
  g2_disabled_boot_authority_valid = (
    (!local.g2_boot_requested || local.g2_disabled_boot_ready) &&
    local.g2_live_gates_disabled
  )

  cost_ready = var.cost_gate && local.cost_evidence_valid
  time_ready = var.live_window_gate && local.destroy_deadline_valid && local.live_window_active
  g008_derivative_ready = var.g008_derivative_receipt != null ? (
    var.g008_derivative_receipt.schema_version == "recova-g008-derivative-v3" &&
    var.g008_derivative_receipt.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256 &&
    timecmp(var.g008_derivative_receipt.receipt_issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.g008_derivative_receipt.receipt_expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.g008_derivative_receipt.receipt_issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.g008_derivative_receipt.receipt_expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  g008_activation_context_digest = try(sha256(jsonencode({
    schema_version                 = "recova-g008-live-activation-context-v1"
    secret_versions                = var.g008_secret_version_resource_names
    activation_nonce_sha256        = sha256(var.activation_receipt.activation_nonce)
    activation_receipt_sha256      = var.activation_receipt.canonical_receipt_sha256
    outbound_barrier_sha256        = var.activation_receipt.outbound_barrier_receipt_sha256
    inbound_barrier_sha256         = var.activation_receipt.inbound_barrier_receipt_sha256
    stage_sequence                 = var.activation_receipt.stage_sequence
    register_attempt_budget        = var.activation_receipt.register_attempt_budget
    unregister_attempt_budget      = var.activation_receipt.unregister_attempt_budget
    total_call_attempt_budget      = var.activation_receipt.total_call_attempt_budget
    retry_count                    = var.activation_receipt.retry_count
    concurrency_count              = var.activation_receipt.concurrency_count
    call_deadline_seconds          = var.activation_receipt.call_deadline_seconds
    contingency_call_budget        = var.activation_receipt.contingency_call_budget
    contingency_authority_required = var.activation_receipt.contingency_authority_required
  })), null)
  g008_authority_ready = var.g008_authority_binding != null ? (
    length(toset(values(var.g008_authority_binding))) == 4 &&
    var.g008_authority_binding.envelope_digest == local.g008_activation_context_digest &&
    var.g008_authority_binding.candidate_digest == sha256(jsonencode({
      review_payload_digest     = var.candidate_manifest.review_payload_digest
      candidate_manifest_sha256 = var.candidate_manifest.manifest_sha256
      runtime_image_digest      = var.g009_candidate_receipt.runtime_image_digest
      candidate_receipt_sha256  = var.g009_candidate_receipt.candidate_receipt_sha256
    }))
  ) : false
  g008_f12_ready = var.g008_f12_contract != null ? (
    var.g008_f12_contract.origin_https_endpoint_path == var.recova_f12_mtls_endpoint_path &&
    timecmp(var.g008_f12_contract.contract_receipt_issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.g008_f12_contract.contract_receipt_expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.g008_f12_contract.contract_receipt_issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.g008_f12_contract.contract_receipt_expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  g008_secrets_ready = nonsensitive(
    var.g008_secret_version_resource_names != null &&
    try(toset(keys(var.g008_secret_version_resource_names)) == local.g008_all_secret_keys, false) &&
    try(length(toset(values(var.g008_secret_version_resource_names))) == length(local.g008_all_secret_keys), false) &&
    try(alltrue([
      for reference in values(var.g008_secret_version_resource_names) :
      can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", reference))
    ]), false)
  )
  prearm_inventory_current = var.prearm_inventory_receipt != null ? (
    timecmp(var.prearm_inventory_receipt.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.prearm_inventory_receipt.expires_at_utc, plantimestamp()) > 0
  ) : false
  supplier_endpoint_current = var.supplier_endpoint_binding != null ? (
    timecmp(var.supplier_endpoint_binding.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.supplier_endpoint_binding.expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.supplier_endpoint_binding.issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.supplier_endpoint_binding.expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  host_policy_current = var.host_policy_receipt != null ? (
    timecmp(var.host_policy_receipt.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.host_policy_receipt.expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.host_policy_receipt.issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.host_policy_receipt.expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  recova_destination_current = var.recova_destination_receipt != null ? (
    timecmp(var.recova_destination_receipt.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.recova_destination_receipt.expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.recova_destination_receipt.issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.recova_destination_receipt.expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  activation_receipt_current = var.activation_receipt != null ? (
    timecmp(var.activation_receipt.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.activation_receipt.expires_at_utc, plantimestamp()) > 0 &&
    (local.live_window_supplied ? (
      timecmp(var.activation_receipt.issued_at_utc, var.live_window_start_utc) <= 0 &&
      timecmp(var.activation_receipt.expires_at_utc, var.live_window_end_utc) >= 0
    ) : true)
  ) : false
  g008_external_iam_receipt_fresh = var.g008_external_iam_provisioning_receipt != null && local.live_window_supplied ? (
    timecmp(var.g008_external_iam_provisioning_receipt.issued_at_utc, plantimestamp()) <= 0 &&
    timecmp(var.g008_external_iam_provisioning_receipt.expires_at_utc, plantimestamp()) > 0 &&
    timecmp(var.g008_external_iam_provisioning_receipt.issued_at_utc, var.live_window_start_utc) <= 0 &&
    timecmp(var.g008_external_iam_provisioning_receipt.expires_at_utc, var.live_window_end_utc) >= 0
  ) : false
  g008_external_iam_receipt_context_valid = var.g008_external_iam_provisioning_receipt != null ? (
    var.g008_external_iam_provisioning_receipt.bootstrap_manifest_binding_sha256 == local.g008_bootstrap_manifest_binding_sha256 &&
    var.g008_external_iam_provisioning_receipt.runtime_service_account_email == local.service_account_emails.runtime &&
    var.g008_external_iam_provisioning_receipt.transaction_service_account_email == local.service_account_emails.transaction_authority &&
    var.g008_external_iam_provisioning_receipt.live_window_start_utc == var.live_window_start_utc &&
    var.g008_external_iam_provisioning_receipt.live_window_end_utc == var.live_window_end_utc &&
    var.g008_external_iam_provisioning_receipt.destruction_deadline_utc == var.destroy_deadline_utc &&
    var.g008_external_iam_provisioning_receipt.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256 &&
    var.g008_external_iam_provisioning_receipt.review_payload_digest == var.candidate_manifest.review_payload_digest &&
    var.g008_external_iam_provisioning_receipt.run_id == var.run_id &&
    var.g008_external_iam_trusted_issuer_key_id != null &&
    var.g008_external_iam_trusted_issuer_key_fingerprint_sha256 != null &&
    var.g008_external_iam_provisioning_receipt.issuer_key_id == var.g008_external_iam_trusted_issuer_key_id &&
    var.g008_external_iam_provisioning_receipt.issuer_key_fingerprint_sha256 == var.g008_external_iam_trusted_issuer_key_fingerprint_sha256 &&
    try(var.g008_external_iam_provisioning_receipt.activation_nonce_sha256 == sha256(var.activation_receipt.activation_nonce), false) &&
    try(var.g008_external_iam_provisioning_receipt.activation_receipt_sha256 == var.activation_receipt.canonical_receipt_sha256, false)
  ) : false
  g008_external_iam_canonical_digest_valid = var.g008_external_iam_provisioning_receipt != null ? (
    var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256 == sha256(jsonencode(local.g008_external_iam_signed_claims))
  ) : false
  g008_external_iam_verification_digest_valid = (
    local.phase_c_live_plan_verified &&
    try(
      var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256 ==
      data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256,
      false,
    )
  )
  g008_external_iam_receipt_ready = (
    local.g008_external_iam_receipt_fresh &&
    local.g008_external_iam_receipt_context_valid &&
    local.phase_c_live_plan_verified &&
    local.g008_external_iam_canonical_digest_valid &&
    local.g008_external_iam_verification_digest_valid
  )
  supplier_signaling_bound = var.supplier_rtp_evidence != null && var.supplier_endpoint_binding != null && var.supplier_signaling_ipv4_cidr != null && var.supplier_signaling_remote_udp_port != null ? (
    var.supplier_signaling_ipv4_cidr == var.supplier_rtp_evidence.signaling_ipv4_cidr &&
    var.supplier_signaling_remote_udp_port == var.supplier_rtp_evidence.signaling_udp_port &&
    var.supplier_endpoint_binding.signaling_ipv4_cidr == var.supplier_rtp_evidence.signaling_ipv4_cidr &&
    var.supplier_endpoint_binding.signaling_remote_udp_port == var.supplier_rtp_evidence.signaling_udp_port &&
    var.supplier_endpoint_binding.media_ipv4_cidrs == var.supplier_rtp_evidence.remote_ipv4_cidrs &&
    var.supplier_endpoint_binding.remote_rtp_udp_port_min == var.supplier_rtp_evidence.remote_rtp_udp_port_min &&
    var.supplier_endpoint_binding.remote_rtp_udp_port_max == var.supplier_rtp_evidence.remote_rtp_udp_port_max &&
    var.supplier_endpoint_binding.remote_rtcp_udp_port_min == var.supplier_rtp_evidence.remote_rtcp_udp_port_min &&
    var.supplier_endpoint_binding.remote_rtcp_udp_port_max == var.supplier_rtp_evidence.remote_rtcp_udp_port_max &&
    var.supplier_rtp_evidence.max_concurrent_calls == 1 &&
    var.supplier_rtp_evidence.calls_per_second == 1
  ) : false
  supplier_signaling_ready       = local.supplier_signaling_bound && local.supplier_rtp_evidence_valid
  sip_connection_authority_ready = var.sip_connection_mode == "registration" ? var.sip_register_gate : var.sip_ip_to_ip_gate
  ip_to_ip_binding_ready = var.sip_connection_mode != "ip_to_ip" ? true : (
    var.sip_ip_to_ip_gate &&
    !var.sip_register_gate &&
    local.supplier_signaling_bound &&
    var.supplier_signaling_remote_udp_port == 5060 &&
    try(var.activation_receipt.sip_connection_mode == "ip_to_ip", false) &&
    try(var.activation_receipt.source_external_ipv4 == var.supplier_endpoint_binding.customer_external_ipv4, false) &&
    try(var.activation_receipt.peer_signaling_ipv4_cidr == var.supplier_endpoint_binding.signaling_ipv4_cidr, false) &&
    try(var.activation_receipt.peer_signaling_udp_port == 5060, false) &&
    try(var.activation_receipt.owned_target_sha256 == var.g008_execution_trigger.target_sha256, false)
  )
  phase_c_live_plan_verified = (
    local.phase_c_live_crypto_enabled &&
    try(data.external.phase_c_live_plan[0].result.verified == "true", false)
  )
  external_ip_reserved = var.external_ip_reservation_gate && local.prearm_inventory_current
  network_path_ready = (
    local.external_ip_reserved &&
    local.phase_c_live_plan_verified &&
    local.supplier_endpoint_current &&
    local.host_policy_current &&
    local.recova_destination_current &&
    local.activation_receipt_current &&
    local.supplier_signaling_ready
  )
  network_path_armed = var.network_path_arm_gate && local.network_path_ready
  control_ready = (
    var.control_readiness_gate &&
    local.network_path_armed &&
    local.recova_destination_current &&
    local.g008_f12_ready
  )
  media_path_ready = (
    local.control_ready &&
    var.rtp_gate &&
    local.recova_destination_current
  )

  sip_ready = (
    local.sip_connection_authority_ready &&
    local.network_path_armed &&
    local.control_ready &&
    local.g2_boot_prerequisites_ready &&
    local.cost_ready &&
    local.time_ready &&
    local.supplier_signaling_ready &&
    local.ip_to_ip_binding_ready &&
    local.g008_derivative_ready &&
    local.g008_authority_ready &&
    local.g008_f12_ready &&
    local.g008_secrets_ready &&
    local.g008_external_iam_receipt_ready
  )
  rtp_ready = (
    var.rtp_gate &&
    local.sip_ready &&
    local.media_path_ready &&
    local.supplier_rtp_evidence_valid
  )

  outbound_live_enabled = var.outbound_call_gate && local.rtp_ready
  inbound_live_enabled  = var.inbound_call_gate && local.rtp_ready
  any_live_enabled      = local.outbound_live_enabled || local.inbound_live_enabled
  exact_execution_contract_ready = nonsensitive(var.activation_receipt != null && var.g008_execution_trigger != null ? (
    var.activation_receipt.sip_connection_mode == var.sip_connection_mode &&
    (
      var.sip_connection_mode == "registration" ? (
        var.activation_receipt.stage_sequence == tolist(["register", "outbound_call", "inbound_call", "unregister"]) &&
        var.activation_receipt.register_attempt_budget == 1 &&
        var.activation_receipt.unregister_attempt_budget == 1
        ) : (
        var.activation_receipt.stage_sequence == tolist(["outbound_call", "inbound_call", "peer_detach"]) &&
        var.activation_receipt.register_attempt_budget == 0 &&
        var.activation_receipt.unregister_attempt_budget == 0 &&
        local.ip_to_ip_binding_ready
      )
    ) &&
    var.activation_receipt.execution_seal_count == 1 &&
    var.activation_receipt.total_call_attempt_budget == 3 &&
    var.activation_receipt.retry_count == 0 &&
    var.activation_receipt.concurrency_count == 1 &&
    var.activation_receipt.call_deadline_seconds == 60 &&
    var.activation_receipt.contingency_call_budget == 1 &&
    var.activation_receipt.contingency_authority_required == true &&
    can(regex("^[0-9a-f]{64}$", var.activation_receipt.outbound_barrier_receipt_sha256)) &&
    can(regex("^[0-9a-f]{64}$", var.activation_receipt.inbound_barrier_receipt_sha256)) &&
    var.activation_receipt.outbound_barrier_receipt_sha256 != var.activation_receipt.inbound_barrier_receipt_sha256 &&
    try(var.g008_execution_trigger.execution_nonce_sha256 == sha256(var.activation_receipt.activation_nonce), false) &&
    try(var.g008_execution_trigger.activation_receipt_sha256 == var.activation_receipt.canonical_receipt_sha256, false)
  ) : false)
  activation_contract = {
    schema_version                  = "recova-g008-runtime-activation-v1"
    activation_id                   = sha256(join(":", [var.run_id, var.candidate_manifest.manifest_sha256, coalesce(var.live_window_start_utc, "disabled"), coalesce(var.live_window_end_utc, "disabled")]))
    activation_nonce_digest         = try(sha256(var.activation_receipt.activation_nonce), "")
    supplier_binding_sha256         = try(var.supplier_endpoint_binding.canonical_receipt_sha256, "")
    host_policy_sha256              = try(var.host_policy_receipt.policy_sha256, "")
    recova_destination_sha256       = try(var.recova_destination_receipt.canonical_receipt_sha256, "")
    external_address_binding_sha256 = try(sha256(var.supplier_endpoint_binding.customer_external_ipv4), "")
    sip_connection_mode             = try(var.activation_receipt.sip_connection_mode, "registration")
    owned_target_sha256             = try(var.activation_receipt.owned_target_sha256, "")
    peer_signaling_ipv4_cidr        = try(var.activation_receipt.peer_signaling_ipv4_cidr, "")
    peer_signaling_udp_port         = try(var.activation_receipt.peer_signaling_udp_port, 0)
    stage_sequence                  = try(var.activation_receipt.stage_sequence, [])
    outbound_barrier_receipt_sha256 = try(var.activation_receipt.outbound_barrier_receipt_sha256, "")
    inbound_barrier_receipt_sha256  = try(var.activation_receipt.inbound_barrier_receipt_sha256, "")
    execution_seal_count            = try(var.activation_receipt.execution_seal_count, 0)
    register_attempt_budget         = var.sip_connection_mode == "registration" ? 1 : 0
    unregister_attempt_budget       = var.sip_connection_mode == "registration" ? 1 : 0
    total_call_attempt_budget       = 3
    call_retry_budget               = 0
    contingency_call_budget         = 1
    contingency_authority_required  = true
    maximum_active_calls            = 1
    maximum_media_seconds_per_call  = 60
    cutoff_action                   = var.sip_connection_mode == "registration" ? "terminate_media_and_unregister" : "terminate_media_and_detach_peer"
  }
  cutoff_required = local.control_phase_ready || local.bounded_live_ready
  watchdog_cutoff_utc = local.cutoff_required ? sort([
    local.cost_evidence_watchdog_valid_until_utc,
    var.live_window_end_utc,
  ])[0] : var.destroy_deadline_utc
  watchdog_traffic_firewall_names = local.network_path_armed ? [
    local.immutable_names.recova_ingress_firewall,
    local.immutable_names.sip_ingress_firewall,
    local.immutable_names.sip_egress_firewall,
    local.immutable_names.rtp_ingress_firewall,
    local.immutable_names.rtp_egress_firewall,
    local.immutable_names.recova_control_egress_firewall,
    local.immutable_names.recova_media_egress_firewall,
    local.immutable_names.google_out_firewall,
  ] : []
  bounded_live_ready = nonsensitive((
    local.sip_connection_authority_ready &&
    var.rtp_gate &&
    var.outbound_call_gate &&
    var.inbound_call_gate &&
    local.sip_ready &&
    local.rtp_ready &&
    local.outbound_live_enabled &&
    local.inbound_live_enabled &&
    local.exact_execution_contract_ready &&
    local.g008_external_iam_receipt_ready
  ))
  control_phase_ready = nonsensitive((
    local.control_ready &&
    !var.sip_register_gate &&
    !var.sip_ip_to_ip_gate &&
    !var.rtp_gate &&
    !var.outbound_call_gate &&
    !var.inbound_call_gate &&
    local.g2_boot_prerequisites_ready &&
    local.cost_ready &&
    local.time_ready &&
    local.g008_derivative_ready &&
    local.g008_authority_ready &&
    local.g008_secrets_ready
  ))
  reservation_ready = (
    local.external_ip_reserved &&
    !var.network_path_arm_gate &&
    !var.control_readiness_gate &&
    !var.cost_gate &&
    !var.live_window_gate &&
    !var.sip_register_gate &&
    !var.sip_ip_to_ip_gate &&
    !var.rtp_gate &&
    !var.outbound_call_gate &&
    !var.inbound_call_gate
  )
  armed_off_ready = (
    local.network_path_armed &&
    !var.control_readiness_gate &&
    !var.sip_register_gate &&
    !var.sip_ip_to_ip_gate &&
    !var.rtp_gate &&
    !var.outbound_call_gate &&
    !var.inbound_call_gate
  )
  disabled_ready = (
    (!local.g2_boot_requested && local.g2_live_gates_disabled) ||
    local.g2_disabled_boot_ready
  )
  disabled_zero_traffic_ready = (
    local.disabled_ready &&
    !local.network_path_armed &&
    !local.control_phase_ready &&
    !local.bounded_live_ready
  )
  deployment_ready = local.disabled_zero_traffic_ready || local.reservation_ready || local.armed_off_ready || local.control_phase_ready || local.bounded_live_ready
  # RUNNING is live authority: no private boot/control intermediate may start the
  # workload before the complete signed four-stage execution seal is present.
  g2_compute_ready = local.bounded_live_ready

  default_disabled = !local.sip_ready && !local.rtp_ready && !local.any_live_enabled
  kill_switch      = !local.bounded_live_ready || !local.live_window_active || !local.cost_evidence_valid || !local.cost_evidence_fresh
  destroy_due      = timecmp(plantimestamp(), var.destroy_deadline_utc) >= 0

  hard_preconditions = {
    phase_b_manifest_is_current  = local.phase_b_manifest_time_valid
    destroy_deadline_is_24h      = local.destroy_deadline_valid
    candidate_is_approved        = local.candidate_manifest_valid
    endpoints_are_approved       = local.endpoints_ready
    cost_is_below_ceiling        = !var.cost_gate || local.cost_evidence_valid
    live_window_is_active        = !var.live_window_gate || local.live_window_active
    supplier_receipt_is_current  = !local.sip_connection_authority_ready || local.supplier_rtp_evidence_valid
    sip_matches_supplier_receipt = !local.sip_connection_authority_ready || (local.supplier_signaling_ready && local.ip_to_ip_binding_ready)
    # Compatibility key consumed by the existing redacted output; it now means
    # absent-by-default or exactly matched to the signed supplier receipt.
    sip_is_exact_host_udp_5060 = (
      (var.supplier_signaling_ipv4_cidr == null && var.supplier_signaling_remote_udp_port == null && var.candidate_sip_listen_udp_port == null) ||
      local.supplier_signaling_bound
    )
    local_rtp_pool_is_tiny = (
      (var.candidate_local_rtp_port_min == null && var.candidate_local_rtp_port_max == null && var.candidate_local_rtcp_port_min == null && var.candidate_local_rtcp_port_max == null) ||
      (
        var.candidate_local_rtp_port_min == local.baked_local_media_udp_port_min &&
        var.candidate_local_rtp_port_max == local.baked_local_media_udp_port_max &&
        var.candidate_local_rtcp_port_min == local.baked_local_media_udp_port_min &&
        var.candidate_local_rtcp_port_max == local.baked_local_media_udp_port_max
      )
    )
    phase_b_is_manifest_only           = true
    secrets_are_references_only        = true
    g009_candidate_receipt_is_bound    = local.g009_candidate_receipt_valid
    phase_c_backend_receipt_is_current = local.phase_c_backend_receipt_valid
    g2_disabled_boot_is_authorized     = local.g2_disabled_boot_authority_valid
    g008_live_bindings_are_complete    = !local.sip_connection_authority_ready || (local.g008_derivative_ready && local.g008_authority_ready && local.g008_f12_ready && local.g008_secrets_ready && local.ip_to_ip_binding_ready)
    ordered_deployment_is_ready        = local.deployment_ready
  }
}
