mock_provider "google" {}

variables {
  deployer_service_account = "phasec-deployer@slit-497603.iam.gserviceaccount.com"
  run_id                   = "offline-smoke-test"
  apply_timestamp_utc      = timestamp()
  destroy_deadline_utc     = timeadd(timestamp(), "24h")

  recova_f1_source_cidrs        = ["10.20.30.40/32"]
  recova_f1_mtls_endpoint_path  = "https://f1.recova.internal/dispatch"
  recova_f2_https_endpoint_path = "https://f2.recova.internal/callback"
  recova_f3_wss_endpoint_path   = "wss://f3.recova.internal/media"
  recova_f4_https_endpoint_path = "https://f4.recova.internal/secrets"
  recova_f5_https_endpoint_path = "https://f5.recova.internal/logs"
  recova_f12_mtls_endpoint_path = "https://f12.recova.internal/authority"

  phase_b_dependency = {
    manifest_sha256              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    signature_base64             = "YWJj"
    signer_key_id                = "phase-b-test-signer"
    verification_receipt_sha256  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    project_id                   = "slit-497603"
    region                       = "asia-northeast3"
    network_self_link            = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/recova-onnuri-phase-b-vpc"
    subnet_self_link             = "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/recova-onnuri-phase-b-subnet-seoul"
    subnet_ipv4_cidr             = "10.73.96.0/24"
    private_ip_google_access     = true
    ingress_deny_rule_name       = "recova-onnuri-phase-b-deny-ingress"
    egress_deny_rule_name        = "recova-onnuri-phase-b-deny-egress"
    phase_b_source_sha256        = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    backend_identity             = "gcs://slit-497603-phase-b-state/onnuri/phase-b"
    backend_generation           = 1
    backend_serial               = 1
    canonical_state_sha256       = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    non_sensitive_outputs_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    issued_at_utc                = "2026-07-15T00:00:00Z"
    expires_at_utc               = "2027-07-15T00:00:00Z"
  }
  g009_candidate_receipt = {
    image_self_link                           = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009"
    image_id                                  = 1
    image_generation                          = 1
    source_sha256                             = "1111111111111111111111111111111111111111111111111111111111111111"
    export_sha256                             = "2222222222222222222222222222222222222222222222222222222222222222"
    derivative_sha256                         = "3333333333333333333333333333333333333333333333333333333333333333"
    runtime_image_digest                      = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    facade_image_digest                       = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
    candidate_receipt_sha256                  = "4444444444444444444444444444444444444444444444444444444444444444"
    candidate_receipt_signature_base64        = "YWJj"
    candidate_receipt_signer_key_id           = "g009-test-signer"
    candidate_receipt_verification_key_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    candidate_receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
    candidate_receipt_expires_at_utc          = "2027-07-15T00:00:00Z"
  }

  candidate_manifest = {
    release_id             = "jambonz-oss-g009"
    source_sha256          = "1111111111111111111111111111111111111111111111111111111111111111"
    image_digest           = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    facade_image_digest    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    sbom_sha256            = "6666666666666666666666666666666666666666666666666666666666666666"
    license_sha256         = "7777777777777777777777777777777777777777777777777777777777777777"
    manifest_sha256        = "8888888888888888888888888888888888888888888888888888888888888888"
    renewed_review_sha256  = "9999999999999999999999999999999999999999999999999999999999999999"
    review_payload_digest  = "sha256:6e759e5e5af876b4ffc561f9f2968203da7d7ae7310e6d29f7f23ddd93266ab8"
    review_approval_status = "approved"
    approved_at_utc        = "2026-07-15T00:00:00Z"
  }

  phase_c_backend_receipt = {
    bucket_name       = "slit-497603-offline-smoke-tfstate"
    prefix            = "onnuri-seoul-staging-phase-c-smoke/offline-smoke-test"
    config_sha256     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    bucket_generation = 1
    recorded_at_utc   = "2026-07-15T00:00:00Z"
  }

  secret_version_resource_names = {
    sip_password               = "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/1"
    f12_endpoint_credential    = "projects/slit-497603/secrets/f12-endpoint-credential/versions/1"
    f12_mtls_certificate       = "projects/slit-497603/secrets/f12-mtls-certificate/versions/1"
    facade_adapter_credential  = "projects/slit-497603/secrets/facade-adapter-credential/versions/1"
    callback_hmac_key          = "projects/slit-497603/secrets/callback-hmac-key/versions/1"
    tls_private_key            = "projects/slit-497603/secrets/tls-private-key/versions/1"
    stock_local_api_credential = "projects/slit-497603/secrets/stock-local-api-credential/versions/1"
  }
}
run "default_disabled_offline_contract" {
  command = plan

  assert {
    condition = (
      var.dependency_manifest_gate == false &&
      var.candidate_gate == false &&
      var.endpoint_identity_gate == false &&
      var.external_ip_reservation_gate == false &&
      var.network_path_arm_gate == false &&
      var.control_readiness_gate == false &&
      var.cost_gate == false &&
      var.live_window_gate == false &&
      var.sip_register_gate == false &&
      var.rtp_gate == false &&
      var.outbound_call_gate == false &&
      var.inbound_call_gate == false
    )
    error_message = "Every traffic and authority gate must default false."
  }

  assert {
    condition = (
      var.phase_c_live_preflight_bundle_path == null &&
      length(data.external.phase_c_live_plan) == 0 &&
      length(data.external.phase_c_live_apply) == 0 &&
      length(terraform_data.phase_c_live_apply_gate) == 0
    )
    error_message = "Default-disabled authority must not invoke or create any cryptographic live gate."
  }

  assert {
    condition = (
      local.disabled_zero_traffic_ready &&
      !local.cutoff_required &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_instance.candidate.service_account[0].email == local.service_account_emails.boot &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == 0 &&
      length(google_compute_firewall.facade_f2_f12_egress) == 0 &&
      length(google_compute_firewall.facade_wss_egress) == 0 &&
      length(google_compute_firewall.restricted_google_egress) == 0 &&
      length(google_compute_firewall.logging_egress) == 0 &&
      length(google_compute_firewall.image_egress) == 0 &&
      length(google_cloud_scheduler_job.watchdog_disable_traffic) == 0 &&
      length(google_cloud_scheduler_job.watchdog_stop_candidate) == 0 &&
      length(google_secret_manager_secret_iam_member.runtime) == 0 &&
      google_compute_instance.candidate.metadata["g008-exact-binding-receipt-sha256"] == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-secret-versions")
    )
    error_message = "The default VM must stay terminated without a public IP, and unvalidated F2/F12, WSS, Google, logging, and image rules must be absent."
  }

  assert {
    condition = (
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      length(google_compute_firewall.sip_ingress) == 0 &&
      length(google_compute_firewall.sip_egress) == 0 &&
      length(google_compute_firewall.rtp_ingress) == 0 &&
      length(google_compute_firewall.rtp_egress) == 0
    )
    error_message = "All live allow rules and supplier-specific SIP/RTP resources must be absent or disabled by default."
  }

  assert {
    condition = (
      !google_compute_firewall.deny_all_ingress.disabled &&
      !google_compute_firewall.deny_all_egress.disabled &&
      google_compute_firewall.deny_all_ingress.name == local.immutable_names.deny_all_ingress_firewall &&
      google_compute_firewall.deny_all_egress.name == local.immutable_names.deny_all_egress_firewall &&
      google_compute_firewall.deny_all_ingress.direction == "INGRESS" &&
      google_compute_firewall.deny_all_egress.direction == "EGRESS" &&
      google_compute_firewall.deny_all_ingress.priority > google_compute_firewall.recova_f1_https_ingress.priority &&
      toset(google_compute_firewall.deny_all_ingress.source_ranges) == toset(["0.0.0.0/0"]) &&
      toset(google_compute_firewall.deny_all_egress.destination_ranges) == toset(["0.0.0.0/0"]) &&
      toset(google_compute_firewall.deny_all_ingress.target_service_accounts) == toset([
        local.service_account_emails.boot,
        local.service_account_emails.runtime,
      ]) &&
      toset(google_compute_firewall.deny_all_egress.target_service_accounts) == toset([
        local.service_account_emails.boot,
        local.service_account_emails.runtime,
      ]) &&
      one(google_compute_firewall.deny_all_ingress.deny).protocol == "all" &&
      one(google_compute_firewall.deny_all_egress.deny).protocol == "all" &&
      one(google_compute_firewall.deny_all_ingress.log_config).metadata == "INCLUDE_ALL_METADATA" &&
      one(google_compute_firewall.deny_all_egress.log_config).metadata == "INCLUDE_ALL_METADATA"
    )
    error_message = "Always-enabled logged IPv4 deny baselines must target exactly the Phase C boot and runtime service accounts and remain lower precedence than narrow live allows."
  }

  assert {
    condition = (
      var.supplier_rtp_evidence == null &&
      length(google_compute_firewall.rtp_ingress) == 0 &&
      length(google_compute_firewall.rtp_egress) == 0
    )
    error_message = "RTP rules must be absent until supplier-authoritative CIDRs and ports are supplied."
  }

  assert {
    condition = (
      local.default_disabled &&
      local.kill_switch &&
      !local.g2_compute_ready &&
      !local.sip_ready &&
      !local.rtp_ready &&
      !local.outbound_live_enabled &&
      !local.inbound_live_enabled &&
      (!local.sip_ready || local.g2_prerequisites_ready) &&
      (!local.rtp_ready || local.sip_ready) &&
      (!local.outbound_live_enabled || local.rtp_ready) &&
      (!local.inbound_live_enabled || local.rtp_ready)
    )
    error_message = "Default authority must be fail closed and every later readiness state must preserve the ordered prerequisite chain."
  }

  assert {
    condition = (
      output.containment_redacted.ttl_hours == 24 &&
      output.containment_redacted.traffic_authority == "disabled" &&
      output.containment_redacted.destroy_execution == "external-leader-required" &&
      output.containment_redacted.cost_ceiling_krw == 50000 &&
      output.containment_redacted.phase_b_mutation_authority == "none" &&
      output.containment_redacted.phase_b_destroy_authority == "none" &&
      output.containment_redacted.automatic_application_retries == 0 &&
      output.containment_redacted.maximum_attempts == 3 &&
      output.containment_redacted.maximum_active_attempts == 1 &&
      output.containment_redacted.maximum_media_seconds == 60 &&
      output.network_policy_redacted.restricted_google_api_reachability_validated == true &&
      output.network_policy_redacted.sip_peer_is_supplier_receipt_bound == false &&
      output.network_policy_redacted.sip_rules_present == false &&
      output.network_policy_redacted.rtp_rules_present == false &&
      output.network_policy_redacted.f2_f12_rule_present == false &&
      output.network_policy_redacted.wss_rule_present == false &&
      output.secret_policy_redacted.secret_values_read == false &&
      output.secret_policy_redacted.identifiers_output == false
    )
    error_message = "TTL, cost, authority, attempt, media, restricted-VIP, and secret redaction bounds must remain explicit."
  }
}
run "verified_g2_disabled_boot_stays_terminated_without_traffic" {
  command = plan

  variables {
    apply_timestamp_utc      = "2030-07-15T01:00:00Z"
    destroy_deadline_utc     = "2030-07-16T01:00:00Z"
    dependency_manifest_gate = true
    candidate_gate           = true
    endpoint_identity_gate   = true
  }

  assert {
    condition = (
      local.g2_disabled_boot_ready &&
      local.g2_live_gates_disabled &&
      !local.g2_compute_ready &&
      local.disabled_zero_traffic_ready &&
      !local.cutoff_required &&
      length(data.external.phase_c_live_plan) == 0 &&
      length(data.external.phase_c_live_apply) == 0 &&
      length(terraform_data.phase_c_live_apply_gate) == 0 &&
      !local.sip_ready &&
      !local.rtp_ready &&
      !local.outbound_live_enabled &&
      !local.inbound_live_enabled &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_instance.candidate.service_account[0].email == local.service_account_emails.boot &&
      google_compute_instance.candidate.labels.dispatch == "disabled" &&
      google_compute_instance.candidate.metadata["workload-dispatch-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["sip-register-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["media-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["outbound-call-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["inbound-call-enabled"] == "FALSE" &&
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      length(google_compute_firewall.sip_ingress) == 0 &&
      length(google_compute_firewall.sip_egress) == 0 &&
      length(google_compute_firewall.rtp_ingress) == 0 &&
      length(google_compute_firewall.rtp_egress) == 0 &&
      length(google_compute_firewall.facade_f2_f12_egress) == 0 &&
      length(google_compute_firewall.facade_wss_egress) == 0 &&
      length(google_cloud_scheduler_job.watchdog_disable_traffic) == 0 &&
      length(google_cloud_scheduler_job.watchdog_stop_candidate) == 0 &&
      length(google_secret_manager_secret_iam_member.runtime) == 0 &&
      google_compute_instance.candidate.metadata["g008-exact-binding-receipt-sha256"] == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-secret-versions")
    )
    error_message = "Verified G2-disabled prerequisites must keep the private workload terminated with dispatch, SIP, RTP, and calls disabled."
  }
}

run "g2_disabled_boot_missing_prerequisite_hard_fails" {
  command = plan

  expect_failures = [google_compute_address.candidate]

  variables {
    apply_timestamp_utc    = "2030-07-15T01:00:00Z"
    destroy_deadline_utc   = "2030-07-16T01:00:00Z"
    candidate_gate         = true
    endpoint_identity_gate = true
  }
}

run "g2_disabled_boot_live_gate_hard_fails" {
  command = plan

  expect_failures = [google_compute_address.candidate]

  variables {
    apply_timestamp_utc      = "2030-07-15T01:00:00Z"
    destroy_deadline_utc     = "2030-07-16T01:00:00Z"
    dependency_manifest_gate = true
    candidate_gate           = true
    endpoint_identity_gate   = true
    cost_gate                = true

    cost_evidence = {
      estimated_total_krw = 1
      observed_total_krw  = 1
      recorded_at_utc     = "2026-07-15T00:00:00Z"
      expires_at_utc      = "2030-07-15T02:00:00Z"
      evidence_sha256     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      signer_key_id       = "cost-test-signer"
    }
  }
}

run "wrong_phase_b_identity_hard_fails" {
  command = plan

  expect_failures = [google_compute_address.candidate]

  variables {
    phase_b_dependency = {
      manifest_sha256              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      signature_base64             = "YWJj"
      signer_key_id                = "phase-b-test-signer"
      verification_receipt_sha256  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      project_id                   = "slit-497603"
      region                       = "asia-northeast3"
      network_self_link            = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/wrong-phase-b-vpc"
      subnet_self_link             = "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/recova-onnuri-phase-b-subnet-seoul"
      subnet_ipv4_cidr             = "10.73.96.0/24"
      private_ip_google_access     = true
      ingress_deny_rule_name       = "recova-onnuri-phase-b-deny-ingress"
      egress_deny_rule_name        = "recova-onnuri-phase-b-deny-egress"
      phase_b_source_sha256        = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      backend_identity             = "gcs://slit-497603-phase-b-state/onnuri/phase-b"
      backend_generation           = 1
      backend_serial               = 1
      canonical_state_sha256       = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      non_sensitive_outputs_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      issued_at_utc                = "2026-07-15T00:00:00Z"
      expires_at_utc               = "2027-07-15T00:00:00Z"
    }
  }
}

run "stale_phase_b_manifest_hard_fails" {
  command = plan

  expect_failures = [google_compute_address.candidate]

  variables {
    phase_b_dependency = {
      manifest_sha256              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      signature_base64             = "YWJj"
      signer_key_id                = "phase-b-test-signer"
      verification_receipt_sha256  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      project_id                   = "slit-497603"
      region                       = "asia-northeast3"
      network_self_link            = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/recova-onnuri-phase-b-vpc"
      subnet_self_link             = "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/recova-onnuri-phase-b-subnet-seoul"
      subnet_ipv4_cidr             = "10.73.96.0/24"
      private_ip_google_access     = true
      ingress_deny_rule_name       = "recova-onnuri-phase-b-deny-ingress"
      egress_deny_rule_name        = "recova-onnuri-phase-b-deny-egress"
      phase_b_source_sha256        = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      backend_identity             = "gcs://slit-497603-phase-b-state/onnuri/phase-b"
      backend_generation           = 1
      backend_serial               = 1
      canonical_state_sha256       = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
      non_sensitive_outputs_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      issued_at_utc                = "2000-07-15T00:00:00Z"
      expires_at_utc               = "2000-07-16T00:00:00Z"
    }
  }
}

run "non_24_hour_ttl_hard_fails" {
  command = plan

  expect_failures = [google_compute_address.candidate]

  variables {
    destroy_deadline_utc = "2026-07-16T02:00:00Z"
  }
}

run "disabled_boot_live_gates_hard_fail" {
  command = plan

  expect_failures = [var.sip_register_gate]

  variables {
    dependency_manifest_gate = true
    candidate_gate           = true
    endpoint_identity_gate   = true
    cost_gate                = true
    live_window_gate         = true
    sip_register_gate        = true
    rtp_gate                 = true
    outbound_call_gate       = true
    inbound_call_gate        = true
    live_window_start_utc    = "2030-07-15T01:00:00Z"
    live_window_end_utc      = "2030-07-15T02:00:00Z"

    cost_evidence = {
      estimated_total_krw = 1
      observed_total_krw  = 1
      recorded_at_utc     = "2026-07-15T00:00:00Z"
      expires_at_utc      = "2030-07-15T02:00:00Z"
      evidence_sha256     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      signer_key_id       = "cost-test-signer"
    }

    supplier_rtp_evidence = {
      signaling_ipv4_cidr         = "198.51.100.1/32"
      signaling_udp_port          = 5060
      remote_ipv4_cidrs           = ["198.51.100.0/24"]
      remote_rtp_udp_port_min     = 10000
      remote_rtp_udp_port_max     = 10099
      remote_rtcp_udp_port_min    = 10100
      remote_rtcp_udp_port_max    = 10199
      max_concurrent_calls        = 1
      calls_per_second            = 1
      canonical_receipt_sha256    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      verification_receipt_sha256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      issued_at_utc               = "2030-07-15T00:00:00Z"
      expires_at_utc              = "2030-07-16T00:00:00Z"
    }
  }
}
run "facade_digest_mismatch_hard_fails" {
  command = plan

  expect_failures = [google_compute_instance.candidate]

  variables {
    g009_candidate_receipt = {
      image_self_link                           = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009"
      image_id                                  = 1
      image_generation                          = 1
      source_sha256                             = "1111111111111111111111111111111111111111111111111111111111111111"
      export_sha256                             = "2222222222222222222222222222222222222222222222222222222222222222"
      derivative_sha256                         = "3333333333333333333333333333333333333333333333333333333333333333"
      runtime_image_digest                      = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      facade_image_digest                       = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
      candidate_receipt_sha256                  = "4444444444444444444444444444444444444444444444444444444444444444"
      candidate_receipt_signature_base64        = "YWJj"
      candidate_receipt_signer_key_id           = "g009-test-signer"
      candidate_receipt_verification_key_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      candidate_receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
      candidate_receipt_expires_at_utc          = "2027-07-15T00:00:00Z"
    }
  }
}

run "runtime_digest_mismatch_hard_fails" {
  command = plan

  expect_failures = [google_compute_instance.candidate]

  variables {
    g009_candidate_receipt = {
      image_self_link                           = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009"
      image_id                                  = 1
      image_generation                          = 1
      source_sha256                             = "1111111111111111111111111111111111111111111111111111111111111111"
      export_sha256                             = "2222222222222222222222222222222222222222222222222222222222222222"
      derivative_sha256                         = "3333333333333333333333333333333333333333333333333333333333333333"
      runtime_image_digest                      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      facade_image_digest                       = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
      candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
      candidate_receipt_sha256                  = "4444444444444444444444444444444444444444444444444444444444444444"
      candidate_receipt_signature_base64        = "YWJj"
      candidate_receipt_signer_key_id           = "g009-test-signer"
      candidate_receipt_verification_key_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      candidate_receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
      candidate_receipt_expires_at_utc          = "2027-07-15T00:00:00Z"
    }
  }
}
run "legacy_g006_candidate_identifier_is_rejected" {
  command = plan

  expect_failures = [var.g009_candidate_receipt]

  variables {
    g009_candidate_receipt = {
      image_self_link                           = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g006"
      image_id                                  = 1
      image_generation                          = 1
      source_sha256                             = "1111111111111111111111111111111111111111111111111111111111111111"
      export_sha256                             = "2222222222222222222222222222222222222222222222222222222222222222"
      derivative_sha256                         = "3333333333333333333333333333333333333333333333333333333333333333"
      runtime_image_digest                      = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      facade_image_digest                       = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
      candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
      candidate_receipt_sha256                  = "4444444444444444444444444444444444444444444444444444444444444444"
      candidate_receipt_signature_base64        = "YWJj"
      candidate_receipt_signer_key_id           = "g009-test-signer"
      candidate_receipt_verification_key_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      candidate_receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
      candidate_receipt_expires_at_utc          = "2027-07-15T00:00:00Z"
    }
  }
}
