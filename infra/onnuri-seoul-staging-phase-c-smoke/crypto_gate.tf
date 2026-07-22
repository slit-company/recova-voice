locals {
  phase_c_live_crypto_enabled = var.phase_c_live_preflight_bundle_path != null
  g008_external_iam_live_requested = (
    var.sip_register_gate ||
    var.sip_ip_to_ip_gate ||
    var.rtp_gate ||
    var.outbound_call_gate ||
    var.inbound_call_gate
  )
  g008_external_iam_signed_claims = !local.g008_external_iam_live_requested ? null : {
    schema_version                    = var.g008_external_iam_provisioning_receipt.schema_version
    bootstrap_manifest_binding_sha256 = var.g008_external_iam_provisioning_receipt.bootstrap_manifest_binding_sha256
    runtime_service_account_email     = var.g008_external_iam_provisioning_receipt.runtime_service_account_email
    review_payload_digest             = var.g008_external_iam_provisioning_receipt.review_payload_digest
    transaction_service_account_email = var.g008_external_iam_provisioning_receipt.transaction_service_account_email
    live_window_start_utc             = var.g008_external_iam_provisioning_receipt.live_window_start_utc
    live_window_end_utc               = var.g008_external_iam_provisioning_receipt.live_window_end_utc
    destruction_deadline_utc          = var.g008_external_iam_provisioning_receipt.destruction_deadline_utc
    candidate_manifest_sha256         = var.g008_external_iam_provisioning_receipt.candidate_manifest_sha256
    run_id                            = var.g008_external_iam_provisioning_receipt.run_id
    activation_nonce_sha256           = var.g008_external_iam_provisioning_receipt.activation_nonce_sha256
    activation_receipt_sha256         = var.g008_external_iam_provisioning_receipt.activation_receipt_sha256
    provisioning_outcome              = var.g008_external_iam_provisioning_receipt.provisioning_outcome
    exact_policy_result_sha256        = var.g008_external_iam_provisioning_receipt.exact_policy_result_sha256
    issuer_key_id                     = var.g008_external_iam_provisioning_receipt.issuer_key_id
    issuer_key_fingerprint_sha256     = var.g008_external_iam_provisioning_receipt.issuer_key_fingerprint_sha256
    issued_at_utc                     = var.g008_external_iam_provisioning_receipt.issued_at_utc
    expires_at_utc                    = var.g008_external_iam_provisioning_receipt.expires_at_utc
  }

  phase_c_live_expected_context = local.phase_c_live_crypto_enabled ? {
    schema_version                  = "recova-phase-c-live-context.v1"
    project_id                      = var.project_id
    region                          = var.region
    run_id                          = var.run_id
    activation_nonce                = var.activation_receipt.activation_nonce
    successor_review_payload_digest = var.activation_receipt.successor_review_payload_digest
    live_window_start_utc           = var.live_window_start_utc
    live_window_end_utc             = var.live_window_end_utc
    phase_b = {
      manifest_sha256                    = var.phase_b_dependency.manifest_sha256
      network_self_link                  = var.phase_b_dependency.network_self_link
      subnet_self_link                   = var.phase_b_dependency.subnet_self_link
      subnet_ipv4_cidr                   = var.phase_b_dependency.subnet_ipv4_cidr
      private_ip_google_access           = var.phase_b_dependency.private_ip_google_access
      ingress_deny_rule_name             = var.phase_b_dependency.ingress_deny_rule_name
      egress_deny_rule_name              = var.phase_b_dependency.egress_deny_rule_name
      phase_b_source_sha256              = var.phase_b_dependency.phase_b_source_sha256
      backend_identity                   = var.phase_b_dependency.backend_identity
      backend_generation                 = tostring(var.phase_b_dependency.backend_generation)
      backend_serial                     = tostring(var.phase_b_dependency.backend_serial)
      canonical_state_sha256             = var.phase_b_dependency.canonical_state_sha256
      non_sensitive_outputs_sha256       = var.phase_b_dependency.non_sensitive_outputs_sha256
      prearm_canonical_inventory_sha256  = var.prearm_inventory_receipt.canonical_inventory_sha256
      prearm_verification_receipt_sha256 = var.prearm_inventory_receipt.verification_receipt_sha256
    }
    execution_contract = {
      sip_connection_mode          = var.activation_receipt.sip_connection_mode
      source_external_ipv4         = try(var.activation_receipt.source_external_ipv4, "")
      peer_signaling_ipv4_cidr     = try(var.activation_receipt.peer_signaling_ipv4_cidr, "")
      peer_signaling_udp_port      = tostring(try(var.activation_receipt.peer_signaling_udp_port, 0))
      owned_target_sha256          = try(var.activation_receipt.owned_target_sha256, "")
      stage_sequence               = var.activation_receipt.stage_sequence
      register_attempt_budget      = tostring(var.activation_receipt.register_attempt_budget)
      unregister_attempt_budget    = tostring(var.activation_receipt.unregister_attempt_budget)
      total_call_attempt_budget    = tostring(var.activation_receipt.total_call_attempt_budget)
      retry_count                  = tostring(var.activation_receipt.retry_count)
      concurrency_count            = tostring(var.activation_receipt.concurrency_count)
      call_deadline_seconds        = tostring(var.activation_receipt.call_deadline_seconds)
      peer_detach_required         = var.activation_receipt.sip_connection_mode == "ip_to_ip"
      containment_cleanup_required = true
    }
    supplier = {
      signaling_ipv4_cidr                  = var.supplier_rtp_evidence.signaling_ipv4_cidr
      signaling_udp_port                   = tostring(var.supplier_rtp_evidence.signaling_udp_port)
      remote_ipv4_cidrs                    = sort(tolist(var.supplier_rtp_evidence.remote_ipv4_cidrs))
      remote_rtp_udp_port_min              = tostring(var.supplier_rtp_evidence.remote_rtp_udp_port_min)
      remote_rtp_udp_port_max              = tostring(var.supplier_rtp_evidence.remote_rtp_udp_port_max)
      remote_rtcp_udp_port_min             = tostring(var.supplier_rtp_evidence.remote_rtcp_udp_port_min)
      remote_rtcp_udp_port_max             = tostring(var.supplier_rtp_evidence.remote_rtcp_udp_port_max)
      max_concurrent_calls                 = tostring(var.supplier_rtp_evidence.max_concurrent_calls)
      calls_per_second                     = tostring(var.supplier_rtp_evidence.calls_per_second)
      evidence_sha256                      = var.supplier_rtp_evidence.canonical_receipt_sha256
      endpoint_binding_canonical_sha256    = var.supplier_endpoint_binding.canonical_receipt_sha256
      endpoint_binding_verification_sha256 = var.supplier_endpoint_binding.verification_receipt_sha256
      customer_external_ipv4               = local.bound_supplier_endpoint.customer_external_ipv4
      bound_signaling_ipv4_cidr            = local.bound_supplier_endpoint.signaling_ipv4_cidr
      bound_signaling_remote_udp_port      = tostring(local.bound_supplier_endpoint.signaling_remote_udp_port)
      candidate_sip_listen_udp_port        = tostring(local.bound_supplier_endpoint.candidate_sip_listen_udp_port)
      bound_media_ipv4_cidrs               = sort(tolist(local.bound_supplier_endpoint.media_ipv4_cidrs))
      bound_remote_rtp_udp_port_min        = tostring(local.bound_supplier_endpoint.remote_rtp_udp_port_min)
      bound_remote_rtp_udp_port_max        = tostring(local.bound_supplier_endpoint.remote_rtp_udp_port_max)
      bound_remote_rtcp_udp_port_min       = tostring(local.bound_supplier_endpoint.remote_rtcp_udp_port_min)
      bound_remote_rtcp_udp_port_max       = tostring(local.bound_supplier_endpoint.remote_rtcp_udp_port_max)
    }
    host_policy = {
      policy_sha256                     = var.host_policy_receipt.policy_sha256
      tuple_binding_sha256              = var.host_policy_receipt.tuple_binding_sha256
      verification_receipt_sha256       = var.host_policy_receipt.verification_receipt_sha256
      candidate_sip_listen_udp_port     = tostring(var.candidate_sip_listen_udp_port)
      candidate_local_rtp_udp_port_min  = tostring(var.candidate_local_rtp_port_min)
      candidate_local_rtp_udp_port_max  = tostring(var.candidate_local_rtp_port_max)
      candidate_local_rtcp_udp_port_min = tostring(var.candidate_local_rtcp_port_min)
      candidate_local_rtcp_udp_port_max = tostring(var.candidate_local_rtcp_port_max)
      issued_at_utc                     = var.host_policy_receipt.issued_at_utc
      expires_at_utc                    = var.host_policy_receipt.expires_at_utc
    }
    recova_destination = {
      canonical_receipt_sha256    = var.recova_destination_receipt.canonical_receipt_sha256
      verification_receipt_sha256 = var.recova_destination_receipt.verification_receipt_sha256
      control_ipv4_cidrs          = sort(tolist(local.bound_recova_destination.control_ipv4_cidrs))
      media_ipv4_cidrs            = sort(tolist(local.bound_recova_destination.media_ipv4_cidrs))
      f1_source_ipv4_cidrs        = local.bound_recova_f1_cidrs
      control_endpoint_sha256     = var.recova_destination_receipt.control_endpoint_sha256
      media_endpoint_sha256       = var.recova_destination_receipt.media_endpoint_sha256
      certificate_binding_sha256  = var.recova_destination_receipt.certificate_binding_sha256
      f1_mtls_endpoint_path       = var.recova_f1_mtls_endpoint_path
      f2_https_endpoint_path      = var.recova_f2_https_endpoint_path
      f3_wss_endpoint_path        = var.recova_f3_wss_endpoint_path
      f4_https_endpoint_path      = var.recova_f4_https_endpoint_path
      f5_https_endpoint_path      = var.recova_f5_https_endpoint_path
      f12_mtls_endpoint_path      = var.recova_f12_mtls_endpoint_path
    }
    candidate_boot = {
      image_self_link                           = var.g009_candidate_receipt.image_self_link
      image_id                                  = tostring(var.g009_candidate_receipt.image_id)
      image_generation                          = tostring(var.g009_candidate_receipt.image_generation)
      source_sha256                             = var.g009_candidate_receipt.source_sha256
      export_sha256                             = var.g009_candidate_receipt.export_sha256
      derivative_sha256                         = var.g009_candidate_receipt.derivative_sha256
      runtime_image_digest                      = var.g009_candidate_receipt.runtime_image_digest
      facade_image_digest                       = var.g009_candidate_receipt.facade_image_digest
      candidate_manifest_sha256                 = var.g009_candidate_receipt.candidate_manifest_sha256
      candidate_receipt_sha256                  = var.g009_candidate_receipt.candidate_receipt_sha256
      candidate_receipt_signature_base64        = var.g009_candidate_receipt.candidate_receipt_signature_base64
      candidate_receipt_signer_key_id           = var.g009_candidate_receipt.candidate_receipt_signer_key_id
      candidate_receipt_verification_key_sha256 = var.g009_candidate_receipt.candidate_receipt_verification_key_sha256
      candidate_receipt_issued_at_utc           = var.g009_candidate_receipt.candidate_receipt_issued_at_utc
      candidate_receipt_expires_at_utc          = var.g009_candidate_receipt.candidate_receipt_expires_at_utc
      compose_sha256                            = filesha256("${path.module}/../../deploy/onnuri-jambonz-oss/compose.yaml")
      startup_sha256                            = filesha256("${path.module}/startup-g008.sh")
    }
    secrets = {
      legacy = local.bound_legacy_secret_versions
    }
    bootstrap = {
      g008_bootstrap_manifest_handle         = local.g008_bootstrap_manifest_handle
      g008_bootstrap_manifest_binding_sha256 = local.g008_bootstrap_manifest_binding_sha256
      review_payload_digest                  = var.candidate_manifest.review_payload_digest
      successor_review_payload_digest        = var.activation_receipt.successor_review_payload_digest
    }
    execution = var.g008_execution_trigger == null ? null : {
      versions = {
        request             = var.g008_execution_trigger.execution_request_version_resource_name
        sip_username        = var.g008_execution_trigger.sip_username_secret_version
        sip_password        = var.g008_execution_trigger.sip_password_secret_version
        sip_realm           = var.g008_execution_trigger.sip_realm_secret_version
        target              = var.g008_execution_trigger.target_secret_version
        execution_nonce     = var.g008_execution_trigger.execution_nonce_secret_version
        operator_credential = var.g008_execution_trigger.operator_credential_secret_version
      }
      content_sha256 = {
        request             = var.g008_execution_trigger.execution_request_sha256
        sip_username        = var.g008_execution_trigger.sip_username_sha256
        sip_password        = var.g008_execution_trigger.sip_password_sha256
        sip_realm           = var.g008_execution_trigger.sip_realm_sha256
        target              = var.g008_execution_trigger.target_sha256
        execution_nonce     = var.g008_execution_trigger.execution_nonce_sha256
        operator_credential = var.g008_execution_trigger.operator_credential_sha256
      }
      review_payload_digest     = var.g008_execution_trigger.review_payload_digest
      candidate_manifest_sha256 = var.candidate_manifest.manifest_sha256
      runtime_image_digest      = var.g009_candidate_receipt.runtime_image_digest
      candidate_receipt_sha256  = var.g009_candidate_receipt.candidate_receipt_sha256
    }
    provider = {
      provider_id_digest = var.provider_redacted_claims.provider_id_digest
      account_id_digest  = var.provider_redacted_claims.account_id_digest
      currency           = var.provider_redacted_claims.currency
      starting_balance   = var.provider_redacted_claims.starting_balance
      evidence_sha256    = var.provider_redacted_claims.evidence_sha256
    }
    derivative = {
      schema_version             = var.g008_derivative_receipt.schema_version
      backend_image_digest       = var.g008_derivative_receipt.backend.image_digest
      backend_receipt_sha256     = var.g008_derivative_receipt.backend.receipt_sha256
      postgres_image_digest      = var.g008_derivative_receipt.postgres.image_digest
      postgres_receipt_sha256    = var.g008_derivative_receipt.postgres.receipt_sha256
      redis_image_digest         = var.g008_derivative_receipt.redis.image_digest
      redis_receipt_sha256       = var.g008_derivative_receipt.redis.receipt_sha256
      ingress_image_digest       = var.g008_derivative_receipt.ingress.image_digest
      ingress_receipt_sha256     = var.g008_derivative_receipt.ingress.receipt_sha256
      derivative_manifest_sha256 = var.g008_derivative_receipt.derivative_manifest_sha256
      candidate_manifest_sha256  = var.g008_derivative_receipt.candidate_manifest_sha256
    }
    f12 = {
      origin_https_endpoint_path     = var.g008_f12_contract.origin_https_endpoint_path
      readiness_path                 = var.g008_f12_contract.readiness_path
      media_wss_endpoint_path        = var.g008_f12_contract.media_wss_endpoint_path
      endpoint_san                   = var.g008_f12_contract.endpoint_san
      tls_certificate_sha256         = var.g008_f12_contract.tls_certificate_sha256
      mtls_client_certificate_sha256 = var.g008_f12_contract.mtls_client_certificate_sha256
      mtls_ca_certificate_sha256     = var.g008_f12_contract.mtls_ca_certificate_sha256
      dispatch_algorithm             = var.g008_f12_contract.dispatch_algorithm
      dispatch_key_id                = var.g008_f12_contract.dispatch_key_id
      dispatch_public_key_sha256     = var.g008_f12_contract.dispatch_public_key_sha256
      media_algorithm                = var.g008_f12_contract.media_algorithm
      media_key_id                   = var.g008_f12_contract.media_key_id
      media_public_key_sha256        = var.g008_f12_contract.media_public_key_sha256
    }
    authority = {
      tenant_digest    = var.g008_authority_binding.tenant_digest
      account_digest   = var.g008_authority_binding.account_digest
      envelope_digest  = var.g008_authority_binding.envelope_digest
      candidate_digest = var.g008_authority_binding.candidate_digest
    }
    cost = {
      currency            = "KRW"
      cost_ceiling_krw    = tostring(var.cost_ceiling_krw)
      estimated_total_krw = tostring(var.cost_evidence.estimated_total_krw)
      observed_total_krw  = tostring(var.cost_evidence.observed_total_krw)
      recorded_at_utc     = var.cost_evidence.recorded_at_utc
      expires_at_utc      = var.cost_evidence.expires_at_utc
      evidence_sha256     = var.cost_evidence.evidence_sha256
      signer_key_id       = var.cost_evidence.signer_key_id
    }
    iam_provisioning = local.g008_external_iam_signed_claims
  } : null
}

data "external" "phase_c_live_plan" {
  count = local.phase_c_live_crypto_enabled ? 1 : 0

  program = ["python3", "${path.module}/../../scripts/verify_phase_c_live_preflight.py"]
  query = {
    bundle_path            = var.phase_c_live_preflight_bundle_path
    expected_context_json  = jsonencode(local.phase_c_live_expected_context)
    expected_bundle_sha256 = ""
    verification_stage     = "plan"
  }
}

resource "terraform_data" "phase_c_live_apply_anchor" {
  count = local.phase_c_live_crypto_enabled ? 1 : 0

  triggers_replace = [plantimestamp()]
}

data "external" "phase_c_live_apply" {
  count = local.phase_c_live_crypto_enabled ? 1 : 0

  program = ["python3", "${path.module}/../../scripts/verify_phase_c_live_preflight.py"]
  query = {
    bundle_path            = var.phase_c_live_preflight_bundle_path
    expected_context_json  = jsonencode(local.phase_c_live_expected_context)
    expected_bundle_sha256 = data.external.phase_c_live_plan[0].result.bundle_sha256
    verification_stage     = "apply"
  }

  depends_on = [terraform_data.phase_c_live_apply_anchor]
}

resource "terraform_data" "phase_c_live_apply_gate" {
  count = local.phase_c_live_crypto_enabled ? 1 : 0

  input = {
    plan_bundle_sha256                    = data.external.phase_c_live_plan[0].result.bundle_sha256
    apply_bundle_sha256                   = data.external.phase_c_live_apply[0].result.bundle_sha256
    plan_authorized_context_sha256        = data.external.phase_c_live_plan[0].result.authorized_context_sha256
    apply_authorized_context_sha256       = data.external.phase_c_live_apply[0].result.authorized_context_sha256
    plan_iam_provisioning_payload_sha256  = try(data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256, "")
    apply_iam_provisioning_payload_sha256 = try(data.external.phase_c_live_apply[0].result.iam_provisioning_payload_sha256, "")
    aggregate_expires_at_utc              = data.external.phase_c_live_apply[0].result.expires_at_utc
    live_window_end_utc                   = var.live_window_end_utc
    minimum_remaining_runway              = local.live_window_minimum_remaining_runway
    effective_cutoff_utc                  = data.external.phase_c_live_apply[0].result.effective_cutoff_utc
  }

  lifecycle {
    precondition {
      condition = (
        data.external.phase_c_live_plan[0].result.verified == "true" &&
        data.external.phase_c_live_apply[0].result.verified == "true" &&
        data.external.phase_c_live_apply[0].result.bundle_sha256 == data.external.phase_c_live_plan[0].result.bundle_sha256 &&
        data.external.phase_c_live_apply[0].result.authorized_context_sha256 == data.external.phase_c_live_plan[0].result.authorized_context_sha256 &&
        try(data.external.phase_c_live_apply[0].result.iam_provisioning_payload_sha256, "") == try(data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256, "") &&
        (!local.g008_external_iam_live_requested || (
          var.g008_external_iam_provisioning_receipt != null &&
          try(data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256, "") != "" &&
          var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256 == try(data.external.phase_c_live_plan[0].result.iam_provisioning_payload_sha256, "")
        )) &&
        var.live_window_end_utc != null &&
        timecmp(data.external.phase_c_live_apply[0].result.expires_at_utc, var.live_window_end_utc) == 0 &&
        (!local.cutoff_required || timecmp(data.external.phase_c_live_apply[0].result.effective_cutoff_utc, local.watchdog_cutoff_utc) == 0) &&
        timecmp(data.external.phase_c_live_apply[0].result.effective_cutoff_utc, timeadd(plantimestamp(), local.live_window_minimum_remaining_runway)) >= 0
      )
      error_message = "Phase C live authority requires continuous plan/apply cryptographic verification of the same bundle and context; apply verification must run inside the signed live window with at least the fixed 15-minute deployment runway remaining, and aggregate authority must end exactly with that window."
    }
  }
}
