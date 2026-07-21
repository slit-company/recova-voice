locals {
  g008_bootstrap_manifest_handle = var.g008_execution_trigger == null || var.g008_bootstrap_manifest_version_resource_name == null ? "" : var.g008_bootstrap_manifest_version_resource_name
  g008_bootstrap_manifest_binding_sha256 = var.g008_execution_trigger != null && var.g008_secret_version_resource_names != null ? sha256(jsonencode({
    schema_version                        = "recova-g008-sealed-bootstrap-manifest-v1"
    transaction_authority_service_account = google_service_account.transaction_authority.email
    secret_version_mounts                 = local.g008_secret_mounts
    execution_versions                    = { for key, reference in local.g008_execution_secret_versions : key => reference if key != "manifest" }
  })) : ""
}

resource "google_compute_instance" "candidate" {
  name                      = local.immutable_names.instance
  project                   = var.project_id
  zone                      = "${var.region}-a"
  machine_type              = "n2-standard-2"
  desired_status            = local.g2_compute_ready ? "RUNNING" : "TERMINATED"
  allow_stopping_for_update = true
  can_ip_forward            = false
  deletion_protection       = false
  enable_display            = false

  tags = ["${local.name_stem}-candidate"]

  labels = merge(local.labels, {
    workload = "candidate"
    compute  = local.g2_compute_ready ? "running" : "terminated"
    dispatch = local.any_live_enabled ? "enabled" : "disabled"
    sip      = local.sip_ready ? "enabled" : "disabled"
    rtp      = local.rtp_ready ? "enabled" : "disabled"
    outbound = local.outbound_live_enabled ? "enabled" : "disabled"
    inbound  = local.inbound_live_enabled ? "enabled" : "disabled"
  })

  boot_disk {
    auto_delete = true
    device_name = local.immutable_names.boot_disk
    mode        = "READ_WRITE"

    initialize_params {
      image  = var.g009_candidate_receipt.image_self_link
      size   = 30
      type   = "pd-balanced"
      labels = local.labels
    }
  }

  scratch_disk {
    interface = "NVME"
  }

  network_interface {
    subnetwork = var.phase_b_dependency.subnet_self_link
    network_ip = google_compute_address.candidate.address
    stack_type = "IPV4_ONLY"

    dynamic "access_config" {
      for_each = local.network_path_armed ? [true] : []

      content {
        nat_ip       = google_compute_address.candidate_external[0].address
        network_tier = "PREMIUM"
      }
    }
  }

  service_account {
    email  = (local.control_phase_ready || local.bounded_live_ready) ? local.service_account_emails.runtime : local.service_account_emails.boot
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  metadata = {
    block-project-ssh-keys                 = "TRUE"
    disable-legacy-endpoints               = "TRUE"
    g008-metadata-token-endpoint           = "169.254.169.254"
    g008-metadata-containment-required     = local.bounded_live_ready ? "TRUE" : "FALSE"
    g008-bootstrap-manifest-handle         = local.g008_bootstrap_manifest_handle
    g008-bootstrap-manifest-binding-sha256 = local.g008_bootstrap_manifest_binding_sha256
    g008-review-payload-digest             = var.activation_receipt == null ? var.candidate_manifest.review_payload_digest : var.activation_receipt.successor_review_payload_digest
    # Legacy bootstrap integrity input consumed by the baked startup script; it is
    # not external-IAM evidence and cannot contribute to live readiness.
    g008-exact-binding-receipt-sha256    = local.g008_bootstrap_manifest_binding_sha256
    g008-iam-receipt-canonical-sha256    = try(var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256, "")
    g008-iam-receipt-verification-sha256 = try(var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256, "")
    enable-oslogin                       = "FALSE"
    serial-port-enable                   = "FALSE"
    workload-dispatch-enabled            = local.bounded_live_ready ? "TRUE" : "FALSE"
    sip-register-enabled                 = local.bounded_live_ready ? "TRUE" : "FALSE"
    media-enabled                        = local.bounded_live_ready ? "TRUE" : "FALSE"
    outbound-call-enabled                = local.bounded_live_ready ? "TRUE" : "FALSE"
    inbound-call-enabled                 = local.bounded_live_ready ? "TRUE" : "FALSE"
    f12-origin-enabled                   = local.bounded_live_ready ? "TRUE" : "FALSE"
    f12-readiness-enabled                = local.bounded_live_ready ? "TRUE" : "FALSE"
    f12-media-wss-enabled                = local.bounded_live_ready ? "TRUE" : "FALSE"
    source-download-enabled              = "FALSE"
    image-download-enabled               = "FALSE"
    startup-mode                         = "ALREADY_BAKED_OFFLINE"
    startup-script                       = file("${path.module}/startup-g008.sh")
    startup-script-sha256                = filesha256("${path.module}/startup-g008.sh")
    g009-image-id                        = tostring(var.g009_candidate_receipt.image_id)
    g009-image-generation                = tostring(var.g009_candidate_receipt.image_generation)
    g009-image-receipt-sha256            = var.g009_candidate_receipt.candidate_receipt_sha256
    live-window-start-utc                = var.live_window_start_utc == null ? "" : var.live_window_start_utc
    live-window-end-utc                  = var.live_window_end_utc == null ? "" : var.live_window_end_utc
    supplier-canonical-receipt-sha256    = try(var.supplier_rtp_evidence.canonical_receipt_sha256, "")
    supplier-verification-receipt-sha256 = try(var.supplier_rtp_evidence.verification_receipt_sha256, "")
    supplier-evidence-expires-at-utc     = try(var.supplier_rtp_evidence.expires_at_utc, "")
    supplier-max-concurrent-calls        = try(tostring(var.supplier_rtp_evidence.max_concurrent_calls), "")
    supplier-calls-per-second            = try(tostring(var.supplier_rtp_evidence.calls_per_second), "")
    prearm-inventory-sha256              = try(var.prearm_inventory_receipt.canonical_inventory_sha256, "")
    prearm-verification-receipt-sha256   = try(var.prearm_inventory_receipt.verification_receipt_sha256, "")
    supplier-binding-sha256              = try(var.supplier_endpoint_binding.canonical_receipt_sha256, "")
    supplier-binding-verification-sha256 = try(var.supplier_endpoint_binding.verification_receipt_sha256, "")
    host-policy-sha256                   = try(var.host_policy_receipt.policy_sha256, "")
    host-policy-tuple-binding-sha256     = try(var.host_policy_receipt.tuple_binding_sha256, "")
    recova-destination-receipt-sha256    = try(var.recova_destination_receipt.canonical_receipt_sha256, "")
    activation-nonce-sha256              = try(sha256(var.activation_receipt.activation_nonce), "")
    activation-receipt-sha256            = try(var.activation_receipt.canonical_receipt_sha256, "")
    activation-verification-sha256       = try(var.activation_receipt.verification_receipt_sha256, "")
    g008-execution-nonce-sha256          = try(nonsensitive(var.g008_execution_trigger.execution_nonce_sha256), "")
    g008-execution-runner-receipt-sha256 = try(var.g009_candidate_receipt.execution_runner_receipt_sha256, "")
    g008-execution-request-sha256        = try(nonsensitive(var.g008_execution_trigger.execution_request_sha256), "")
    g008-operator-credential-sha256      = try(nonsensitive(var.g008_execution_trigger.operator_credential_sha256), "")
    g008-execution-runner-sha256         = try(nonsensitive(var.g008_execution_trigger.execution_runner_sha256), "")
    g008-trusted-keyset-sha256           = try(nonsensitive(var.g008_execution_trigger.trusted_keyset_sha256), "")
    g008-provider-script-sha256          = try(nonsensitive(var.g008_execution_trigger.provider_script_sha256), "")
    g008-one-shot-marker-sha256 = sha256(jsonencode({
      run_id                          = var.run_id
      candidate_manifest_sha256       = var.candidate_manifest.manifest_sha256
      successor_review_payload_digest = var.activation_receipt == null ? var.candidate_manifest.review_payload_digest : var.activation_receipt.successor_review_payload_digest
      candidate_receipt_sha256        = var.g009_candidate_receipt.candidate_receipt_sha256
    }))
    g008-derivative-schema-version     = try(var.g008_derivative_receipt.schema_version, "")
    g008-derivative-expires-at-utc     = try(var.g008_derivative_receipt.receipt_expires_at_utc, "")
    g008-f12-contract-expires-at-utc   = try(var.g008_f12_contract.contract_receipt_expires_at_utc, "")
    g008-backend-image-digest          = try(var.g008_derivative_receipt.backend.image_digest, "")
    g008-backend-image-receipt-sha256  = try(var.g008_derivative_receipt.backend.receipt_sha256, "")
    g008-postgres-image-digest         = try(var.g008_derivative_receipt.postgres.image_digest, "")
    g008-postgres-image-receipt-sha256 = try(var.g008_derivative_receipt.postgres.receipt_sha256, "")
    g008-redis-image-digest            = try(var.g008_derivative_receipt.redis.image_digest, "")
    g008-redis-image-receipt-sha256    = try(var.g008_derivative_receipt.redis.receipt_sha256, "")
    g008-ingress-image-digest          = try(var.g008_derivative_receipt.ingress.image_digest, "")
    g008-ingress-image-receipt-sha256  = try(var.g008_derivative_receipt.ingress.receipt_sha256, "")
    g008-derivative-manifest-sha256    = try(var.g008_derivative_receipt.derivative_manifest_sha256, "")
    g008-derivative-receipt-sha256     = try(var.g008_derivative_receipt.receipt_sha256, "")
    g008-tenant-digest                 = try(var.g008_authority_binding.tenant_digest, "")
    g008-account-digest                = try(var.g008_authority_binding.account_digest, "")
    g008-envelope-digest               = try(var.g008_authority_binding.envelope_digest, "")
    g008-candidate-digest              = try(var.g008_authority_binding.candidate_digest, "")
    g008-f12-origin                    = try(var.g008_f12_contract.origin_https_endpoint_path, "")
    g008-f12-readiness-path            = try(var.g008_f12_contract.readiness_path, "")
    g008-f12-media-wss                 = try(var.g008_f12_contract.media_wss_endpoint_path, "")
    g008-f12-endpoint-san              = try(var.g008_f12_contract.endpoint_san, "")
    g008-f12-tls-certificate-sha256    = try(var.g008_f12_contract.tls_certificate_sha256, "")
    g008-f12-mtls-certificate-sha256   = try(var.g008_f12_contract.mtls_client_certificate_sha256, "")
    g008-f12-mtls-ca-sha256            = try(var.g008_f12_contract.mtls_ca_certificate_sha256, "")
    g008-dispatch-algorithm            = try(var.g008_f12_contract.dispatch_algorithm, "")
    g008-dispatch-key-id               = try(var.g008_f12_contract.dispatch_key_id, "")
    g008-dispatch-public-key-sha256    = try(var.g008_f12_contract.dispatch_public_key_sha256, "")
    g008-media-algorithm               = try(var.g008_f12_contract.media_algorithm, "")
    g008-media-key-id                  = try(var.g008_f12_contract.media_key_id, "")
    g008-media-public-key-sha256       = try(var.g008_f12_contract.media_public_key_sha256, "")
    g008-f12-contract-receipt-sha256   = try(var.g008_f12_contract.contract_receipt_sha256, "")
    g008-secret-mounts-read-only       = "TRUE"
    g008-watchdog-cutoff-utc           = local.watchdog_cutoff_utc
    g008-watchdog-cost-ceiling-krw     = tostring(var.cost_ceiling_krw)
  }

  lifecycle {
    precondition {
      condition     = local.deployment_ready
      error_message = "Phase C must be exactly default-off, verified G2-disabled-ready, or fully evidence-bound and ordered through dependency, candidate, endpoint, cost, window, SIP, RTP, and one call direction."
    }
    precondition {
      condition     = !local.g2_compute_ready || (local.g2_disabled_boot_ready || local.control_phase_ready || local.bounded_live_ready)
      error_message = "The private VM may run only for verified G2 no-traffic boot, cutoff-protected control readiness, or bounded live readiness."
    }
    precondition {
      condition     = local.g009_candidate_receipt_valid
      error_message = "The G009 candidate receipt must be current and bind the exact approved runtime, facade, source, and manifest digests."
    }
    precondition {
      condition = !var.sip_register_gate || (
        local.g008_derivative_ready &&
        local.g008_authority_ready &&
        local.g008_f12_ready &&
        local.g008_secrets_ready
      )
      error_message = "Live SIP authority requires the current recova-g008-derivative-v3 receipt, exact authority digests, current F12 contract, and all numeric secret versions."
    }
    precondition {
      condition = !(
        var.sip_register_gate ||
        var.rtp_gate ||
        var.outbound_call_gate ||
        var.inbound_call_gate
        ) || (
        var.g008_execution_trigger != null &&
        try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false) &&
        try(var.g008_execution_trigger.candidate_receipt_sha256 == var.g009_candidate_receipt.candidate_receipt_sha256, false) &&
        try(var.g008_execution_trigger.execution_runner_receipt_sha256 == var.g009_candidate_receipt.execution_runner_receipt_sha256, false) &&
        try(var.g008_execution_trigger.activation_receipt_sha256 == var.activation_receipt.canonical_receipt_sha256, false)
      )
      error_message = "Every live gate requires the exact numeric execution trigger bound to its activation receipt and baked-runner candidate receipt."
    }
    precondition {
      condition = !(
        var.sip_register_gate ||
        var.rtp_gate ||
        var.outbound_call_gate ||
        var.inbound_call_gate
      ) || local.g008_external_iam_receipt_ready
      error_message = "Every live gate requires a fresh externally issued authenticated G008 IAM provisioning receipt bound to the exact manifest, principals, window, destruction deadline, candidate, run, activation, policy result, and issuer key."
    }
    precondition {
      condition     = local.phase_b_manifest_time_valid && !local.destroy_due
      error_message = "The Phase B manifest and Phase C TTL must remain current."
    }

    precondition {
      condition     = !local.bounded_live_ready || local.cost_evidence_fresh
      error_message = "Live activation requires cost evidence fresh enough for the independently scheduled watchdog cutoff."
    }
    precondition {
      condition = !local.network_path_armed || (
        length(google_compute_address.candidate_external) == 1 &&
        var.supplier_endpoint_binding != null &&
        google_compute_address.candidate_external[0].address == var.supplier_endpoint_binding.customer_external_ipv4 &&
        local.network_path_ready
      )
      error_message = "The access configuration may attach only the exact reserved IPv4 bound by the preverified supplier receipt after all path bindings are ready."
    }

    precondition {
      condition = !(
        local.network_path_armed && !local.control_ready && !local.sip_ready
      ) || local.default_disabled
      error_message = "Armed/off must attach only to a TERMINATED candidate while every traffic allow remains disabled."
    }
  }

  depends_on = [
    google_project_iam_member.containment,
    google_secret_manager_secret_iam_member.runtime,
    google_service_account_iam_member.runtime_mints_transaction_token,
    google_compute_firewall.restricted_google_egress,
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]
}

check "g008_runtime_gate_alignment" {
  assert {
    condition = (
      google_compute_instance.candidate.metadata["workload-dispatch-enabled"] == (local.any_live_enabled ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["sip-register-enabled"] == (local.sip_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["media-enabled"] == (local.rtp_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["outbound-call-enabled"] == (local.outbound_live_enabled ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["inbound-call-enabled"] == (local.inbound_live_enabled ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["f12-origin-enabled"] == (local.sip_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["f12-readiness-enabled"] == (local.sip_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["f12-media-wss-enabled"] == (local.rtp_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["source-download-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["image-download-enabled"] == "FALSE" &&
      google_compute_instance.candidate.metadata["g008-secret-mounts-read-only"] == "TRUE" &&
      google_compute_instance.candidate.metadata["disable-legacy-endpoints"] == "TRUE" &&
      google_compute_instance.candidate.metadata["g008-metadata-token-endpoint"] == "169.254.169.254" &&
      google_compute_instance.candidate.metadata["g008-metadata-containment-required"] == (local.bounded_live_ready ? "TRUE" : "FALSE") &&
      google_compute_instance.candidate.metadata["g008-bootstrap-manifest-handle"] == local.g008_bootstrap_manifest_handle &&
      google_compute_instance.candidate.metadata["g008-bootstrap-manifest-binding-sha256"] == local.g008_bootstrap_manifest_binding_sha256 &&
      google_compute_instance.candidate.metadata["g008-exact-binding-receipt-sha256"] == local.g008_bootstrap_manifest_binding_sha256 &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] == try(var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256, "") &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] == try(var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256, "") &&
      google_compute_instance.candidate.metadata["startup-script"] == file("${path.module}/startup-g008.sh") &&
      google_compute_instance.candidate.metadata["startup-script-sha256"] == filesha256("${path.module}/startup-g008.sh") &&
      google_compute_instance.candidate.metadata["g008-execution-nonce-sha256"] == try(nonsensitive(var.g008_execution_trigger.execution_nonce_sha256), "") &&
      google_compute_instance.candidate.metadata["g008-review-payload-digest"] == (var.activation_receipt == null ? var.candidate_manifest.review_payload_digest : var.activation_receipt.successor_review_payload_digest) &&
      google_compute_instance.candidate.metadata["g008-one-shot-marker-sha256"] == sha256(jsonencode({
        run_id                          = var.run_id
        candidate_manifest_sha256       = var.candidate_manifest.manifest_sha256
        successor_review_payload_digest = var.activation_receipt == null ? var.candidate_manifest.review_payload_digest : var.activation_receipt.successor_review_payload_digest
        candidate_receipt_sha256        = var.g009_candidate_receipt.candidate_receipt_sha256
      })) &&
      google_compute_instance.candidate.metadata["g008-watchdog-cutoff-utc"] == local.watchdog_cutoff_utc &&
      google_compute_instance.candidate.metadata["startup-mode"] == "ALREADY_BAKED_OFFLINE"
    )
    error_message = "Dispatch, SIP, RTP/media/F12 WSS, the opaque digest-bound bootstrap manifest, and separate call-direction gates must align; the audited one-shot startup is hash-bound and downloads remain disabled."
  }
}

check "public_admin_surface_is_exactly_gated" {
  assert {
    condition = (
      google_compute_instance.candidate.can_ip_forward == false &&
      google_compute_instance.candidate.enable_display == false &&
      google_compute_instance.candidate.metadata["block-project-ssh-keys"] == "TRUE" &&
      google_compute_instance.candidate.metadata["enable-oslogin"] == "FALSE" &&
      google_compute_instance.candidate.metadata["serial-port-enable"] == "FALSE" &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == (local.network_path_armed ? 1 : 0)
    )
    error_message = "Forwarding, display, SSH keys, OS Login, and serial console stay disabled; the sole public access configuration must be exact-receipt-gated."
  }
}
