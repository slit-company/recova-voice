output "phase_c_redacted_identity" {
  description = "Non-sensitive identity of the independently stateful Phase C foundation."
  sensitive   = false
  value = {
    phase      = local.phase_name
    run_id     = var.run_id
    project_id = var.project_id
    region     = var.region
  }
}

output "containment_redacted" {
  description = "Non-sensitive bounded containment metadata; this is not evidence that external destruction has run."
  sensitive   = false
  value = {
    apply_timestamp_utc           = local.containment_contract.apply_timestamp_utc
    destroy_deadline_utc          = local.containment_contract.destroy_deadline_utc
    ttl_hours                     = local.containment_contract.ttl_hours
    cost_ceiling_krw              = local.containment_contract.cost_ceiling_krw
    traffic_authority             = local.containment_contract.traffic_authority
    phase_b_mutation_authority    = local.containment_contract.phase_b_mutation_authority
    phase_b_destroy_authority     = local.containment_contract.phase_b_destroy_authority
    automatic_application_retries = local.containment_contract.automatic_application_retries
    maximum_attempts              = local.containment_contract.maximum_attempts
    maximum_active_attempts       = local.containment_contract.maximum_active_attempts
    maximum_media_seconds         = local.containment_contract.maximum_media_seconds
    destroy_execution             = "external-leader-required"
  }
}

output "network_policy_redacted" {
  description = "Graph-derived managed network posture plus redacted inventory bindings; project-wide absence requires the signed inventory receipt."
  sensitive   = false
  value = {
    external_address_reserved                    = length(google_compute_address.candidate_external) == 1
    external_address_attached                    = local.network_path_armed
    external_address_binding_sha256              = try(sha256(google_compute_address.candidate_external[0].address), "")
    managed_cloud_nat_count                      = 0
    prearm_inventory_sha256                      = try(var.prearm_inventory_receipt.canonical_inventory_sha256, "")
    prearm_inventory_verification_sha256         = try(var.prearm_inventory_receipt.verification_receipt_sha256, "")
    sip_peer_is_supplier_receipt_bound           = local.supplier_signaling_bound
    sip_rules_present                            = length(google_compute_firewall.sip_ingress) == 1 && length(google_compute_firewall.sip_egress) == 1
    rtp_rules_present                            = length(google_compute_firewall.rtp_ingress) == 1 && length(google_compute_firewall.rtp_egress) == 1
    f2_f12_rule_present                          = length(google_compute_firewall.facade_f2_f12_egress) == 1
    wss_rule_present                             = length(google_compute_firewall.facade_wss_egress) == 1
    watchdog_rule_count                          = length(google_cloud_scheduler_job.watchdog_disable_traffic)
    watchdog_stop_present                        = length(google_cloud_scheduler_job.watchdog_stop_candidate) == 1
    watchdog_cutoff_utc                          = local.watchdog_cutoff_utc
    restricted_google_api_reachability_validated = local.restricted_google_api_reachability_validated
  }
}

output "secret_policy_redacted" {
  description = "Non-sensitive secret-reference posture; identifiers and payloads are intentionally omitted."
  sensitive   = false
  value = {
    base_reference_count  = 7
    live_reference_count  = local.g008_secrets_ready ? 10 : 0
    numeric_versions_only = true
    secret_values_read    = false
    identifiers_output    = false
  }
}
