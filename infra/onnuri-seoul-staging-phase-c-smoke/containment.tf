locals {
  containment_contract = {
    phase                         = local.phase_name
    run_id                        = var.run_id
    apply_timestamp_utc           = var.apply_timestamp_utc
    destroy_deadline_utc          = var.destroy_deadline_utc
    ttl_hours                     = 24
    cost_ceiling_krw              = 50000
    traffic_authority             = local.bounded_live_ready ? "separately-approved-live" : "disabled"
    phase_b_mutation_authority    = "none"
    phase_b_destroy_authority     = "none"
    automatic_application_retries = local.activation_contract.call_retry_budget
    maximum_attempts              = local.activation_contract.total_call_attempt_budget
    maximum_active_attempts       = local.activation_contract.maximum_active_calls
    maximum_media_seconds         = local.activation_contract.maximum_media_seconds_per_call
  }
  watchdog_contract = {
    actuator_identity             = local.service_account_emails.watchdog
    cutoff_utc                    = local.watchdog_cutoff_utc
    cost_evidence_valid_until_utc = local.cost_evidence_watchdog_valid_until_utc
    cost_ceiling_krw              = var.cost_ceiling_krw
    traffic_firewalls             = local.watchdog_traffic_firewall_names
    stop_instance                 = local.immutable_names.instance
    retry_count                   = 0
    authority_expires             = "with-terraform-destruction"
  }
  g007_disabled_boot_gate_valid = (
    !var.dependency_manifest_gate &&
    !var.candidate_gate &&
    !var.endpoint_identity_gate &&
    !var.cost_gate &&
    !var.live_window_gate &&
    !var.sip_register_gate &&
    !var.rtp_gate &&
    !var.outbound_call_gate &&
    !var.inbound_call_gate
  )

  # Reachability is authority-backed only when the inherited Phase B subnet
  # explicitly enables Private Google Access.
  restricted_google_api_reachability_validated = local.phase_b_private_google_access_ready
}

resource "google_cloud_scheduler_job" "watchdog_disable_traffic" {
  for_each = local.network_path_armed ? toset(local.watchdog_traffic_firewall_names) : toset([])

  project          = var.project_id
  region           = var.region
  name             = "${local.name_stem}-wd-${substr(sha256(each.value), 0, 6)}"
  description      = "One-shot-equivalent fail-closed cutoff: disable the named Phase C live firewall."
  schedule         = formatdate("mm hh DD MM *", local.watchdog_cutoff_utc)
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"
  paused           = false

  retry_config {
    retry_count = 0
  }

  http_target {
    http_method = "PATCH"
    uri         = "https://compute.googleapis.com/compute/v1/projects/${var.project_id}/global/firewalls/${each.value}?updateMask=disabled"
    body        = base64encode(jsonencode({ disabled = true }))

    oauth_token {
      service_account_email = local.service_account_emails.watchdog
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  depends_on = [google_project_iam_member.containment]
}

resource "google_cloud_scheduler_job" "watchdog_stop_candidate" {
  count = local.network_path_armed ? 1 : 0

  project          = var.project_id
  region           = var.region
  name             = "${local.name_stem}-wd-stop"
  description      = "One-shot-equivalent fail-closed cutoff: stop the named Phase C VM."
  schedule         = formatdate("mm hh DD MM *", local.watchdog_cutoff_utc)
  time_zone        = "Etc/UTC"
  attempt_deadline = "60s"
  paused           = false

  retry_config {
    retry_count = 0
  }

  http_target {
    http_method = "POST"
    uri         = "https://compute.googleapis.com/compute/v1/projects/${var.project_id}/zones/${var.region}-a/instances/${local.immutable_names.instance}/stop"

    oauth_token {
      service_account_email = local.service_account_emails.watchdog
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }

  depends_on = [
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_project_iam_member.containment,
  ]
}


check "restricted_google_api_reachability_is_exact" {
  assert {
    condition = (
      local.restricted_google_api_reachability_validated == local.phase_b_private_google_access_ready &&
      length(google_compute_firewall.restricted_google_egress) == (local.bounded_live_ready ? 1 : 0) &&
      length(google_compute_firewall.logging_egress) == 0 &&
      length(google_compute_firewall.image_egress) == 0
    )
    error_message = "Restricted Google API reachability must be backed by Phase B Private Google Access and exist only for bounded live execution."
  }
}
check "watchdog_target_set_is_exact" {
  assert {
    condition = toset(local.watchdog_traffic_firewall_names) == (
      local.network_path_armed ? toset([
        local.immutable_names.recova_ingress_firewall,
        local.immutable_names.sip_ingress_firewall,
        local.immutable_names.sip_egress_firewall,
        local.immutable_names.rtp_ingress_firewall,
        local.immutable_names.rtp_egress_firewall,
        local.immutable_names.recova_control_egress_firewall,
        local.immutable_names.recova_media_egress_firewall,
        local.immutable_names.google_out_firewall,
      ]) : toset([])
    )
    error_message = "The watchdog target set must exactly cover every live firewall, including restricted Google egress."
  }
}

check "containment_labels_are_bounded" {
  assert {
    condition = (
      local.labels.application == "recova" &&
      local.labels.environment == "staging" &&
      local.labels.phase == "c-smoke" &&
      local.labels.region == "asia-northeast3" &&
      local.labels.managed_by == "terraform" &&
      length(local.labels.run_id) <= 40
    )
    error_message = "Phase C labels must remain fixed, non-sensitive, and bounded."
  }
}
