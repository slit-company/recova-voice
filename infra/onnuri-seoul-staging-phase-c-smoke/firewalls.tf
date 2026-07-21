locals {
  supplier_rtp_cidrs = local.bound_supplier_endpoint == null ? [] : sort(tolist(local.bound_supplier_endpoint.media_ipv4_cidrs))
  remote_rtp_min     = try(local.bound_supplier_endpoint.remote_rtp_udp_port_min, 65535)
  remote_rtp_max     = try(local.bound_supplier_endpoint.remote_rtp_udp_port_max, 65535)
  remote_rtcp_min    = try(local.bound_supplier_endpoint.remote_rtcp_udp_port_min, 65535)
  remote_rtcp_max    = try(local.bound_supplier_endpoint.remote_rtcp_udp_port_max, 65535)
  runtime_targets    = [local.service_account_emails.runtime, local.service_account_emails.boot]
}
resource "google_compute_firewall" "deny_all_ingress" {
  name      = local.immutable_names.deny_all_ingress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "INGRESS"
  priority  = 65534
  disabled  = false

  source_ranges           = ["0.0.0.0/0"]
  target_service_accounts = local.runtime_targets

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = local.immutable_names.deny_all_egress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "EGRESS"
  priority  = 65534
  disabled  = false

  destination_ranges      = ["0.0.0.0/0"]
  target_service_accounts = local.runtime_targets

  deny {
    protocol = "all"
  }

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "recova_f1_https_ingress" {
  name      = local.immutable_names.recova_ingress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "INGRESS"
  priority  = 1100
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  source_ranges           = local.bound_recova_f1_cidrs
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "sip_ingress" {
  count = local.bound_supplier_endpoint == null ? 0 : 1

  name      = local.immutable_names.sip_ingress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "INGRESS"
  priority  = 1110
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  source_ranges           = [local.bound_supplier_endpoint.signaling_ipv4_cidr]
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "udp"
    ports    = [tostring(local.bound_supplier_endpoint.candidate_sip_listen_udp_port)]
  }
}

resource "google_compute_firewall" "sip_egress" {
  count = local.bound_supplier_endpoint == null ? 0 : 1

  name      = local.immutable_names.sip_egress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "EGRESS"
  priority  = 1110
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  destination_ranges      = [local.bound_supplier_endpoint.signaling_ipv4_cidr]
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "udp"
    ports    = [tostring(local.bound_supplier_endpoint.signaling_remote_udp_port)]
  }
}

resource "google_compute_firewall" "rtp_ingress" {
  count = local.bound_supplier_endpoint == null || local.bound_host_policy == null ? 0 : 1

  name      = local.immutable_names.rtp_ingress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "INGRESS"
  priority  = 1120
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  source_ranges           = local.supplier_rtp_cidrs
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "udp"
    ports = [
      "${local.baked_local_media_udp_port_min}-${local.baked_local_media_udp_port_max}",
    ]
  }
}

resource "google_compute_firewall" "rtp_egress" {
  count = local.bound_supplier_endpoint == null || local.bound_host_policy == null ? 0 : 1

  name      = local.immutable_names.rtp_egress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "EGRESS"
  priority  = 1120
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  destination_ranges      = local.supplier_rtp_cidrs
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "udp"
    ports = [
      "${local.remote_rtp_min}-${local.remote_rtp_max}",
      "${local.remote_rtcp_min}-${local.remote_rtcp_max}",
    ]
  }
}

resource "google_compute_firewall" "facade_f2_f12_egress" {
  count = local.bound_recova_destination == null ? 0 : 1

  name      = local.immutable_names.recova_control_egress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "EGRESS"
  priority  = 1200
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]
  description = "Exact preverified private F2/F12 control/status TCP/443 destinations."

  destination_ranges      = sort(tolist(local.bound_recova_destination.control_ipv4_cidrs))
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "facade_wss_egress" {
  count = local.bound_recova_destination == null ? 0 : 1

  name      = local.immutable_names.recova_media_egress_firewall
  project   = var.project_id
  network   = var.phase_b_dependency.network_self_link
  direction = "EGRESS"
  priority  = 1210
  disabled  = !local.bounded_live_ready
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]
  description = "Exact preverified private F3 media WSS TCP/443 destinations."

  destination_ranges      = sort(tolist(local.bound_recova_destination.media_ipv4_cidrs))
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "restricted_google_egress" {
  count = local.bounded_live_ready ? 1 : 0

  name        = local.immutable_names.google_out_firewall
  project     = var.project_id
  network     = var.phase_b_dependency.network_self_link
  direction   = "EGRESS"
  priority    = 1220
  disabled    = !local.bounded_live_ready
  description = "Exact restricted.googleapis.com VIP for numeric-version Secret Manager startup; no NAT or other Google API egress."

  destination_ranges      = [local.restricted_google_api_vip_cidr]
  target_service_accounts = [local.service_account_emails.runtime]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  lifecycle {
    precondition {
      condition = !local.bounded_live_ready || (
        local.phase_c_live_plan_verified &&
        local.g008_secrets_ready &&
        local.phase_b_private_google_access_ready &&
        !local.kill_switch
      )
      error_message = "Restricted Google API egress requires live cryptographic verification, exact secret bindings, Private Google Access, and the active watchdog-protected window."
    }
  }
}

resource "google_compute_firewall" "logging_egress" {
  count = 0

  name        = "${local.name_stem}-logging-out"
  project     = var.project_id
  network     = var.phase_b_dependency.network_self_link
  direction   = "EGRESS"
  priority    = 1230
  disabled    = true
  description = "Named logging egress remains disabled and has no workload target in G001."

  destination_ranges      = ["192.0.2.0/32"]
  target_service_accounts = [google_service_account.logging.email]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "image_egress" {
  count = 0

  name        = "${local.name_stem}-image-out"
  project     = var.project_id
  network     = var.phase_b_dependency.network_self_link
  direction   = "EGRESS"
  priority    = 1240
  disabled    = true
  description = "Named image egress remains disabled and has no workload target in G001."

  destination_ranges      = ["192.0.2.0/32"]
  target_service_accounts = [google_service_account.logging.email]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

check "firewall_gate_alignment" {
  assert {
    condition = (
      google_compute_firewall.recova_f1_https_ingress.disabled == !local.bounded_live_ready &&
      try(
        google_compute_firewall.sip_ingress[0].disabled == !local.bounded_live_ready &&
        google_compute_firewall.sip_egress[0].disabled == !local.bounded_live_ready,
        var.supplier_endpoint_binding == null,
      ) &&
      try(
        google_compute_firewall.rtp_ingress[0].disabled == !local.bounded_live_ready &&
        google_compute_firewall.rtp_egress[0].disabled == !local.bounded_live_ready,
        var.supplier_endpoint_binding == null,
      ) &&
      try(
        google_compute_firewall.facade_f2_f12_egress[0].disabled == !local.bounded_live_ready &&
        google_compute_firewall.facade_wss_egress[0].disabled == !local.bounded_live_ready,
        var.recova_destination_receipt == null,
      ) &&
      try(
        google_compute_firewall.restricted_google_egress[0].disabled == !local.bounded_live_ready &&
        google_compute_firewall.restricted_google_egress[0].destination_ranges == toset(["199.36.153.4/30"]) &&
        google_compute_firewall.restricted_google_egress[0].target_service_accounts == toset([local.service_account_emails.runtime]),
        !local.bounded_live_ready,
      ) &&
      (!local.network_path_armed || (
        var.supplier_endpoint_binding != null &&
        var.host_policy_receipt != null &&
        var.activation_receipt != null
      ))
    )
    error_message = "Every allow rule must remain disabled until the complete bounded-live gate and exact supplier, host-policy, Recova, and activation bindings are ready."
  }
}

check "unvalidated_egress_is_absent_and_google_egress_is_exact" {
  assert {
    condition = (
      (var.recova_destination_receipt != null || (
        length(google_compute_firewall.facade_f2_f12_egress) == 0 &&
        length(google_compute_firewall.facade_wss_egress) == 0
      )) &&
      length(google_compute_firewall.restricted_google_egress) == (local.bounded_live_ready ? 1 : 0) &&
      try(
        length(google_compute_firewall.restricted_google_egress[0].destination_ranges) == 1 &&
        contains(google_compute_firewall.restricted_google_egress[0].destination_ranges, "199.36.153.4/30") &&
        one(google_compute_firewall.restricted_google_egress[0].allow).protocol == "tcp" &&
        length(one(google_compute_firewall.restricted_google_egress[0].allow).ports) == 1 &&
        contains(one(google_compute_firewall.restricted_google_egress[0].allow).ports, "443") &&
        length(google_compute_firewall.restricted_google_egress[0].target_service_accounts) == 1 &&
        contains(google_compute_firewall.restricted_google_egress[0].target_service_accounts, local.service_account_emails.runtime),
        !local.bounded_live_ready,
      ) &&
      length(google_compute_firewall.logging_egress) == 0 &&
      length(google_compute_firewall.image_egress) == 0
    )
    error_message = "F2/F12 and F3 must be exact-receipt-bound; the sole Google API path is restricted.googleapis.com /30 TCP/443 and logging/image egress remain absent."
  }
}

check "no_broad_allowlist_cidrs" {
  assert {
    condition = (
      alltrue([for cidr in var.recova_f1_source_cidrs : tonumber(split("/", cidr)[1]) == 32]) &&
      (var.supplier_endpoint_binding == null ? true : alltrue([
        for cidr in var.supplier_endpoint_binding.media_ipv4_cidrs :
        tonumber(split("/", cidr)[1]) >= 24 && cidr != "0.0.0.0/0"
      ])) &&
      (var.recova_destination_receipt == null ? true : alltrue([
        for cidr in setunion(var.recova_destination_receipt.control_ipv4_cidrs, var.recova_destination_receipt.media_ipv4_cidrs) :
        tonumber(split("/", cidr)[1]) == 32
      ]))
    )
    error_message = "F1/control/media destinations must be exact /32s and supplier media CIDRs must remain canonical /24-/32 values."
  }
}

check "host_firewall_sdp_contract" {
  assert {
    condition = !local.network_path_armed || (
      var.host_policy_receipt != null &&
      var.candidate_local_rtp_port_min == local.baked_local_media_udp_port_min &&
      var.candidate_local_rtp_port_max == local.baked_local_media_udp_port_max &&
      var.candidate_local_rtcp_port_min == local.baked_local_media_udp_port_min &&
      var.candidate_local_rtcp_port_max == local.baked_local_media_udp_port_max &&
      var.host_policy_receipt.candidate_local_rtp_port_min == local.baked_local_media_udp_port_min &&
      var.host_policy_receipt.candidate_local_rtp_port_max == local.baked_local_media_udp_port_max &&
      var.host_policy_receipt.candidate_local_rtcp_port_min == local.baked_local_media_udp_port_min &&
      var.host_policy_receipt.candidate_local_rtcp_port_max == local.baked_local_media_udp_port_max
    )
    error_message = "Arm/live requires an exact runtime-bound local RTP/RTCP pool and matching preverified immutable host-policy receipt."
  }
}
