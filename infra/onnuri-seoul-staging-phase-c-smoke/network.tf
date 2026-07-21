locals {
  phase_b_private_google_access_ready = var.phase_b_dependency.private_ip_google_access
  restricted_google_api_vip_cidr      = "199.36.153.4/30"
}

resource "google_compute_address" "candidate" {
  name         = local.immutable_names.address
  project      = var.project_id
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = var.phase_b_dependency.subnet_self_link
  description  = "Phase C candidate private address; the separately gated external reservation is managed independently."

  lifecycle {
    precondition {
      condition = (
        var.phase_b_dependency.project_id == var.project_id &&
        var.phase_b_dependency.region == var.region &&
        var.phase_b_dependency.network_self_link == "https://www.googleapis.com/compute/v1/projects/${var.project_id}/global/networks/recova-onnuri-phase-b-vpc" &&
        var.phase_b_dependency.subnet_self_link == "https://www.googleapis.com/compute/v1/projects/${var.project_id}/regions/${var.region}/subnetworks/recova-onnuri-phase-b-subnet-seoul" &&
        var.phase_b_dependency.subnet_ipv4_cidr == var.candidate_subnet_ipv4_cidr &&
        var.phase_b_dependency.ingress_deny_rule_name == "recova-onnuri-phase-b-deny-ingress" &&
        var.phase_b_dependency.egress_deny_rule_name == "recova-onnuri-phase-b-deny-egress" &&
        local.phase_b_manifest_time_valid
      )
      error_message = "Phase C requires the current, exact leader-validated Phase B network manifest."
    }
    precondition {
      condition     = !local.bounded_live_ready || local.phase_b_private_google_access_ready
      error_message = "Exact-version Secret Manager startup requires Phase B Private Google Access; Cloud NAT or public API egress is prohibited."
    }
    precondition {
      condition     = local.destroy_deadline_valid && !local.destroy_due && var.cost_ceiling_krw == 50000
      error_message = "The destroy deadline must be exactly 24 hours after apply, remain in the future, and preserve the KRW 50,000 ceiling."
    }
    precondition {
      condition = (
        (!local.sip_ready || local.g2_prerequisites_ready) &&
        (!local.rtp_ready || local.sip_ready) &&
        (!local.outbound_live_enabled || local.rtp_ready) &&
        (!local.inbound_live_enabled || local.rtp_ready)
      )
      error_message = "SIP, RTP, outbound, and inbound readiness must advance only through their explicit prerequisite chain."
    }
    precondition {
      condition     = !local.g008_external_iam_live_requested || local.g008_external_iam_receipt_ready
      error_message = "Any live authority requires a fresh, independently verified external G008 IAM receipt bound to the exact bootstrap manifest, principals, activation, candidate, run, and approved live window."
    }
    precondition {
      condition     = !local.any_live_enabled || local.bounded_live_ready
      error_message = "Outbound or inbound traffic may be enabled only by complete bounded-live readiness, including the exact four-stage, no-retry, one-active, 60-second authority."
    }

    precondition {
      condition = (
        local.containment_contract.traffic_authority != "disabled" ||
        local.g2_disabled_boot_authority_valid ||
        local.armed_off_ready ||
        local.control_phase_ready ||
        local.bounded_live_ready ||
        (
          local.external_ip_reserved &&
          !var.network_path_arm_gate &&
          !var.control_readiness_gate &&
          !var.cost_gate &&
          !var.live_window_gate &&
          !var.sip_register_gate &&
          !var.rtp_gate &&
          !var.outbound_call_gate &&
          !var.inbound_call_gate
        )
      )
      error_message = "Disabled G2 boot allows only verified disabled, reservation, armed-off, control, or fully bounded-live states; partial authority is rejected."
    }
    precondition {
      condition = (
        local.containment_contract.ttl_hours == 24 &&
        local.destroy_deadline_valid &&
        local.containment_contract.cost_ceiling_krw == 50000 &&
        local.containment_contract.traffic_authority == (local.any_live_enabled ? "separately-approved-live" : "disabled") &&
        local.containment_contract.phase_b_mutation_authority == "none" &&
        local.containment_contract.phase_b_destroy_authority == "none" &&
        local.containment_contract.automatic_application_retries == 0 &&
        local.containment_contract.maximum_attempts == 3 &&
        local.containment_contract.maximum_active_attempts == 1 &&
        local.containment_contract.maximum_media_seconds == 60 &&
        local.default_disabled == !local.any_live_enabled &&
        local.kill_switch == (!local.any_live_enabled || !local.live_window_active || !local.cost_evidence_valid)
      )
      error_message = "Phase C containment must preserve kill, Phase-B independence, and the maximum-three-call, one-active, 60-second, 24-hour, KRW 50,000 bounds."
    }

  }
}

resource "google_compute_address" "candidate_external" {
  count = var.external_ip_reservation_gate ? 1 : 0

  name         = "${local.name_stem}-external"
  project      = var.project_id
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
  ip_version   = "IPV4"
  description  = "Phase C supplier-bound external IPv4 reservation; reservation alone carries no traffic."

  lifecycle {
    precondition {
      condition = (
        local.external_ip_reserved &&
        var.prearm_inventory_receipt != null &&
        var.prearm_inventory_receipt.run_id == var.run_id &&
        var.prearm_inventory_receipt.project_id == var.project_id &&
        var.prearm_inventory_receipt.network_self_link == var.phase_b_dependency.network_self_link &&
        var.prearm_inventory_receipt.phase_b_manifest_sha256 == var.phase_b_dependency.manifest_sha256 &&
        timecmp(var.prearm_inventory_receipt.issued_at_utc, plantimestamp()) <= 0 &&
        timecmp(var.prearm_inventory_receipt.expires_at_utc, plantimestamp()) > 0 &&
        var.prearm_inventory_receipt.external_address_count == 0 &&
        var.prearm_inventory_receipt.access_config_count == 0 &&
        var.prearm_inventory_receipt.prohibited_connectivity_count == 0
      )
      error_message = "External reservation requires a current preverified pre-arm inventory proving the exact Phase B identity and zero existing public or prohibited connectivity."
    }

    precondition {
      condition     = !var.network_path_arm_gate || local.network_path_ready
      error_message = "Attachment authority requires every exact supplier, host-policy, Recova destination, and activation binding; reservation remains non-traffic otherwise."
    }
  }
}


check "restricted_google_api_path_is_private" {
  assert {
    condition = (
      !local.bounded_live_ready ||
      (
        local.phase_b_private_google_access_ready &&
        local.restricted_google_api_vip_cidr == "199.36.153.4/30"
      )
    )
    error_message = "The live one-shot may reach Google APIs only through Private Google Access and the restricted.googleapis.com /30."
  }
}
