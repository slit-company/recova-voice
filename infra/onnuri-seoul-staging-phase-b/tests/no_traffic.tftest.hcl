run "no_traffic_graph" {
  command = plan

  variables {
    project_id       = "phase-b-g0-pending"
    subnet_ipv4_cidr = "10.0.0.0/24"
  }

  assert {
    condition     = google_compute_network.phase_b.auto_create_subnetworks == false && google_compute_network.phase_b.routing_mode == "REGIONAL" && google_compute_network.phase_b.delete_default_routes_on_create == true && google_compute_network.phase_b.enable_ula_internal_ipv6 == false
    error_message = "The Phase B network must remain an empty custom regional IPv4 foundation."
  }

  assert {
    condition     = google_compute_subnetwork.phase_b.region == "asia-northeast3" && google_compute_subnetwork.phase_b.stack_type == "IPV4_ONLY" && google_compute_subnetwork.phase_b.private_ip_google_access == false
    error_message = "The Phase B subnet must remain Seoul IPv4-only without private Google access."
  }

  assert {
    condition     = google_compute_firewall.deny_all_ingress.direction == "INGRESS" && google_compute_firewall.deny_all_ingress.priority == 65534 && google_compute_firewall.deny_all_ingress.source_ranges == ["0.0.0.0/0"] && google_compute_firewall.deny_all_ingress.deny[0].protocol == "all"
    error_message = "Ingress must be a targetless all-protocol deny rule."
  }

  assert {
    condition     = google_compute_firewall.deny_all_egress.direction == "EGRESS" && google_compute_firewall.deny_all_egress.priority == 65534 && google_compute_firewall.deny_all_egress.destination_ranges == ["0.0.0.0/0"] && google_compute_firewall.deny_all_egress.deny[0].protocol == "all"
    error_message = "Egress must be a targetless all-protocol deny rule."
  }
}
