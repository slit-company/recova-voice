resource "google_compute_firewall" "deny_all_ingress" {
  name      = "recova-onnuri-phase-b-deny-ingress"
  network   = google_compute_network.phase_b.id
  direction = "INGRESS"
  priority  = 65534

  source_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}

resource "google_compute_firewall" "deny_all_egress" {
  name      = "recova-onnuri-phase-b-deny-egress"
  network   = google_compute_network.phase_b.id
  direction = "EGRESS"
  priority  = 65534

  destination_ranges = ["0.0.0.0/0"]

  deny {
    protocol = "all"
  }
}
