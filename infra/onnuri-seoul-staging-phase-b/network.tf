resource "google_compute_network" "phase_b" {
  name                            = "recova-onnuri-phase-b-vpc"
  auto_create_subnetworks         = false
  routing_mode                    = "REGIONAL"
  delete_default_routes_on_create = true
  enable_ula_internal_ipv6        = false
  description                     = "Phase B foundation; no live traffic is enabled."
}

resource "google_compute_subnetwork" "phase_b" {
  name                     = "recova-onnuri-phase-b-subnet-seoul"
  region                   = "asia-northeast3"
  network                  = google_compute_network.phase_b.id
  ip_cidr_range            = var.subnet_ipv4_cidr
  private_ip_google_access = false
  stack_type               = "IPV4_ONLY"
}
