output "project_id" {
  description = "Phase B project identifier for the leader-signed dependency manifest."
  value       = var.project_id
  sensitive   = false
}

output "region" {
  description = "Phase B region for the leader-signed dependency manifest."
  value       = var.region
  sensitive   = false
}

output "network_self_link" {
  description = "Phase B VPC canonical self link for the leader-signed dependency manifest."
  value       = google_compute_network.phase_b.self_link
  sensitive   = false
}

output "subnet_self_link" {
  description = "Phase B subnet canonical self link for the leader-signed dependency manifest."
  value       = google_compute_subnetwork.phase_b.self_link
  sensitive   = false
}

output "subnet_ipv4_cidr" {
  description = "Phase B subnet CIDR for the leader-signed dependency manifest."
  value       = google_compute_subnetwork.phase_b.ip_cidr_range
  sensitive   = false
}
output "private_ip_google_access" {
  description = "Whether the Phase B subnet permits private Google API access."
  value       = google_compute_subnetwork.phase_b.private_ip_google_access
  sensitive   = false
}

output "ingress_deny_rule_name" {
  description = "Phase B ingress deny-rule name for the leader-signed dependency manifest."
  value       = google_compute_firewall.deny_all_ingress.name
  sensitive   = false
}

output "ingress_deny_rule_self_link" {
  description = "Phase B ingress deny-rule canonical self link for the leader-signed dependency manifest."
  value       = google_compute_firewall.deny_all_ingress.self_link
  sensitive   = false
}

output "egress_deny_rule_name" {
  description = "Phase B egress deny-rule name for the leader-signed dependency manifest."
  value       = google_compute_firewall.deny_all_egress.name
  sensitive   = false
}

output "egress_deny_rule_self_link" {
  description = "Phase B egress deny-rule canonical self link for the leader-signed dependency manifest."
  value       = google_compute_firewall.deny_all_egress.self_link
  sensitive   = false
}

output "source_contract_version" {
  description = "Version of the non-sensitive Phase B source handoff contract."
  value       = "phase-b-source-contract-v1"
  sensitive   = false
}