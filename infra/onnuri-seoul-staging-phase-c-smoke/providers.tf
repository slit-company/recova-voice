provider "google" {
  project                     = var.project_id
  region                      = var.region
  impersonate_service_account = var.deployer_service_account
}
