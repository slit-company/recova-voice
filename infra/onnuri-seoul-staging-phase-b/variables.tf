variable "project_id" {
  description = "Frozen Phase B project identifier."
  type        = string
  nullable    = false

  validation {
    condition     = var.project_id == "slit-497603"
    error_message = "project_id must remain fixed to slit-497603."
  }
}

variable "region" {
  description = "Frozen Phase B GCP region."
  type        = string
  nullable    = false

  validation {
    condition     = var.region == "asia-northeast3"
    error_message = "region must remain fixed to asia-northeast3."
  }
}

variable "subnet_ipv4_cidr" {
  description = "Approved canonical Seoul subnet CIDR."
  type        = string
  nullable    = false

  validation {
    condition     = var.subnet_ipv4_cidr == "10.73.96.0/24"
    error_message = "subnet_ipv4_cidr must remain fixed to the approved canonical 10.73.96.0/24."
  }
}

variable "deployer_service_account" {
  description = "Approved Phase B deployer service account; this source grants it no resources or roles."
  type        = string
  nullable    = false

  validation {
    condition = (
      trimspace(var.deployer_service_account) == var.deployer_service_account &&
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@slit-497603\\.iam\\.gserviceaccount\\.com$", var.deployer_service_account))
    )
    error_message = "deployer_service_account must be an approved slit-497603 service-account email with a 6-30 character lowercase account ID."
  }
}
