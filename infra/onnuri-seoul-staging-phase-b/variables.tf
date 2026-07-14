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
  description = "Future G0-approved RFC1918 /24 for the Seoul subnet."
  type        = string
  nullable    = false

  validation {
    condition = (
      can(cidrhost(var.subnet_ipv4_cidr, 0)) &&
      endswith(var.subnet_ipv4_cidr, "/24") &&
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", var.subnet_ipv4_cidr))
    )
    error_message = "subnet_ipv4_cidr must be an RFC1918 /24."
  }
}

variable "deployer_service_account" {
  description = "G0-gated deployer service-account placeholder; no deployer is authorized in this phase."
  type        = string
  nullable    = false

  validation {
    condition     = var.deployer_service_account == "REPLACE_WITH_G0_APPROVED_DEPLOYER_SERVICE_ACCOUNT"
    error_message = "deployer_service_account must remain the G0-approved placeholder."
  }
}
