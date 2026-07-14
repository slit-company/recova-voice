variable "project_id" {
  description = "Future G0-approved project identifier; no value is supplied by this source-only phase."
  type        = string
  nullable    = false

  validation {
    condition     = trimspace(var.project_id) != ""
    error_message = "project_id must be supplied only after the G0 approval gate."
  }
}

variable "subnet_ipv4_cidr" {
  description = "Future G0-approved RFC1918 /24 for the Seoul subnet; no value is supplied by this source-only phase."
  type        = string
  nullable    = false

  validation {
    condition = (
      can(cidrhost(var.subnet_ipv4_cidr, 0)) &&
      tonumber(split("/", var.subnet_ipv4_cidr)[1]) == 24 &&
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", cidrhost(var.subnet_ipv4_cidr, 0)))
    )
    error_message = "subnet_ipv4_cidr must be a G0-approved RFC1918 /24."
  }
}
