variable "project_id" {
  description = "Frozen Phase C GCP project identifier."
  type        = string
  default     = "slit-497603"
  nullable    = false

  validation {
    condition     = var.project_id == "slit-497603"
    error_message = "project_id must remain fixed to slit-497603."
  }
}

variable "region" {
  description = "Frozen Phase C GCP region."
  type        = string
  default     = "asia-northeast3"
  nullable    = false

  validation {
    condition     = var.region == "asia-northeast3"
    error_message = "region must remain fixed to asia-northeast3."
  }
}

variable "phase_c_live_preflight_bundle_path" {
  description = "Local path to the untrusted canonical redacted Phase C live-preflight bundle; null disables all cryptographic verification and live authority."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.phase_c_live_preflight_bundle_path == null ? true : length(trimspace(var.phase_c_live_preflight_bundle_path)) > 0
    error_message = "phase_c_live_preflight_bundle_path must be null or a non-empty local path."
  }
}

variable "provider_redacted_claims" {
  description = "Redacted provider credit claims bound by the signed provider prerequisite; null keeps live authority disabled."
  type = object({
    provider_id_digest = string
    account_id_digest  = string
    currency           = string
    starting_balance   = string
    evidence_sha256    = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.provider_redacted_claims == null ? true : (
      alltrue([
        for digest in [
          var.provider_redacted_claims.provider_id_digest,
          var.provider_redacted_claims.account_id_digest,
          var.provider_redacted_claims.evidence_sha256,
        ] : can(regex("^[0-9a-f]{64}$", digest))
      ]) &&
      var.provider_redacted_claims.currency == "KRW" &&
      can(regex("^(0|[1-9][0-9]*)(\\.[0-9]*[1-9])?$", var.provider_redacted_claims.starting_balance))
    )
    error_message = "provider_redacted_claims must contain only canonical redacted SHA-256 identities, KRW, a canonical nonnegative balance, and evidence digest."
  }
}

variable "candidate_subnet_ipv4_cidr" {
  description = "Leader-validated candidate /24; the default is not collision approval."
  type        = string
  default     = "10.73.96.0/24"
  nullable    = false

  validation {
    condition = (
      can(cidrhost(var.candidate_subnet_ipv4_cidr, 0)) &&
      endswith(var.candidate_subnet_ipv4_cidr, "/24") &&
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", var.candidate_subnet_ipv4_cidr)) &&
      try(cidrhost(var.candidate_subnet_ipv4_cidr, 0), "invalid") == try(split("/", var.candidate_subnet_ipv4_cidr)[0], "")
    )
    error_message = "candidate_subnet_ipv4_cidr must be a canonical RFC1918 /24."
  }
}

variable "deployer_service_account" {
  description = "Approved Phase C deployer identity; credentials are never Terraform inputs."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]@slit-497603\\.iam\\.gserviceaccount\\.com$", var.deployer_service_account))
    error_message = "deployer_service_account must be a service account in slit-497603."
  }
}

variable "run_id" {
  description = "Immutable lowercase run identifier used in Phase C names and labels."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{5,39}$", var.run_id)) && !endswith(var.run_id, "-")
    error_message = "run_id must be 6-40 lowercase letters, digits, or hyphens and must start with a letter and end alphanumerically."
  }
}

variable "apply_timestamp_utc" {
  description = "Immutable RFC3339 UTC timestamp recorded for the authorized Phase C apply."
  type        = string
  nullable    = false

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.apply_timestamp_utc)) && can(regex("Z$", var.apply_timestamp_utc))
    error_message = "apply_timestamp_utc must be an RFC3339 UTC timestamp ending in Z."
  }
}

variable "destroy_deadline_utc" {
  description = "Immutable RFC3339 UTC deadline, exactly 24 hours after apply_timestamp_utc."
  type        = string
  nullable    = false

  validation {
    condition     = can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.destroy_deadline_utc)) && can(regex("Z$", var.destroy_deadline_utc))
    error_message = "destroy_deadline_utc must be an RFC3339 UTC timestamp ending in Z."
  }
}

variable "live_window_start_utc" {
  description = "Approved REGISTER/call window start; null keeps live traffic disabled."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.live_window_start_utc == null ? true : can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.live_window_start_utc)) && can(regex("Z$", var.live_window_start_utc))
    error_message = "live_window_start_utc must be null or an RFC3339 UTC timestamp ending in Z."
  }
}

variable "live_window_end_utc" {
  description = "Approved REGISTER/call window end; null keeps live traffic disabled."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.live_window_end_utc == null ? true : can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.live_window_end_utc)) && can(regex("Z$", var.live_window_end_utc))
    error_message = "live_window_end_utc must be null or an RFC3339 UTC timestamp ending in Z."
  }
}

variable "cost_ceiling_krw" {
  description = "Immutable all-in Phase C ceiling in KRW."
  type        = number
  default     = 50000
  nullable    = false

  validation {
    condition     = var.cost_ceiling_krw == 50000
    error_message = "cost_ceiling_krw must remain exactly KRW 50,000."
  }
}

variable "cost_evidence" {
  description = "Current signed cost estimate/observation; null keeps live traffic disabled."
  type = object({
    estimated_total_krw = number
    observed_total_krw  = number
    recorded_at_utc     = string
    expires_at_utc      = string
    evidence_sha256     = string
    signer_key_id       = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.cost_evidence == null ? true : (
      var.cost_evidence.estimated_total_krw >= 0 &&
      var.cost_evidence.observed_total_krw >= 0 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.cost_evidence.recorded_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.cost_evidence.expires_at_utc)) &&
      try(timecmp(var.cost_evidence.expires_at_utc, var.cost_evidence.recorded_at_utc) > 0, false) &&
      can(regex("^[0-9a-f]{64}$", var.cost_evidence.evidence_sha256)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.cost_evidence.signer_key_id))
    )
    error_message = "cost_evidence must contain nonnegative KRW values, bounded RFC3339 recording and expiry times, a SHA-256 digest, and signer key ID."
  }
}

variable "phase_b_dependency" {
  description = "Leader-validated, signed immutable Phase B manifest values. This is not remote state."
  type = object({
    manifest_sha256              = string
    signature_base64             = string
    signer_key_id                = string
    verification_receipt_sha256  = string
    project_id                   = string
    region                       = string
    network_self_link            = string
    subnet_self_link             = string
    subnet_ipv4_cidr             = string
    private_ip_google_access     = bool
    ingress_deny_rule_name       = string
    egress_deny_rule_name        = string
    phase_b_source_sha256        = string
    backend_identity             = string
    backend_generation           = number
    backend_serial               = number
    canonical_state_sha256       = string
    non_sensitive_outputs_sha256 = string
    issued_at_utc                = string
    expires_at_utc               = string
  })
  nullable = false

  validation {
    condition = (
      var.phase_b_dependency.project_id == "slit-497603" &&
      var.phase_b_dependency.region == "asia-northeast3" &&
      can(regex("^https://www\\.googleapis\\.com/compute/v1/projects/slit-497603/global/networks/[a-z][a-z0-9-]{0,62}$", var.phase_b_dependency.network_self_link)) &&
      can(regex("^https://www\\.googleapis\\.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/[a-z][a-z0-9-]{0,62}$", var.phase_b_dependency.subnet_self_link)) &&
      var.phase_b_dependency.subnet_ipv4_cidr == var.candidate_subnet_ipv4_cidr &&
      var.phase_b_dependency.private_ip_google_access &&
      can(regex("^[a-z][a-z0-9-]{0,62}$", var.phase_b_dependency.ingress_deny_rule_name)) &&
      can(regex("^[a-z][a-z0-9-]{0,62}$", var.phase_b_dependency.egress_deny_rule_name)) &&
      var.phase_b_dependency.ingress_deny_rule_name != var.phase_b_dependency.egress_deny_rule_name &&
      can(regex("^[0-9a-f]{64}$", var.phase_b_dependency.manifest_sha256)) &&
      can(regex("^[A-Za-z0-9+/]+={0,2}$", var.phase_b_dependency.signature_base64)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.phase_b_dependency.signer_key_id)) &&
      can(regex("^[0-9a-f]{64}$", var.phase_b_dependency.verification_receipt_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.phase_b_dependency.phase_b_source_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.phase_b_dependency.canonical_state_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.phase_b_dependency.non_sensitive_outputs_sha256)) &&
      can(regex("^gcs://[a-z0-9][a-z0-9._-]{2,221}/[A-Za-z0-9._/-]+$", var.phase_b_dependency.backend_identity)) &&
      floor(var.phase_b_dependency.backend_generation) == var.phase_b_dependency.backend_generation && var.phase_b_dependency.backend_generation > 0 &&
      floor(var.phase_b_dependency.backend_serial) == var.phase_b_dependency.backend_serial && var.phase_b_dependency.backend_serial >= 0 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.phase_b_dependency.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.phase_b_dependency.expires_at_utc))
    )
    error_message = "phase_b_dependency must be the exact signed Seoul Phase B manifest with canonical links, positive generation, immutable hashes, and valid timestamps."
  }
}

variable "g009_candidate_receipt" {
  description = "Externally verified G009 candidate receipt; it pins one immutable runtime image and its facade binding without trust booleans or defaults."
  type = object({
    image_self_link                           = string
    image_id                                  = number
    image_generation                          = number
    source_sha256                             = string
    export_sha256                             = string
    derivative_sha256                         = string
    runtime_image_digest                      = string
    facade_image_digest                       = string
    candidate_manifest_sha256                 = string
    candidate_receipt_sha256                  = string
    candidate_receipt_signature_base64        = string
    candidate_receipt_signer_key_id           = string
    candidate_receipt_verification_key_sha256 = string
    execution_runner_receipt_sha256           = optional(string)
    candidate_receipt_issued_at_utc           = string
    candidate_receipt_expires_at_utc          = string
  })
  nullable = false

  validation {
    condition = (
      can(regex("^https://www\\.googleapis\\.com/compute/v1/projects/slit-497603/global/images/[a-z][a-z0-9-]{0,62}$", var.g009_candidate_receipt.image_self_link)) &&
      !strcontains(lower(var.g009_candidate_receipt.image_self_link), "g006") &&
      floor(var.g009_candidate_receipt.image_id) == var.g009_candidate_receipt.image_id &&
      var.g009_candidate_receipt.image_id > 0 &&
      floor(var.g009_candidate_receipt.image_generation) == var.g009_candidate_receipt.image_generation &&
      var.g009_candidate_receipt.image_generation > 0 &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.source_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.export_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.derivative_sha256)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.g009_candidate_receipt.runtime_image_digest)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.g009_candidate_receipt.facade_image_digest)) &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.candidate_manifest_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.candidate_receipt_sha256)) &&
      (
        try(var.g009_candidate_receipt.execution_runner_receipt_sha256 == null, true) ||
        try(can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.execution_runner_receipt_sha256)), false)
      ) &&
      can(regex("^[A-Za-z0-9+/]+={0,2}$", var.g009_candidate_receipt.candidate_receipt_signature_base64)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.g009_candidate_receipt.candidate_receipt_signer_key_id)) &&
      !strcontains(lower(var.g009_candidate_receipt.candidate_receipt_signer_key_id), "g006") &&
      can(regex("^[0-9a-f]{64}$", var.g009_candidate_receipt.candidate_receipt_verification_key_sha256)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g009_candidate_receipt.candidate_receipt_issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g009_candidate_receipt.candidate_receipt_expires_at_utc))
    )
    error_message = "g009_candidate_receipt must pin a non-G006 slit-497603 image, signed receipt, verification key fingerprint, manifest, runtime/facade digests, and an optional baked execution-runner receipt digest."
  }
}

variable "candidate_manifest" {
  description = "G-1 approved immutable stock/facade candidate; values are required immutable inputs, never defaults."
  type = object({
    release_id             = string
    source_sha256          = string
    image_digest           = string
    facade_image_digest    = string
    sbom_sha256            = string
    license_sha256         = string
    manifest_sha256        = string
    renewed_review_sha256  = string
    review_payload_digest  = string
    review_approval_status = string
    approved_at_utc        = string
  })
  nullable = false

  validation {
    condition = (
      can(regex("^[A-Za-z0-9][A-Za-z0-9._-]{1,127}$", var.candidate_manifest.release_id)) &&
      !strcontains(lower(var.candidate_manifest.release_id), "g006") &&
      can(regex("^[0-9a-f]{64}$", var.candidate_manifest.source_sha256)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.candidate_manifest.image_digest)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.candidate_manifest.facade_image_digest)) &&
      can(regex("^[0-9a-f]{64}$", var.candidate_manifest.sbom_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.candidate_manifest.license_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.candidate_manifest.manifest_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.candidate_manifest.renewed_review_sha256)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.candidate_manifest.review_payload_digest)) &&
      var.candidate_manifest.review_approval_status == "approved" &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.candidate_manifest.approved_at_utc))
    )
    error_message = "candidate_manifest must contain the exact approved review payload digest and approved status alongside one immutable release and SHA-256 candidate, facade, SBOM, license, manifest, and renewed-review digests."
  }
}

variable "supplier_rtp_evidence" {
  description = "Preverified canonical supplier tuple receipt; null keeps all supplier traffic disabled."
  type = object({
    signaling_ipv4_cidr         = string
    signaling_udp_port          = number
    remote_ipv4_cidrs           = set(string)
    remote_rtp_udp_port_min     = number
    remote_rtp_udp_port_max     = number
    remote_rtcp_udp_port_min    = number
    remote_rtcp_udp_port_max    = number
    max_concurrent_calls        = number
    calls_per_second            = number
    canonical_receipt_sha256    = string
    verification_receipt_sha256 = string
    issued_at_utc               = string
    expires_at_utc              = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.supplier_rtp_evidence == null ? true : (
      can(cidrhost(var.supplier_rtp_evidence.signaling_ipv4_cidr, 0)) &&
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.supplier_rtp_evidence.signaling_ipv4_cidr)) &&
      try(cidrhost(var.supplier_rtp_evidence.signaling_ipv4_cidr, 0), "invalid") == try(split("/", var.supplier_rtp_evidence.signaling_ipv4_cidr)[0], "") &&
      !startswith(var.supplier_rtp_evidence.signaling_ipv4_cidr, "0.") &&
      !startswith(var.supplier_rtp_evidence.signaling_ipv4_cidr, "127.") &&
      !startswith(var.supplier_rtp_evidence.signaling_ipv4_cidr, "169.254.") &&
      try(tonumber(split(".", var.supplier_rtp_evidence.signaling_ipv4_cidr)[0]), 255) < 224 &&
      floor(var.supplier_rtp_evidence.signaling_udp_port) == var.supplier_rtp_evidence.signaling_udp_port &&
      var.supplier_rtp_evidence.signaling_udp_port >= 1 &&
      var.supplier_rtp_evidence.signaling_udp_port <= 65535 &&
      length(var.supplier_rtp_evidence.remote_ipv4_cidrs) > 0 &&
      length(var.supplier_rtp_evidence.remote_ipv4_cidrs) <= 8 &&
      alltrue([for cidr in var.supplier_rtp_evidence.remote_ipv4_cidrs :
        can(cidrhost(cidr, 0)) &&
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/", cidr)) &&
        can(regex("/(2[4-9]|3[0-2])$", cidr)) &&
        try(cidrhost(cidr, 0), "invalid") == try(split("/", cidr)[0], "") &&
        !startswith(cidr, "0.")
      ]) &&
      alltrue([
        for port in [
          var.supplier_rtp_evidence.remote_rtp_udp_port_min,
          var.supplier_rtp_evidence.remote_rtp_udp_port_max,
          var.supplier_rtp_evidence.remote_rtcp_udp_port_min,
          var.supplier_rtp_evidence.remote_rtcp_udp_port_max,
        ] : floor(port) == port && port >= 1 && port <= 65535
      ]) &&
      var.supplier_rtp_evidence.remote_rtp_udp_port_max >= var.supplier_rtp_evidence.remote_rtp_udp_port_min &&
      var.supplier_rtp_evidence.remote_rtcp_udp_port_max >= var.supplier_rtp_evidence.remote_rtcp_udp_port_min &&
      var.supplier_rtp_evidence.remote_rtp_udp_port_max - var.supplier_rtp_evidence.remote_rtp_udp_port_min + 1 <= 100 &&
      var.supplier_rtp_evidence.remote_rtcp_udp_port_max - var.supplier_rtp_evidence.remote_rtcp_udp_port_min + 1 <= 100 &&
      floor(var.supplier_rtp_evidence.max_concurrent_calls) == var.supplier_rtp_evidence.max_concurrent_calls &&
      floor(var.supplier_rtp_evidence.calls_per_second) == var.supplier_rtp_evidence.calls_per_second &&
      var.supplier_rtp_evidence.max_concurrent_calls == 1 &&
      var.supplier_rtp_evidence.calls_per_second == 1 &&
      can(regex("^[0-9a-f]{64}$", var.supplier_rtp_evidence.canonical_receipt_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.supplier_rtp_evidence.verification_receipt_sha256)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.supplier_rtp_evidence.issued_at_utc)) &&
      can(regex("Z$", var.supplier_rtp_evidence.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.supplier_rtp_evidence.expires_at_utc)) &&
      can(regex("Z$", var.supplier_rtp_evidence.expires_at_utc)) &&
      try(timecmp(var.supplier_rtp_evidence.expires_at_utc, var.supplier_rtp_evidence.issued_at_utc), 0) > 0
    )
    error_message = "supplier_rtp_evidence must be a preverified canonical receipt for one safe signaling /32, exact UDP signaling/RTP/RTCP bounds, and limits of one concurrent call and one call per second."
  }
}

variable "candidate_local_rtp_port_min" {
  description = "First runtime-bound candidate-local RTP UDP port; null keeps attachment and media disabled."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition     = var.candidate_local_rtp_port_min == null ? true : var.candidate_local_rtp_port_min == 40000
    error_message = "candidate_local_rtp_port_min must be null or the baked runtime pool start, 40000."
  }
}

variable "candidate_local_rtp_port_max" {
  description = "Last runtime-bound candidate-local RTP UDP port; null keeps attachment and media disabled."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition = var.candidate_local_rtp_port_max == null ? var.candidate_local_rtp_port_min == null : (
      var.candidate_local_rtp_port_min == 40000 &&
      var.candidate_local_rtp_port_max == 40099
    )
    error_message = "The candidate-local RTP pool must be omitted or exactly match the baked runtime pool, 40000-40099."
  }
}

variable "candidate_local_rtcp_port_min" {
  description = "First runtime-bound candidate-local RTCP UDP port; null keeps attachment and media disabled."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition     = var.candidate_local_rtcp_port_min == null ? true : var.candidate_local_rtcp_port_min == 40000
    error_message = "candidate_local_rtcp_port_min must be null or the baked runtime pool start, 40000."
  }
}

variable "candidate_local_rtcp_port_max" {
  description = "Last runtime-bound candidate-local RTCP UDP port; null keeps attachment and media disabled."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition = var.candidate_local_rtcp_port_max == null ? var.candidate_local_rtcp_port_min == null : (
      var.candidate_local_rtcp_port_min == 40000 &&
      var.candidate_local_rtcp_port_max == 40099
    )
    error_message = "The candidate-local RTCP pool must be omitted or exactly match the baked runtime pool, 40000-40099."
  }
}

variable "supplier_signaling_ipv4_cidr" {
  description = "Supplier-receipted signaling IPv4 host route; null keeps SIP resources absent."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition = var.supplier_signaling_ipv4_cidr == null ? true : (
      can(cidrhost(var.supplier_signaling_ipv4_cidr, 0)) &&
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.supplier_signaling_ipv4_cidr)) &&
      try(cidrhost(var.supplier_signaling_ipv4_cidr, 0), "invalid") == try(split("/", var.supplier_signaling_ipv4_cidr)[0], "") &&
      !startswith(var.supplier_signaling_ipv4_cidr, "0.") &&
      !startswith(var.supplier_signaling_ipv4_cidr, "127.") &&
      !startswith(var.supplier_signaling_ipv4_cidr, "169.254.") &&
      try(tonumber(split(".", var.supplier_signaling_ipv4_cidr)[0]), 255) < 224
    )
    error_message = "supplier_signaling_ipv4_cidr must be null or one canonical, safe IPv4 host /32."
  }
}

variable "supplier_signaling_remote_udp_port" {
  description = "Supplier-receipted remote SIP UDP port; it is not the candidate listen port."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition = (
      (var.supplier_signaling_remote_udp_port == null) == (var.supplier_signaling_ipv4_cidr == null) &&
      (var.supplier_signaling_remote_udp_port == null ? true : floor(var.supplier_signaling_remote_udp_port) == var.supplier_signaling_remote_udp_port && var.supplier_signaling_remote_udp_port >= 1 && var.supplier_signaling_remote_udp_port <= 65535)
    )
    error_message = "supplier_signaling_remote_udp_port must be omitted with the signaling host or be an integer from 1 through 65535."
  }
}

variable "candidate_sip_listen_udp_port" {
  description = "Exact candidate-local SIP UDP listen port bound by the host-policy receipt; null keeps attachment and SIP disabled."
  type        = number
  default     = null
  nullable    = true

  validation {
    condition     = var.candidate_sip_listen_udp_port == null ? true : floor(var.candidate_sip_listen_udp_port) == var.candidate_sip_listen_udp_port && var.candidate_sip_listen_udp_port >= 1024 && var.candidate_sip_listen_udp_port <= 65535
    error_message = "candidate_sip_listen_udp_port must be null or an integer from 1024 through 65535."
  }
}

variable "recova_f1_source_cidrs" {
  description = "Approved Recova backend source identities for facade HTTPS; every entry must be one host."
  type        = set(string)
  nullable    = false

  validation {
    condition = length(var.recova_f1_source_cidrs) > 0 && length(var.recova_f1_source_cidrs) <= 8 && alltrue([
      for cidr in var.recova_f1_source_cidrs :
      can(cidrhost(cidr, 0)) && can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", cidr)) && try(cidrhost(cidr, 0), "invalid") == try(split("/", cidr)[0], "") && !startswith(cidr, "0.")
    ])
    error_message = "recova_f1_source_cidrs must contain 1-8 canonical IPv4 /32 identities."
  }
}

variable "recova_f1_mtls_endpoint_path" {
  description = "Exact private F1 mTLS HTTPS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f1_mtls_endpoint_path)) && !strcontains(var.recova_f1_mtls_endpoint_path, "..") && !strcontains(var.recova_f1_mtls_endpoint_path, "@")
    error_message = "recova_f1_mtls_endpoint_path must be one private .internal https:// mTLS endpoint with an explicit path."
  }
}

variable "recova_f2_https_endpoint_path" {
  description = "Exact private F2 HTTPS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f2_https_endpoint_path)) && !strcontains(var.recova_f2_https_endpoint_path, "..") && !strcontains(var.recova_f2_https_endpoint_path, "@")
    error_message = "recova_f2_https_endpoint_path must be one private .internal https:// endpoint with an explicit path."
  }
}

variable "recova_f3_wss_endpoint_path" {
  description = "Exact private F3 WSS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^wss://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f3_wss_endpoint_path)) && !strcontains(var.recova_f3_wss_endpoint_path, "..") && !strcontains(var.recova_f3_wss_endpoint_path, "@")
    error_message = "recova_f3_wss_endpoint_path must be one private .internal wss:// endpoint with an explicit path."
  }
}

variable "recova_f4_https_endpoint_path" {
  description = "Exact private F4 HTTPS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f4_https_endpoint_path)) && !strcontains(var.recova_f4_https_endpoint_path, "..") && !strcontains(var.recova_f4_https_endpoint_path, "@")
    error_message = "recova_f4_https_endpoint_path must be one private .internal https:// endpoint with an explicit path."
  }
}

variable "recova_f5_https_endpoint_path" {
  description = "Exact private F5 HTTPS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f5_https_endpoint_path)) && !strcontains(var.recova_f5_https_endpoint_path, "..") && !strcontains(var.recova_f5_https_endpoint_path, "@")
    error_message = "recova_f5_https_endpoint_path must be one private .internal https:// endpoint with an explicit path."
  }
}

variable "recova_f12_mtls_endpoint_path" {
  description = "Exact private F12 mTLS HTTPS endpoint and path; no public URL is accepted."
  type        = string
  nullable    = false

  validation {
    condition     = can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal(:[0-9]{1,5})?/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.recova_f12_mtls_endpoint_path)) && !strcontains(var.recova_f12_mtls_endpoint_path, "..") && !strcontains(var.recova_f12_mtls_endpoint_path, "@")
    error_message = "recova_f12_mtls_endpoint_path must be one private .internal https:// mTLS endpoint with an explicit path."
  }
}

variable "phase_c_backend_receipt" {
  description = "Receipt for the globally unique Phase C GCS backend configuration supplied outside Terraform variables."
  type = object({
    bucket_name       = string
    prefix            = string
    config_sha256     = string
    bucket_generation = number
    recorded_at_utc   = string
  })
  nullable = false

  validation {
    condition = (
      can(regex("^slit-497603-[a-z0-9][a-z0-9-]{5,42}-tfstate$", var.phase_c_backend_receipt.bucket_name)) &&
      can(regex("^onnuri-seoul-staging-phase-c-smoke/[a-z][a-z0-9-]{5,39}$", var.phase_c_backend_receipt.prefix)) &&
      endswith(var.phase_c_backend_receipt.prefix, var.run_id) &&
      can(regex("^[0-9a-f]{64}$", var.phase_c_backend_receipt.config_sha256)) &&
      floor(var.phase_c_backend_receipt.bucket_generation) == var.phase_c_backend_receipt.bucket_generation &&
      var.phase_c_backend_receipt.bucket_generation > 0 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.phase_c_backend_receipt.recorded_at_utc))
    )
    error_message = "phase_c_backend_receipt must identify an externally supplied, project/run-specific GCS bucket and prefix with immutable config hash and generation."
  }
}

variable "secret_version_resource_names" {
  description = "Runtime secret version resource names only; plaintext secret values are rejected by type and validation."
  type        = map(string)
  nullable    = false
  sensitive   = true

  validation {
    condition = (
      toset(keys(var.secret_version_resource_names)) == toset([
        "sip_password",
        "f12_endpoint_credential",
        "f12_mtls_certificate",
        "facade_adapter_credential",
        "callback_hmac_key",
        "tls_private_key",
        "stock_local_api_credential",
      ]) &&
      alltrue([for ref in values(var.secret_version_resource_names) :
        can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", ref)) &&
        !endswith(ref, "/versions/latest")
      ]) &&
      var.secret_version_resource_names.sip_password == "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/1"
    )
    error_message = "The legacy secret map must contain exactly the seven required keys with canonical numeric Secret Manager version resource names; SIP password must be pinned to onnuri-sip-password-staging version 1."
  }
}

variable "g008_derivative_receipt" {
  description = "Signed G008 Recova derivative receipt binding the exact already-baked backend data-plane images; no image may be resolved or downloaded at startup."
  type = object({
    schema_version = string
    backend = object({
      image_digest   = string
      receipt_sha256 = string
    })
    postgres = object({
      image_digest   = string
      receipt_sha256 = string
    })
    redis = object({
      image_digest   = string
      receipt_sha256 = string
    })
    ingress = object({
      image_digest   = string
      receipt_sha256 = string
    })
    derivative_manifest_sha256      = string
    candidate_manifest_sha256       = string
    receipt_sha256                  = string
    receipt_signature_base64        = string
    receipt_signer_key_id           = string
    receipt_verification_key_sha256 = string
    receipt_issued_at_utc           = string
    receipt_expires_at_utc          = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.g008_derivative_receipt == null ? true : (
      var.g008_derivative_receipt.schema_version == "recova-g008-derivative-v3" &&
      alltrue([
        for component in [
          var.g008_derivative_receipt.backend,
          var.g008_derivative_receipt.postgres,
          var.g008_derivative_receipt.redis,
          var.g008_derivative_receipt.ingress,
        ] :
        can(regex("^sha256:[0-9a-f]{64}$", component.image_digest)) &&
        can(regex("^[0-9a-f]{64}$", component.receipt_sha256))
      ]) &&
      length(toset([
        var.g008_derivative_receipt.backend.image_digest,
        var.g008_derivative_receipt.postgres.image_digest,
        var.g008_derivative_receipt.redis.image_digest,
        var.g008_derivative_receipt.ingress.image_digest,
      ])) == 4 &&
      length(toset([
        var.g008_derivative_receipt.backend.receipt_sha256,
        var.g008_derivative_receipt.postgres.receipt_sha256,
        var.g008_derivative_receipt.redis.receipt_sha256,
        var.g008_derivative_receipt.ingress.receipt_sha256,
      ])) == 4 &&
      can(regex("^[0-9a-f]{64}$", var.g008_derivative_receipt.derivative_manifest_sha256)) &&
      can(regex("^[0-9a-f]{64}$", var.g008_derivative_receipt.candidate_manifest_sha256)) &&
      var.g008_derivative_receipt.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256 &&
      can(regex("^[0-9a-f]{64}$", var.g008_derivative_receipt.receipt_sha256)) &&
      can(regex("^[A-Za-z0-9+/]+={0,2}$", var.g008_derivative_receipt.receipt_signature_base64)) &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.g008_derivative_receipt.receipt_signer_key_id)) &&
      can(regex("^[0-9a-f]{64}$", var.g008_derivative_receipt.receipt_verification_key_sha256)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_derivative_receipt.receipt_issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_derivative_receipt.receipt_expires_at_utc)) &&
      timecmp(var.g008_derivative_receipt.receipt_expires_at_utc, var.g008_derivative_receipt.receipt_issued_at_utc) > 0
    )
    error_message = "g008_derivative_receipt must use recova-g008-derivative-v3 and bind four distinct sha256 images to exact per-image receipts, the G009 candidate manifest, and one signed expiring derivative receipt."
  }
}

variable "g008_authority_binding" {
  description = "Digest-only binding of the exact tenant, account, envelope, and sealed candidate; raw provider values are prohibited."
  type = object({
    tenant_digest    = string
    account_digest   = string
    envelope_digest  = string
    candidate_digest = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.g008_authority_binding == null ? true : alltrue([
      for digest in values(var.g008_authority_binding) :
      can(regex("^[0-9a-f]{64}$", digest))
    ])
    error_message = "g008_authority_binding accepts only exact lowercase SHA-256 digests."
  }

}

variable "g008_f12_contract" {
  description = "Exact private F12 origin/readiness/media identities and independently receipted TLS, mTLS, dispatch, and media ES256 key bindings."
  type = object({
    origin_https_endpoint_path        = string
    readiness_path                    = string
    media_wss_endpoint_path           = string
    endpoint_san                      = string
    tls_certificate_sha256            = string
    mtls_client_certificate_sha256    = string
    mtls_ca_certificate_sha256        = string
    dispatch_algorithm                = string
    dispatch_key_id                   = string
    dispatch_public_key_sha256        = string
    media_algorithm                   = string
    media_key_id                      = string
    media_public_key_sha256           = string
    contract_receipt_sha256           = string
    contract_receipt_signature_base64 = string
    contract_receipt_signer_key_id    = string
    contract_verification_key_sha256  = string
    contract_receipt_issued_at_utc    = string
    contract_receipt_expires_at_utc   = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.g008_f12_contract == null ? true : (
      can(regex("^https://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.g008_f12_contract.origin_https_endpoint_path)) &&
      can(regex("^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.g008_f12_contract.readiness_path)) &&
      can(regex("^wss://[A-Za-z0-9][A-Za-z0-9.-]*\\.internal/[A-Za-z0-9._~!$&'()*+,;=:@%/-]+$", var.g008_f12_contract.media_wss_endpoint_path)) &&
      !strcontains(var.g008_f12_contract.origin_https_endpoint_path, "..") &&
      !strcontains(var.g008_f12_contract.readiness_path, "..") &&
      !strcontains(var.g008_f12_contract.media_wss_endpoint_path, "..") &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9.-]*\\.internal$", var.g008_f12_contract.endpoint_san)) &&
      startswith(var.g008_f12_contract.origin_https_endpoint_path, "https://${var.g008_f12_contract.endpoint_san}/") &&
      startswith(var.g008_f12_contract.media_wss_endpoint_path, "wss://${var.g008_f12_contract.endpoint_san}/") &&
      var.g008_f12_contract.dispatch_algorithm == "ES256" &&
      var.g008_f12_contract.media_algorithm == "ES256" &&
      var.g008_f12_contract.dispatch_key_id != var.g008_f12_contract.media_key_id &&
      alltrue([
        for key_id in [
          var.g008_f12_contract.dispatch_key_id,
          var.g008_f12_contract.media_key_id,
          var.g008_f12_contract.contract_receipt_signer_key_id,
        ] : can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", key_id))
      ]) &&
      alltrue([
        for fingerprint in [
          var.g008_f12_contract.tls_certificate_sha256,
          var.g008_f12_contract.mtls_client_certificate_sha256,
          var.g008_f12_contract.mtls_ca_certificate_sha256,
          var.g008_f12_contract.dispatch_public_key_sha256,
          var.g008_f12_contract.media_public_key_sha256,
          var.g008_f12_contract.contract_receipt_sha256,
          var.g008_f12_contract.contract_verification_key_sha256,
        ] : can(regex("^[0-9a-f]{64}$", fingerprint))
      ]) &&
      can(regex("^[A-Za-z0-9+/]+={0,2}$", var.g008_f12_contract.contract_receipt_signature_base64)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_f12_contract.contract_receipt_issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_f12_contract.contract_receipt_expires_at_utc)) &&
      timecmp(var.g008_f12_contract.contract_receipt_expires_at_utc, var.g008_f12_contract.contract_receipt_issued_at_utc) > 0
    )
    error_message = "g008_f12_contract must bind one private SAN to exact HTTPS/readiness/WSS paths, separate ES256 keys, certificate/key fingerprints, and an independently signed receipt."
  }
}

variable "g008_secret_version_resource_names" {
  description = "Numeric-only purpose-separated Compose runtime secret versions; payloads remain outside Terraform."
  type        = map(string)
  default     = null
  nullable    = true
  sensitive   = true

  validation {
    condition = var.g008_secret_version_resource_names == null ? true : (
      toset(keys(var.g008_secret_version_resource_names)) == toset([
        "postgres_password",
        "redis_password",
        "f12_tls_private_key",
        "f12_tls_certificate",
        "f12_mtls_private_key",
        "f12_mtls_certificate",
        "f12_mtls_ca_certificate",
        "dispatch_es256_private_key",
        "dispatch_es256_public_key",
        "media_es256_private_key",
        "media_es256_public_key",
        "execution_evidence_es256_private_key",
        "execution_evidence_es256_public_key",
        "registration_attestation_es256_private_key",
        "registration_attestation_es256_public_key",
        "authority_recovery_key",
        "mariadb_root_password",
        "webhook_secret",
        "account_api_token",
        "registration_egress_proof",
        "f12_endpoint_credential",
        "registration_f12_endpoint_credential",
        "stock_api_token",
        "jambones_mysql_password",
        "jwt_secret",
        "encryption_secret",
        "drachtio_feature_secret",
        "drachtio_sip_secret",
        "freeswitch_esl_password",
        "execution_request",
        "execution_sip_username",
        "execution_sip_password",
        "execution_sip_realm",
        "execution_target",
        "execution_nonce",
        "operator_credential",
      ]) &&
      alltrue([
        for reference in values(var.g008_secret_version_resource_names) :
        can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", reference)) &&
        !endswith(reference, "/versions/latest")
      ]) &&
      length(toset(values(var.g008_secret_version_resource_names))) == 36
    )
    error_message = "The G008 secret map must contain exactly the twenty-nine runtime purposes plus seven execution purposes, each with a distinct canonical project-local numeric Secret Manager version resource name."
  }
}

variable "g008_bootstrap_manifest_version_resource_name" {
  description = "Exact numeric Secret Manager version containing the sealed bootstrap manifest; distinct from all seven execution payload versions."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true

  validation {
    condition = var.g008_bootstrap_manifest_version_resource_name == null ? true : (
      can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", var.g008_bootstrap_manifest_version_resource_name)) &&
      !endswith(var.g008_bootstrap_manifest_version_resource_name, "/versions/latest")
    )
    error_message = "g008_bootstrap_manifest_version_resource_name must be one exact project-local numeric Secret Manager version."
  }
}
variable "g008_external_iam_provisioning_receipt" {
  description = "Externally issued, independently authenticated, redacted receipt proving the exact bounded G008 IAM policy was applied without broader bindings; no purpose/version inventory is accepted."
  type = object({
    schema_version                            = string
    bootstrap_manifest_binding_sha256         = string
    runtime_service_account_email             = string
    transaction_service_account_email         = string
    live_window_start_utc                     = string
    live_window_end_utc                       = string
    destruction_deadline_utc                  = string
    candidate_manifest_sha256                 = string
    review_payload_digest                     = string
    run_id                                    = string
    activation_nonce_sha256                   = string
    activation_receipt_sha256                 = string
    provisioning_outcome                      = string
    exact_policy_result_sha256                = string
    issuer_key_id                             = string
    issuer_key_fingerprint_sha256             = string
    issued_at_utc                             = string
    expires_at_utc                            = string
    canonical_receipt_sha256                  = string
    cryptographic_verification_receipt_sha256 = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.g008_external_iam_provisioning_receipt == null ? true : (
      var.g008_external_iam_provisioning_receipt.schema_version == "recova-g008-external-iam-provisioning-receipt-v1" &&
      can(regex("^[a-z][a-z0-9-]{0,62}@slit-497603\\.iam\\.gserviceaccount\\.com$", var.g008_external_iam_provisioning_receipt.runtime_service_account_email)) &&
      can(regex("^[a-z][a-z0-9-]{0,62}@slit-497603\\.iam\\.gserviceaccount\\.com$", var.g008_external_iam_provisioning_receipt.transaction_service_account_email)) &&
      var.g008_external_iam_provisioning_receipt.runtime_service_account_email != var.g008_external_iam_provisioning_receipt.transaction_service_account_email &&
      var.g008_external_iam_provisioning_receipt.run_id == var.run_id &&
      var.g008_external_iam_provisioning_receipt.provisioning_outcome == "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS" &&
      can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.g008_external_iam_provisioning_receipt.issuer_key_id)) &&
      alltrue([
        for digest in [
          var.g008_external_iam_provisioning_receipt.bootstrap_manifest_binding_sha256,
          var.g008_external_iam_provisioning_receipt.candidate_manifest_sha256,
          var.g008_external_iam_provisioning_receipt.activation_nonce_sha256,
          var.g008_external_iam_provisioning_receipt.activation_receipt_sha256,
          var.g008_external_iam_provisioning_receipt.exact_policy_result_sha256,
          var.g008_external_iam_provisioning_receipt.issuer_key_fingerprint_sha256,
          var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256,
          var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256,
        ] : can(regex("^[0-9a-f]{64}$", digest))
      ]) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.g008_external_iam_provisioning_receipt.review_payload_digest)) &&
      length(toset([
        var.g008_external_iam_provisioning_receipt.bootstrap_manifest_binding_sha256,
        var.g008_external_iam_provisioning_receipt.exact_policy_result_sha256,
        var.g008_external_iam_provisioning_receipt.issuer_key_fingerprint_sha256,
        var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256,
        var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256,
      ])) == 5 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_external_iam_provisioning_receipt.live_window_start_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_external_iam_provisioning_receipt.live_window_end_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_external_iam_provisioning_receipt.destruction_deadline_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_external_iam_provisioning_receipt.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.g008_external_iam_provisioning_receipt.expires_at_utc)) &&
      timecmp(var.g008_external_iam_provisioning_receipt.live_window_end_utc, var.g008_external_iam_provisioning_receipt.live_window_start_utc) > 0 &&
      timecmp(var.g008_external_iam_provisioning_receipt.destruction_deadline_utc, var.g008_external_iam_provisioning_receipt.live_window_end_utc) >= 0 &&
      timecmp(var.g008_external_iam_provisioning_receipt.expires_at_utc, var.g008_external_iam_provisioning_receipt.issued_at_utc) > 0
    )
    error_message = "g008_external_iam_provisioning_receipt must be a redacted v1 receipt with the exact approved review payload digest, distinct exact-policy, issuer, canonical, verification, and manifest digests, two distinct project-local service accounts, exact context fields, and ordered RFC3339 UTC bounds."
  }
}
variable "g008_external_iam_trusted_issuer_key_id" {
  description = "Out-of-band pinned key ID authorized to verify the external G008 IAM provisioning receipt."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.g008_external_iam_trusted_issuer_key_id == null ? true : can(regex("^[A-Za-z0-9][A-Za-z0-9_./:-]{2,255}$", var.g008_external_iam_trusted_issuer_key_id))
    error_message = "g008_external_iam_trusted_issuer_key_id must be null or a valid out-of-band pinned key ID."
  }
}

variable "g008_external_iam_trusted_issuer_key_fingerprint_sha256" {
  description = "Out-of-band pinned SHA-256 fingerprint for the key that independently verified the external G008 IAM provisioning receipt."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.g008_external_iam_trusted_issuer_key_fingerprint_sha256 == null ? true : can(regex("^[0-9a-f]{64}$", var.g008_external_iam_trusted_issuer_key_fingerprint_sha256))
    error_message = "g008_external_iam_trusted_issuer_key_fingerprint_sha256 must be null or a lowercase SHA-256 digest."
  }
}
variable "g008_execution_trigger" {
  description = "Sole immutable baked-runner trigger: exactly seven execution-purpose numeric versions, canonical source digests, and receipt bindings."
  type = object({
    schema_version                          = string
    execution_request_version_resource_name = string
    sip_username_secret_version             = string
    sip_password_secret_version             = string
    sip_realm_secret_version                = string
    target_secret_version                   = string
    execution_nonce_secret_version          = string
    operator_credential_secret_version      = string
    execution_request_sha256                = string
    sip_username_sha256                     = string
    sip_password_sha256                     = string
    sip_realm_sha256                        = string
    target_sha256                           = string

    execution_nonce_sha256     = string
    operator_credential_sha256 = string
    execution_runner_sha256    = string
    trusted_keyset_sha256      = string
    provider_script_sha256     = string
    candidate_receipt_sha256   = string
    review_payload_digest      = string
    candidate_manifest_sha256  = string
    runtime_image_digest       = string

    execution_runner_receipt_sha256 = string
    activation_receipt_sha256       = string
  })
  default   = null
  nullable  = true
  sensitive = true

  validation {
    condition = var.g008_execution_trigger == null ? true : (
      var.g008_execution_trigger.schema_version == "recova-g008-execution-seal-v1" &&
      alltrue([
        for reference in [
          var.g008_execution_trigger.execution_request_version_resource_name,
          var.g008_execution_trigger.sip_username_secret_version,
          var.g008_execution_trigger.sip_password_secret_version,
          var.g008_execution_trigger.sip_realm_secret_version,
          var.g008_execution_trigger.target_secret_version,
          var.g008_execution_trigger.execution_nonce_secret_version,
          var.g008_execution_trigger.operator_credential_secret_version,
        ] :
        can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", reference)) &&
        !endswith(reference, "/versions/latest")
      ]) &&
      length(toset([
        var.g008_execution_trigger.execution_request_version_resource_name,
        var.g008_execution_trigger.sip_username_secret_version,
        var.g008_execution_trigger.sip_password_secret_version,
        var.g008_execution_trigger.sip_realm_secret_version,
        var.g008_execution_trigger.target_secret_version,
        var.g008_execution_trigger.execution_nonce_secret_version,
        var.g008_execution_trigger.operator_credential_secret_version,
      ])) == 7 &&
      var.g008_bootstrap_manifest_version_resource_name != null &&
      !contains(toset([
        var.g008_execution_trigger.execution_request_version_resource_name,
        var.g008_execution_trigger.sip_username_secret_version,
        var.g008_execution_trigger.sip_password_secret_version,
        var.g008_execution_trigger.sip_realm_secret_version,
        var.g008_execution_trigger.target_secret_version,
        var.g008_execution_trigger.execution_nonce_secret_version,
        var.g008_execution_trigger.operator_credential_secret_version,
      ]), var.g008_bootstrap_manifest_version_resource_name) &&
      try(var.g008_execution_trigger.execution_request_version_resource_name == var.g008_secret_version_resource_names["execution_request"], false) &&
      try(var.g008_execution_trigger.sip_username_secret_version == var.g008_secret_version_resource_names["execution_sip_username"], false) &&
      try(var.g008_execution_trigger.sip_password_secret_version == var.g008_secret_version_resource_names["execution_sip_password"], false) &&
      try(var.g008_execution_trigger.sip_realm_secret_version == var.g008_secret_version_resource_names["execution_sip_realm"], false) &&
      try(var.g008_execution_trigger.target_secret_version == var.g008_secret_version_resource_names["execution_target"], false) &&
      try(var.g008_execution_trigger.execution_nonce_secret_version == var.g008_secret_version_resource_names["execution_nonce"], false) &&
      try(var.g008_execution_trigger.operator_credential_secret_version == var.g008_secret_version_resource_names["operator_credential"], false) &&
      alltrue([
        for digest in [
          var.g008_execution_trigger.execution_request_sha256,
          var.g008_execution_trigger.sip_username_sha256,
          var.g008_execution_trigger.sip_password_sha256,
          var.g008_execution_trigger.sip_realm_sha256,
          var.g008_execution_trigger.target_sha256,
          var.g008_execution_trigger.execution_nonce_sha256,
          var.g008_execution_trigger.operator_credential_sha256,
          var.g008_execution_trigger.execution_runner_sha256,
          var.g008_execution_trigger.trusted_keyset_sha256,
          var.g008_execution_trigger.provider_script_sha256,
        ] : can(regex("^[0-9a-f]{64}$", digest))
      ]) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.g008_execution_trigger.review_payload_digest)) &&
      try(var.g008_execution_trigger.execution_nonce_sha256 == sha256(var.activation_receipt.activation_nonce), false) &&
      var.g008_execution_trigger.candidate_receipt_sha256 == var.g009_candidate_receipt.candidate_receipt_sha256 &&
      try(var.g008_execution_trigger.execution_runner_receipt_sha256 == var.g009_candidate_receipt.execution_runner_receipt_sha256, false) &&
      try(var.g008_execution_trigger.activation_receipt_sha256 == var.activation_receipt.canonical_receipt_sha256, false) &&
      try(var.g008_execution_trigger.review_payload_digest == var.candidate_manifest.review_payload_digest, false) &&
      try(var.g008_execution_trigger.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256, false) &&
      try(var.g008_execution_trigger.runtime_image_digest == var.g009_candidate_receipt.runtime_image_digest, false)
    )
    error_message = "g008_execution_trigger requires recova-g008-execution-seal-v1, seven distinct execution-purpose numeric versions with exact content SHA-256 digests plus a separate sealed bootstrap-manifest numeric version, frozen runner/keyset/provider-script SHA-256 digests, and exact approved review-payload, manifest, runtime image, candidate receipt, baked-runner, and activation receipt bindings."
  }
}

variable "prearm_inventory_receipt" {
  description = "Externally verified canonical pre-arm inventory digest; Terraform validates bindings and never claims to verify the source signature."
  type = object({
    run_id                        = string
    project_id                    = string
    network_self_link             = string
    phase_b_manifest_sha256       = string
    canonical_inventory_sha256    = string
    verification_receipt_sha256   = string
    external_address_count        = number
    access_config_count           = number
    prohibited_connectivity_count = number
    issued_at_utc                 = string
    expires_at_utc                = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.prearm_inventory_receipt == null ? true : (
      var.prearm_inventory_receipt.run_id == var.run_id &&
      var.prearm_inventory_receipt.project_id == var.project_id &&
      var.prearm_inventory_receipt.network_self_link == var.phase_b_dependency.network_self_link &&
      var.prearm_inventory_receipt.phase_b_manifest_sha256 == var.phase_b_dependency.manifest_sha256 &&
      alltrue([for digest in [
        var.prearm_inventory_receipt.canonical_inventory_sha256,
        var.prearm_inventory_receipt.verification_receipt_sha256,
      ] : can(regex("^[0-9a-f]{64}$", digest))]) &&
      var.prearm_inventory_receipt.external_address_count == 0 &&
      var.prearm_inventory_receipt.access_config_count == 0 &&
      var.prearm_inventory_receipt.prohibited_connectivity_count == 0 &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.prearm_inventory_receipt.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.prearm_inventory_receipt.expires_at_utc)) &&
      timecmp(var.prearm_inventory_receipt.expires_at_utc, var.prearm_inventory_receipt.issued_at_utc) > 0
    )
    error_message = "prearm_inventory_receipt must be a current-run preverified canonical digest proving Phase B identity and zero public/NAT/router/LB/forwarding attachment."
  }
}

variable "supplier_endpoint_binding" {
  description = "Preverified canonical supplier receipt binding the reserved public address and every exact supplier/customer UDP tuple."
  type = object({
    run_id                        = string
    customer_external_ipv4        = string
    signaling_ipv4_cidr           = string
    signaling_remote_udp_port     = number
    candidate_sip_listen_udp_port = number
    media_ipv4_cidrs              = set(string)
    remote_rtp_udp_port_min       = number
    remote_rtp_udp_port_max       = number
    remote_rtcp_udp_port_min      = number
    remote_rtcp_udp_port_max      = number
    canonical_receipt_sha256      = string
    verification_receipt_sha256   = string
    issued_at_utc                 = string
    expires_at_utc                = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.supplier_endpoint_binding == null ? true : (
      var.supplier_endpoint_binding.run_id == var.run_id &&
      can(cidrhost("${var.supplier_endpoint_binding.customer_external_ipv4}/32", 0)) &&
      !startswith(var.supplier_endpoint_binding.customer_external_ipv4, "0.") &&
      !startswith(var.supplier_endpoint_binding.customer_external_ipv4, "10.") &&
      !startswith(var.supplier_endpoint_binding.customer_external_ipv4, "127.") &&
      !startswith(var.supplier_endpoint_binding.customer_external_ipv4, "169.254.") &&
      !startswith(var.supplier_endpoint_binding.customer_external_ipv4, "192.168.") &&
      can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", var.supplier_endpoint_binding.signaling_ipv4_cidr)) &&
      var.supplier_endpoint_binding.signaling_ipv4_cidr == var.supplier_signaling_ipv4_cidr &&
      var.supplier_endpoint_binding.signaling_remote_udp_port == var.supplier_signaling_remote_udp_port &&
      try(var.supplier_endpoint_binding.signaling_ipv4_cidr == var.supplier_rtp_evidence.signaling_ipv4_cidr, false) &&
      try(var.supplier_endpoint_binding.signaling_remote_udp_port == var.supplier_rtp_evidence.signaling_udp_port, false) &&
      var.supplier_endpoint_binding.candidate_sip_listen_udp_port == var.candidate_sip_listen_udp_port &&
      var.supplier_rtp_evidence != null &&
      try(var.supplier_endpoint_binding.media_ipv4_cidrs == var.supplier_rtp_evidence.remote_ipv4_cidrs, false) &&
      try(var.supplier_endpoint_binding.remote_rtp_udp_port_min == var.supplier_rtp_evidence.remote_rtp_udp_port_min, false) &&
      try(var.supplier_endpoint_binding.remote_rtp_udp_port_max == var.supplier_rtp_evidence.remote_rtp_udp_port_max, false) &&
      try(var.supplier_endpoint_binding.remote_rtcp_udp_port_min == var.supplier_rtp_evidence.remote_rtcp_udp_port_min, false) &&
      try(var.supplier_endpoint_binding.remote_rtcp_udp_port_max == var.supplier_rtp_evidence.remote_rtcp_udp_port_max, false) &&
      alltrue([for digest in [
        var.supplier_endpoint_binding.canonical_receipt_sha256,
        var.supplier_endpoint_binding.verification_receipt_sha256,
      ] : can(regex("^[0-9a-f]{64}$", digest))]) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.supplier_endpoint_binding.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.supplier_endpoint_binding.expires_at_utc)) &&
      timecmp(var.supplier_endpoint_binding.expires_at_utc, var.supplier_endpoint_binding.issued_at_utc) > 0
    )
    error_message = "supplier_endpoint_binding must preverify and exactly bind this run, the reserved public endpoint, separate SIP ports, and supplier media tuples."
  }
}

variable "host_policy_receipt" {
  description = "Preverified canonical digest for the immutable default-drop host policy and runtime-bound local SIP/RTP/RTCP ports."
  type = object({
    run_id                        = string
    policy_sha256                 = string
    tuple_binding_sha256          = string
    verification_receipt_sha256   = string
    candidate_sip_listen_udp_port = number
    candidate_local_rtp_port_min  = number
    candidate_local_rtp_port_max  = number
    candidate_local_rtcp_port_min = number
    candidate_local_rtcp_port_max = number
    issued_at_utc                 = string
    expires_at_utc                = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.host_policy_receipt == null ? true : (
      var.host_policy_receipt.run_id == var.run_id &&
      var.host_policy_receipt.candidate_sip_listen_udp_port == var.candidate_sip_listen_udp_port &&
      var.host_policy_receipt.candidate_local_rtp_port_min == 40000 &&
      var.host_policy_receipt.candidate_local_rtp_port_max == 40099 &&
      var.host_policy_receipt.candidate_local_rtcp_port_min == 40000 &&
      var.host_policy_receipt.candidate_local_rtcp_port_max == 40099 &&
      var.host_policy_receipt.candidate_local_rtp_port_min == var.candidate_local_rtp_port_min &&
      var.host_policy_receipt.candidate_local_rtp_port_max == var.candidate_local_rtp_port_max &&
      var.host_policy_receipt.candidate_local_rtcp_port_min == var.candidate_local_rtcp_port_min &&
      var.host_policy_receipt.candidate_local_rtcp_port_max == var.candidate_local_rtcp_port_max &&
      alltrue([for digest in [
        var.host_policy_receipt.policy_sha256,
        var.host_policy_receipt.tuple_binding_sha256,
        var.host_policy_receipt.verification_receipt_sha256,
      ] : can(regex("^[0-9a-f]{64}$", digest))]) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.host_policy_receipt.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.host_policy_receipt.expires_at_utc)) &&
      timecmp(var.host_policy_receipt.expires_at_utc, var.host_policy_receipt.issued_at_utc) > 0
    )
    error_message = "host_policy_receipt must preverify the immutable host-policy digest and exactly bind the baked 40000-40099 RTP/RTCP runtime pool."
  }
}

variable "recova_destination_receipt" {
  description = "Preverified canonical receipt for exact private F2/F12 control and F3 media destination /32s and endpoint identities."
  type = object({
    run_id                      = string
    control_ipv4_cidrs          = set(string)
    media_ipv4_cidrs            = set(string)
    control_endpoint_sha256     = string
    media_endpoint_sha256       = string
    certificate_binding_sha256  = string
    canonical_receipt_sha256    = string
    verification_receipt_sha256 = string
    issued_at_utc               = string
    expires_at_utc              = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.recova_destination_receipt == null ? true : (
      var.recova_destination_receipt.run_id == var.run_id &&
      length(var.recova_destination_receipt.control_ipv4_cidrs) > 0 &&
      length(var.recova_destination_receipt.media_ipv4_cidrs) > 0 &&
      alltrue([for cidr in setunion(var.recova_destination_receipt.control_ipv4_cidrs, var.recova_destination_receipt.media_ipv4_cidrs) :
        can(cidrhost(cidr, 0)) &&
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}/32$", cidr)) &&
        try(cidrhost(cidr, 0), "invalid") == try(split("/", cidr)[0], "")
      ]) &&
      alltrue([for digest in [
        var.recova_destination_receipt.control_endpoint_sha256,
        var.recova_destination_receipt.media_endpoint_sha256,
        var.recova_destination_receipt.certificate_binding_sha256,
        var.recova_destination_receipt.canonical_receipt_sha256,
        var.recova_destination_receipt.verification_receipt_sha256,
      ] : can(regex("^[0-9a-f]{64}$", digest))]) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.recova_destination_receipt.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.recova_destination_receipt.expires_at_utc)) &&
      timecmp(var.recova_destination_receipt.expires_at_utc, var.recova_destination_receipt.issued_at_utc) > 0
    )
    error_message = "recova_destination_receipt must preverify this run's exact private control/media /32s and endpoint/certificate bindings."
  }
}

variable "activation_receipt" {
  description = "Preverified signed live execution contract binding the exact successor review payload, four-stage sequence, both operator barriers, one execution seal, and fixed safety budgets."
  type = object({
    run_id                            = string
    activation_nonce                  = string
    successor_review_payload_digest   = string
    supplier_binding_sha256           = string
    host_policy_sha256                = string
    recova_destination_receipt_sha256 = string
    canonical_receipt_sha256          = string
    verification_receipt_sha256       = string
    stage_sequence                    = list(string)
    sip_connection_mode               = optional(string, "registration")
    source_external_ipv4              = optional(string)
    peer_signaling_ipv4_cidr          = optional(string)
    peer_signaling_udp_port           = optional(number)
    owned_target_sha256               = optional(string)
    outbound_barrier_receipt_sha256   = string
    inbound_barrier_receipt_sha256    = string
    execution_seal_count              = number
    register_attempt_budget           = number
    unregister_attempt_budget         = number
    total_call_attempt_budget         = number
    contingency_call_budget           = number
    contingency_authority_required    = bool
    retry_count                       = number
    concurrency_count                 = number
    call_deadline_seconds             = number
    issued_at_utc                     = string
    expires_at_utc                    = string
  })
  default  = null
  nullable = true

  validation {
    condition = var.activation_receipt == null ? true : (
      var.activation_receipt.run_id == var.run_id &&
      can(regex("^[A-Za-z0-9_-]{16,128}$", var.activation_receipt.activation_nonce)) &&
      can(regex("^sha256:[0-9a-f]{64}$", var.activation_receipt.successor_review_payload_digest)) &&
      var.activation_receipt.successor_review_payload_digest == var.candidate_manifest.review_payload_digest &&
      var.supplier_endpoint_binding != null &&
      var.host_policy_receipt != null &&
      var.recova_destination_receipt != null &&
      try(var.activation_receipt.supplier_binding_sha256 == var.supplier_endpoint_binding.canonical_receipt_sha256, false) &&
      try(var.activation_receipt.host_policy_sha256 == var.host_policy_receipt.policy_sha256, false) &&
      try(var.activation_receipt.recova_destination_receipt_sha256 == var.recova_destination_receipt.canonical_receipt_sha256, false) &&
      alltrue([for digest in [
        var.activation_receipt.canonical_receipt_sha256,
        var.activation_receipt.verification_receipt_sha256,
        var.activation_receipt.outbound_barrier_receipt_sha256,
        var.activation_receipt.inbound_barrier_receipt_sha256,
      ] : can(regex("^[0-9a-f]{64}$", digest))]) &&
      var.activation_receipt.outbound_barrier_receipt_sha256 != var.activation_receipt.inbound_barrier_receipt_sha256 &&
      contains(["registration", "ip_to_ip"], var.activation_receipt.sip_connection_mode) &&
      (
        var.activation_receipt.sip_connection_mode == "registration" ? (
          var.activation_receipt.stage_sequence == tolist(["register", "outbound_call", "inbound_call", "unregister"]) &&
          var.activation_receipt.register_attempt_budget == 1 &&
          var.activation_receipt.unregister_attempt_budget == 1
          ) : (
          var.activation_receipt.stage_sequence == tolist(["outbound_call", "inbound_call", "peer_detach"]) &&
          var.activation_receipt.register_attempt_budget == 0 &&
          var.activation_receipt.unregister_attempt_budget == 0 &&
          try(var.activation_receipt.source_external_ipv4 == var.supplier_endpoint_binding.customer_external_ipv4, false) &&
          try(var.activation_receipt.peer_signaling_ipv4_cidr == var.supplier_endpoint_binding.signaling_ipv4_cidr, false) &&
          try(var.activation_receipt.peer_signaling_udp_port == 5060, false) &&
          try(var.activation_receipt.peer_signaling_udp_port == var.supplier_endpoint_binding.signaling_remote_udp_port, false) &&
          try(can(cidrhost("${var.activation_receipt.source_external_ipv4}/32", 0)), false) &&
          try(can(regex("^[0-9a-f]{64}$", var.activation_receipt.owned_target_sha256)), false)
        )
      ) &&
      var.activation_receipt.execution_seal_count == 1 &&
      var.activation_receipt.total_call_attempt_budget == 3 &&
      var.activation_receipt.retry_count == 0 &&
      var.activation_receipt.concurrency_count == 1 &&
      var.activation_receipt.call_deadline_seconds == 60 &&
      var.activation_receipt.contingency_call_budget == 1 &&
      var.activation_receipt.contingency_authority_required == true &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.activation_receipt.issued_at_utc)) &&
      can(formatdate("YYYY-MM-DD'T'hh:mm:ss'Z'", var.activation_receipt.expires_at_utc)) &&
      timecmp(var.activation_receipt.expires_at_utc, var.activation_receipt.issued_at_utc) > 0
    )
    error_message = "activation_receipt must bind either the legacy REGISTER/outbound/inbound/UNREGISTER contract or the no-register outbound/inbound/peer-detach contract, plus the exact reserved source IPv4, peer /32:5060/UDP, owned target digest, one seal, maximum three calls, zero retries, concurrency one, and a 60-second deadline."
  }
}

variable "external_ip_reservation_gate" {
  description = "Separately authorizes reservation of one unattached Phase-C regional external IPv4 address."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.external_ip_reservation_gate || var.prearm_inventory_receipt != null
    error_message = "external_ip_reservation_gate requires a preverified canonical pre-arm inventory receipt."
  }
}

variable "network_path_arm_gate" {
  description = "Separately authorizes attachment only after the reserved address and all exact preverified receipts are bound."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition = !var.network_path_arm_gate || (
      var.external_ip_reservation_gate &&
      var.supplier_endpoint_binding != null &&
      var.host_policy_receipt != null &&
      var.recova_destination_receipt != null &&
      var.activation_receipt != null
    )
    error_message = "network_path_arm_gate requires reservation plus exact supplier, host-policy, Recova destination, and activation receipts."
  }
}

variable "control_readiness_gate" {
  description = "Separately authorizes only exact private F2/F12 TCP/443 readiness egress."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.control_readiness_gate || (var.network_path_arm_gate && var.recova_destination_receipt != null)
    error_message = "control_readiness_gate requires an armed path and the exact Recova destination receipt."
  }
}
variable "dependency_manifest_gate" {
  description = "Leader confirmation that the supplied Phase B manifest was independently verified."
  type        = bool
  default     = false
  nullable    = false
}

variable "candidate_gate" {
  description = "G-1/G0 confirmation for the exact immutable candidate."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.candidate_gate || var.candidate_manifest != null
    error_message = "candidate_gate cannot be true without candidate_manifest."
  }
}

variable "endpoint_identity_gate" {
  description = "Approval for the exact F1/F2/F3 Recova endpoint identities."
  type        = bool
  default     = false
  nullable    = false
}

variable "cost_gate" {
  description = "Confirmation that current signed cost evidence is within the ceiling."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.cost_gate || var.cost_evidence != null
    error_message = "cost_gate cannot be true without cost_evidence."
  }
}

variable "live_window_gate" {
  description = "Confirmation of the bounded live window within the Phase C TTL."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.live_window_gate || (var.live_window_start_utc != null && var.live_window_end_utc != null)
    error_message = "live_window_gate cannot be true without both live-window timestamps."
  }
}

variable "sip_connection_mode" {
  description = "SIP signaling mode. registration preserves the legacy REGISTER flow; ip_to_ip requires an exact no-register peer binding."
  type        = string
  default     = "registration"
  nullable    = false

  validation {
    condition     = contains(["registration", "ip_to_ip"], var.sip_connection_mode)
    error_message = "sip_connection_mode must be registration or ip_to_ip."
  }
}

variable "sip_ip_to_ip_gate" {
  description = "Separate G3 approval for bounded no-register IP-to-IP SIP with exact peer detachment cleanup."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition = !var.sip_ip_to_ip_gate || (
      var.sip_connection_mode == "ip_to_ip" &&
      !var.sip_register_gate &&
      var.dependency_manifest_gate &&
      var.candidate_gate &&
      var.endpoint_identity_gate &&
      var.cost_gate &&
      var.live_window_gate &&
      var.network_path_arm_gate &&
      var.supplier_signaling_ipv4_cidr != null &&
      var.supplier_signaling_remote_udp_port == 5060 &&
      var.candidate_sip_listen_udp_port != null &&
      var.supplier_rtp_evidence != null &&
      var.activation_receipt != null &&
      try(var.activation_receipt.sip_connection_mode == "ip_to_ip", false) &&
      var.g008_execution_trigger != null &&
      var.g008_external_iam_provisioning_receipt != null &&
      try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false)
    )
    error_message = "sip_ip_to_ip_gate requires the no-register mode, exact peer /32:5060 binding, bounded activation authority, external IAM receipt, and immutable execution trigger."
  }
}

variable "sip_register_gate" {
  description = "Separate G3 approval for one bounded SIP REGISTER operation."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition     = !var.sip_register_gate || var.sip_connection_mode == "registration"
    error_message = "sip_register_gate is valid only in registration mode."
  }

  validation {
    condition = !var.sip_register_gate || (
      var.dependency_manifest_gate &&
      var.candidate_gate &&
      var.endpoint_identity_gate &&
      var.cost_gate &&
      var.live_window_gate &&
      var.network_path_arm_gate &&
      var.supplier_signaling_ipv4_cidr != null &&
      var.supplier_signaling_remote_udp_port != null &&
      var.candidate_sip_listen_udp_port != null &&
      var.supplier_rtp_evidence != null &&
      var.activation_receipt != null &&
      var.g008_execution_trigger != null &&
      var.g008_external_iam_provisioning_receipt != null &&
      try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false)
    )
    error_message = "sip_register_gate requires all preceding gates, an armed path, exact separate supplier/local SIP ports, preverified activation authority, an externally authenticated IAM provisioning receipt, and the immutable execution trigger bound to a baked-runner candidate receipt."
  }
}

variable "rtp_gate" {
  description = "Separate G4 approval for supplier-bounded RTP."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition = !var.rtp_gate || (
      (var.sip_register_gate || var.sip_ip_to_ip_gate) &&
      var.supplier_rtp_evidence != null &&
      var.g008_execution_trigger != null &&
      try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false)
    )
    error_message = "rtp_gate requires the SIP gate, supplier RTP evidence, and the immutable baked-runner trigger."
  }
}

variable "outbound_call_gate" {
  description = "Separate G5 approval for the bounded outbound attempt."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition = !var.outbound_call_gate || (
      var.rtp_gate &&
      var.g008_execution_trigger != null &&
      try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false)
    )
    error_message = "outbound_call_gate requires RTP and the immutable baked-runner trigger."
  }
}

variable "inbound_call_gate" {
  description = "Separate G5 approval for the bounded inbound attempt."
  type        = bool
  default     = false
  nullable    = false

  validation {
    condition = !var.inbound_call_gate || (
      var.rtp_gate &&
      var.g008_execution_trigger != null &&
      try(var.g009_candidate_receipt.execution_runner_receipt_sha256 != null, false)
    )
    error_message = "inbound_call_gate requires RTP and the immutable baked-runner trigger."
  }
}

check "live_direction_gates_are_atomic" {
  assert {
    condition     = var.outbound_call_gate == var.inbound_call_gate
    error_message = "Outbound and inbound live gates must be activated or disabled together under the exact four-stage authority."
  }
}
