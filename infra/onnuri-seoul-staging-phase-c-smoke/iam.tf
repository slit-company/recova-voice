locals {
  custom_role_stem = replace(local.run_slug, "-", "_")
  runtime_secret_keys = toset([
    "sip_password",
    "f12_endpoint_credential",
    "f12_mtls_certificate",
    "facade_adapter_credential",
    "callback_hmac_key",
    "tls_private_key",
    "stock_local_api_credential",
  ])
  g008_required_secret_keys = toset(keys(local.g008_secret_mount_targets))
  g008_execution_input_secret_keys = toset([
    "execution_request",
    "execution_sip_username",
    "execution_sip_password",
    "execution_sip_realm",
    "execution_target",
    "execution_nonce",
    "operator_credential",
  ])
  g008_all_secret_keys = setunion(local.g008_required_secret_keys, local.g008_execution_input_secret_keys)
  g008_runtime_secret_keys = toset([
    for purpose, mount in local.g008_secret_mount_targets : purpose
    if mount.consumer != "transaction_authority"
  ])
  g008_backend_secret_keys = toset([
    for purpose, mount in local.g008_secret_mount_targets : purpose
    if mount.consumer == "backend"
  ])
  g008_transaction_authority_secret_keys = toset([
    for purpose, mount in local.g008_secret_mount_targets : purpose
    if mount.consumer == "transaction_authority"
  ])
  g008_provider_child_secret_keys = toset([
    "dispatch_es256_public_key",
    "media_es256_public_key",
  ])
  # Used only to derive the redacted bootstrap binding digest and host-prefetch
  # manifest contract; it is never materialized in a managed IAM resource.
  g008_execution_secret_versions = var.g008_execution_trigger == null || var.g008_bootstrap_manifest_version_resource_name == null ? {} : {
    manifest            = var.g008_bootstrap_manifest_version_resource_name
    request             = var.g008_execution_trigger.execution_request_version_resource_name
    sip_username        = var.g008_execution_trigger.sip_username_secret_version
    sip_password        = var.g008_execution_trigger.sip_password_secret_version
    sip_realm           = var.g008_execution_trigger.sip_realm_secret_version
    target              = var.g008_execution_trigger.target_secret_version
    execution_nonce     = var.g008_execution_trigger.execution_nonce_secret_version
    operator_credential = var.g008_execution_trigger.operator_credential_secret_version
  }
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = local.immutable_names.runtime_service_account
  display_name = "Onnuri Phase C gated runtime"
  description  = "Runtime identity without Compute, firewall, IAM, or logging administration authority."
}

resource "google_service_account" "transaction_authority" {
  project      = var.project_id
  account_id   = local.immutable_names.transaction_authority_service_account
  display_name = "Onnuri Phase C registration transaction authority"
  description  = "Reads only transaction-authority secret purposes; provider children and the backend cannot use this identity."
}
resource "google_service_account" "boot" {
  project      = var.project_id
  account_id   = local.immutable_names.boot_service_account
  display_name = "Onnuri Phase C disabled boot"
  description  = "G2 disabled-boot identity with no Secret Manager or live traffic authority."
}


resource "google_service_account" "logging" {
  project      = var.project_id
  account_id   = local.immutable_names.logging_service_account
  display_name = "Onnuri Phase C log writer"
}

resource "google_service_account" "watchdog" {
  project      = var.project_id
  account_id   = local.immutable_names.watchdog_service_account
  display_name = "Onnuri Phase C independent watchdog"
  description  = "Independently disables named Phase C traffic rules and stops the named VM."
}


resource "google_service_account" "evidence" {
  project      = var.project_id
  account_id   = local.immutable_names.evidence_service_account
  display_name = "Onnuri Phase C evidence reader"
}

resource "google_project_iam_custom_role" "runtime" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_runtime"
  title       = "Onnuri Phase C runtime secret reader"
  description = "Read only explicitly bound numeric secret versions."
  permissions = ["secretmanager.versions.access"]
  stage       = "GA"
}

resource "google_project_iam_custom_role" "transaction_authority" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_txn"
  title       = "Onnuri Phase C transaction authority secret reader"
  description = "Read only the exact transaction-authority numeric secret versions."
  permissions = ["secretmanager.versions.access"]
  stage       = "GA"
}

resource "google_project_iam_custom_role" "transaction_token_minter" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_txn_token"
  title       = "Onnuri Phase C isolated bootstrap transaction token minter"
  description = "Mint one short-lived transaction-authority token only during the metadata-contained host bootstrap; no workload receives this authority."
  permissions = ["iam.serviceAccounts.getAccessToken"]
  stage       = "GA"
}

resource "google_service_account_iam_member" "runtime_mints_transaction_token" {
  count = local.bounded_live_ready ? 1 : 0
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  service_account_id = "projects/${var.project_id}/serviceAccounts/${local.immutable_names.transaction_authority_service_account}@${var.project_id}.iam.gserviceaccount.com"
  role               = google_project_iam_custom_role.transaction_token_minter.name
  member             = google_service_account.runtime.member

  condition {
    title       = "g008-transaction-token-live-window"
    description = "Bootstrap may mint the isolated transaction token only after live start and before both live and destruction deadlines."
    expression = format(
      "request.time >= timestamp('%s') && request.time < timestamp('%s') && request.time < timestamp('%s')",
      var.live_window_start_utc,
      var.live_window_end_utc,
      var.destroy_deadline_utc,
    )
  }
}

resource "google_project_iam_custom_role" "logging" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_logging"
  title       = "Onnuri Phase C log writer"
  permissions = ["logging.logEntries.create"]
  stage       = "GA"
}

resource "google_project_iam_custom_role" "containment" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_contain"
  title       = "Onnuri Phase C named containment actuator"
  description = "Stop the named VM and disable only its named permissive firewall rules."
  permissions = ["compute.instances.stop", "compute.firewalls.update"]
  stage       = "GA"
}

resource "google_project_iam_custom_role" "evidence" {
  project     = var.project_id
  role_id     = "onnuri_c_${local.custom_role_stem}_evidence"
  title       = "Onnuri Phase C dedicated evidence view reader"
  permissions = ["logging.views.access"]
  stage       = "GA"
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each = local.bounded_live_ready ? local.runtime_secret_keys : toset([])
  depends_on = [
    terraform_data.phase_c_live_apply_gate,
    google_cloud_scheduler_job.watchdog_disable_traffic,
    google_cloud_scheduler_job.watchdog_stop_candidate,
  ]

  project   = var.project_id
  secret_id = split("/", local.bound_legacy_secret_versions[each.value])[3]
  role      = google_project_iam_custom_role.runtime.name
  member    = google_service_account.runtime.member

  condition {
    title       = "live-numeric-version-before-live-expiry"
    description = "Live runtime may access only the supplied numeric secret version during the bounded live window."
    expression = format(
      "resource.name == '%s' && request.time >= timestamp('%s') && request.time < timestamp('%s') && request.time < timestamp('%s')",
      local.bound_legacy_secret_versions[each.value],
      var.live_window_start_utc,
      var.live_window_end_utc,
      var.destroy_deadline_utc,
    )
  }
}

# G008 exact-version grants are deliberately provisioned outside this Terraform
# state boundary. The signed external provisioning contract MUST bind every
# manifest purpose to its numeric version and condition both runtime identities
# on request.time >= live_window_start_utc, request.time < live_window_end_utc,
# and request.time < destroy_deadline_utc. This module persists only the redacted
# receipt/binding digest; bootstrap fails closed if any exact grant is absent.

check "g008_secret_purposes_are_isolated" {
  assert {
    condition = (
      length(setintersection(local.g008_runtime_secret_keys, local.g008_transaction_authority_secret_keys)) == 0 &&
      setunion(local.g008_runtime_secret_keys, local.g008_transaction_authority_secret_keys) == local.g008_required_secret_keys &&
      length(setintersection(local.g008_provider_child_secret_keys, setunion(
        toset([
          "f12_tls_private_key",
          "f12_tls_certificate",
          "f12_mtls_private_key",
          "f12_mtls_certificate",
          "f12_mtls_ca_certificate",
          "registration_attestation_es256_private_key",
          "registration_attestation_es256_public_key",
        ]),
        local.g008_transaction_authority_secret_keys,
      ))) == 0 &&
      contains(local.g008_backend_secret_keys, "registration_attestation_es256_public_key") &&
      !contains(local.g008_backend_secret_keys, "registration_attestation_es256_private_key") &&
      !contains(local.g008_runtime_secret_keys, "registration_attestation_es256_private_key") &&
      contains(local.g008_transaction_authority_secret_keys, "registration_attestation_es256_private_key")
    )
    error_message = "Runtime and transaction-authority secret sets must be disjoint and exhaustive; provider children must exclude all F12 and attestation secrets, and the private registration attestation key must be transaction-authority-only."
  }
}

resource "google_project_iam_member" "logging" {
  project = var.project_id
  role    = google_project_iam_custom_role.logging.name
  member  = google_service_account.logging.member

  condition {
    title       = "phase-c-log-writes-before-expiry"
    description = "Log writes cease at the immutable Phase C deadline."
    expression  = "request.time < timestamp('${var.destroy_deadline_utc}')"
  }
}

resource "google_project_iam_member" "containment" {
  project = var.project_id
  role    = google_project_iam_custom_role.containment.name
  member  = "serviceAccount:${local.service_account_emails.watchdog}"

  condition {
    title       = "contain-only-named-phase-c-resources"
    description = "Authority remains valid until Terraform removes it after the named VM and live rules are destroyed."
    expression = format(
      "(resource.type == 'compute.googleapis.com/Instance' && resource.name == 'projects/%s/zones/%s-a/instances/%s') || (resource.type == 'compute.googleapis.com/Firewall' && resource.name in [%s])",
      var.project_id,
      var.region,
      local.immutable_names.instance,
      join(", ", [for name in [
        local.immutable_names.recova_ingress_firewall,
        local.immutable_names.sip_ingress_firewall,
        local.immutable_names.sip_egress_firewall,
        local.immutable_names.rtp_ingress_firewall,
        local.immutable_names.rtp_egress_firewall,
        local.immutable_names.recova_control_egress_firewall,
        local.immutable_names.recova_media_egress_firewall,
        local.immutable_names.google_out_firewall,
      ] : "'projects/${var.project_id}/global/firewalls/${name}'"]),
    )
  }
}

check "runtime_has_no_compute_or_firewall_role" {
  assert {
    condition = length(setintersection(
      toset(google_project_iam_custom_role.runtime.permissions),
      toset(["compute.instances.start", "compute.instances.stop", "compute.firewalls.create", "compute.firewalls.update", "compute.firewalls.delete", "resourcemanager.projects.setIamPolicy"]),
    )) == 0
    error_message = "Runtime authority must not include Compute, firewall, or IAM mutation."
  }
}
