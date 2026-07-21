locals {
  secret_version_references = {
    for purpose, resource_name in var.secret_version_resource_names : purpose => {
      project_id = split("/", resource_name)[1]
      secret_id  = split("/", resource_name)[3]
      version    = split("/", resource_name)[5]
    }
  }
}

locals {
  g008_secret_mount_targets = {
    postgres_password                          = { target = "/run/secrets/g008-recova-postgres-password", consumer = "backend" }
    redis_password                             = { target = "/run/secrets/g008-recova-redis-password", consumer = "backend" }
    f12_tls_private_key                        = { target = "/run/secrets/g008-f12-tls-private-key", consumer = "f12_ingress" }
    f12_tls_certificate                        = { target = "/run/secrets/g008-f12-tls-certificate", consumer = "f12_ingress" }
    f12_mtls_private_key                       = { target = "/run/secrets/g008-f12-mtls-private-key", consumer = "transaction_authority" }
    f12_mtls_certificate                       = { target = "/run/secrets/g008-f12-mtls-certificate", consumer = "transaction_authority" }
    f12_mtls_ca_certificate                    = { target = "/run/secrets/g008-f12-mtls-ca-certificate", consumer = "transaction_authority" }
    dispatch_es256_private_key                 = { target = "/run/secrets/g008-dispatch-es256-private-key", consumer = "backend" }
    dispatch_es256_public_key                  = { target = "/run/secrets/g008-dispatch-es256-public-key", consumer = "backend" }
    media_es256_private_key                    = { target = "/run/secrets/g008-media-es256-private-key", consumer = "backend" }
    media_es256_public_key                     = { target = "/run/secrets/g008-media-es256-public-key", consumer = "backend" }
    execution_evidence_es256_private_key       = { target = "/run/secrets/g008-execution-evidence-es256-private-key", consumer = "backend" }
    execution_evidence_es256_public_key        = { target = "/run/secrets/g008-execution-evidence-es256-public-key", consumer = "backend" }
    registration_attestation_es256_private_key = { target = "/run/secrets/g008-registration-attestation-es256-private-key", consumer = "transaction_authority" }
    registration_attestation_es256_public_key  = { target = "/run/secrets/g008-registration-attestation-es256-public-key", consumer = "backend" }
    authority_recovery_key                     = { target = "/run/secrets/g008-authority-recovery-key", consumer = "backend" }
    mariadb_root_password                      = { target = "/run/secrets/g009-mariadb-root-password", consumer = "backend" }
    webhook_secret                             = { target = "/run/secrets/g009-webhook-secret", consumer = "backend" }
    account_api_token                          = { target = "/run/secrets/g009-account-api-token", consumer = "backend" }
    registration_egress_proof                  = { target = "/run/secrets/g009-registration-egress-proof", consumer = "backend" }
    f12_endpoint_credential                    = { target = "/run/secrets/g008-f12-endpoint-credential", consumer = "backend" }
    registration_f12_endpoint_credential       = { target = "/run/secrets/g008-registration-f12-endpoint-credential", consumer = "transaction_authority" }
    stock_api_token                            = { target = "/run/secrets/g008-stock-api-token", consumer = "backend" }
    jambones_mysql_password                    = { target = "/run/secrets/g009-jambones-mysql-password", consumer = "backend" }
    jwt_secret                                 = { target = "/run/secrets/g009-jwt-secret", consumer = "backend" }
    encryption_secret                          = { target = "/run/secrets/g009-encryption-secret", consumer = "backend" }
    drachtio_feature_secret                    = { target = "/run/secrets/g009-drachtio-feature-secret", consumer = "backend" }
    drachtio_sip_secret                        = { target = "/run/secrets/g009-drachtio-sip-secret", consumer = "backend" }
    freeswitch_esl_password                    = { target = "/run/secrets/g009-freeswitch-esl-password", consumer = "backend" }
  }

  g008_secret_mounts = var.g008_secret_version_resource_names == null ? {} : {
    for purpose, mount in local.g008_secret_mount_targets : purpose => {
      version_resource_name = var.g008_secret_version_resource_names[purpose]
      target                = mount.target
      consumer              = mount.consumer
      read_only             = true
    }
  }
}

# Secret values are deliberately not data sources, resources, locals, or
# outputs. Runtime IAM is bound only to the supplied immutable numeric version
# resource names; Terraform never accesses a secret payload.
check "secret_references_are_immutable_identifiers_only" {
  assert {
    condition = alltrue([
      for reference in values(local.secret_version_references) :
      reference.project_id == var.project_id &&
      can(regex("^[A-Za-z][A-Za-z0-9_-]{0,254}$", reference.secret_id)) &&
      can(regex("^[1-9][0-9]*$", reference.version))
    ])
    error_message = "Every runtime secret must be a project-local Secret Manager resource with an immutable numeric version identifier."
  }
}

check "secret_reference_set_is_exact" {
  assert {
    condition = (
      toset(keys(local.secret_version_references)) == local.runtime_secret_keys &&
      length(local.secret_version_references) == 7
    )
    error_message = "The runtime secret reference set must contain exactly the seven reviewed purposes and no secret values."
  }
}

# These declarations are a sealed startup input contract, not Terraform secret
# reads or mounts. The already-baked runtime may mount only the named file for
# each purpose after a later authority explicitly enables that runtime.
check "g008_secret_mount_contract_is_least_privilege" {
  assert {
    condition = var.g008_secret_version_resource_names == null ? true : (
      toset(keys(local.g008_secret_mounts)) == local.g008_required_secret_keys &&
      toset(keys(var.g008_secret_version_resource_names)) == local.g008_all_secret_keys &&
      length(setintersection(local.g008_required_secret_keys, local.g008_execution_input_secret_keys)) == 0 &&
      length(local.g008_secret_mounts) == 29 &&
      length(local.g008_execution_input_secret_keys) == 7 &&
      length(local.g008_all_secret_keys) == 36 &&
      length(toset(values(var.g008_secret_version_resource_names))) == 36 &&
      length(toset([for mount in values(local.g008_secret_mounts) : mount.target])) == 29 &&
      local.g008_secret_mounts.registration_attestation_es256_private_key.consumer == "transaction_authority" &&
      local.g008_secret_mounts.registration_attestation_es256_public_key.consumer == "backend" &&
      alltrue([
        for purpose, mount in local.g008_secret_mounts :
        mount.read_only &&
        startswith(mount.target, "/run/secrets/") &&
        !strcontains(mount.target, "..") &&
        can(regex("^projects/slit-497603/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", mount.version_resource_name)) &&
        !(mount.consumer == "provider_child" && (
          startswith(purpose, "f12_") ||
          startswith(purpose, "registration_attestation_")
        ))
      ])
    )
    error_message = "G008 startup inputs must expose exactly twenty-nine runtime and seven execution read-only numeric-version files, with private attestation isolated to the transaction authority and no provider-child F12/attestation access."
  }
}
