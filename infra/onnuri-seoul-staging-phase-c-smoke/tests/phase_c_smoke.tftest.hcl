mock_provider "google" {
  mock_resource "google_compute_address" {
    defaults = {
      address = "203.0.113.10"
    }
  }
  mock_resource "google_service_account" {
    defaults = {
      email  = "mock@slit-497603.iam.gserviceaccount.com"
      member = "serviceAccount:mock@slit-497603.iam.gserviceaccount.com"
    }
  }
}

variables {
  deployer_service_account                      = "phasec-deployer@slit-497603.iam.gserviceaccount.com"
  run_id                                        = "g008-disabled-smoke"
  apply_timestamp_utc                           = "2030-07-15T01:00:00Z"
  destroy_deadline_utc                          = "2030-07-16T01:00:00Z"
  g008_bootstrap_manifest_version_resource_name = "projects/slit-497603/secrets/g008-sealed-bootstrap-manifest/versions/22"

  recova_f1_source_cidrs        = ["10.20.30.40/32"]
  recova_f1_mtls_endpoint_path  = "https://f1.recova.internal/dispatch"
  recova_f2_https_endpoint_path = "https://f2.recova.internal/callback"
  recova_f3_wss_endpoint_path   = "wss://f3.recova.internal/media"
  recova_f4_https_endpoint_path = "https://f4.recova.internal/secrets"
  recova_f5_https_endpoint_path = "https://f5.recova.internal/logs"
  recova_f12_mtls_endpoint_path = "https://f12.recova.internal/authority"

  provider_redacted_claims = {
    provider_id_digest = "1717171717171717171717171717171717171717171717171717171717171717"
    account_id_digest  = "1818181818181818181818181818181818181818181818181818181818181818"
    currency           = "KRW"
    starting_balance   = "10000"
    evidence_sha256    = "1919191919191919191919191919191919191919191919191919191919191919"
  }

  phase_b_dependency = {
    manifest_sha256              = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    signature_base64             = "YWJj"
    signer_key_id                = "phase-b-test-signer"
    verification_receipt_sha256  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    project_id                   = "slit-497603"
    region                       = "asia-northeast3"
    network_self_link            = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/recova-onnuri-phase-b-vpc"
    subnet_self_link             = "https://www.googleapis.com/compute/v1/projects/slit-497603/regions/asia-northeast3/subnetworks/recova-onnuri-phase-b-subnet-seoul"
    subnet_ipv4_cidr             = "10.73.96.0/24"
    private_ip_google_access     = true
    ingress_deny_rule_name       = "recova-onnuri-phase-b-deny-ingress"
    egress_deny_rule_name        = "recova-onnuri-phase-b-deny-egress"
    phase_b_source_sha256        = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    backend_identity             = "gcs://slit-497603-phase-b-state/onnuri/phase-b"
    backend_generation           = 1
    backend_serial               = 1
    canonical_state_sha256       = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    non_sensitive_outputs_sha256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    issued_at_utc                = "2026-07-15T00:00:00Z"
    expires_at_utc               = "2035-07-15T00:00:00Z"
  }

  g009_candidate_receipt = {
    image_self_link                           = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/images/recova-jambonz-g009"
    image_id                                  = 1
    image_generation                          = 1
    source_sha256                             = "1111111111111111111111111111111111111111111111111111111111111111"
    export_sha256                             = "2222222222222222222222222222222222222222222222222222222222222222"
    derivative_sha256                         = "3333333333333333333333333333333333333333333333333333333333333333"
    runtime_image_digest                      = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    facade_image_digest                       = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
    candidate_receipt_sha256                  = "4444444444444444444444444444444444444444444444444444444444444444"
    candidate_receipt_signature_base64        = "YWJj"
    candidate_receipt_signer_key_id           = "g009-test-signer"
    candidate_receipt_verification_key_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    execution_runner_receipt_sha256           = "1515151515151515151515151515151515151515151515151515151515151515"
    candidate_receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
    candidate_receipt_expires_at_utc          = "2035-07-15T00:00:00Z"
  }

  candidate_manifest = {
    release_id             = "jambonz-oss-g009"
    source_sha256          = "1111111111111111111111111111111111111111111111111111111111111111"
    image_digest           = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    facade_image_digest    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    sbom_sha256            = "6666666666666666666666666666666666666666666666666666666666666666"
    license_sha256         = "7777777777777777777777777777777777777777777777777777777777777777"
    manifest_sha256        = "8888888888888888888888888888888888888888888888888888888888888888"
    renewed_review_sha256  = "9999999999999999999999999999999999999999999999999999999999999999"
    review_payload_digest  = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
    review_approval_status = "approved"
    approved_at_utc        = "2026-07-15T00:00:00Z"
  }

  phase_c_backend_receipt = {
    bucket_name       = "slit-497603-g008-disabled-tfstate"
    prefix            = "onnuri-seoul-staging-phase-c-smoke/g008-disabled-smoke"
    config_sha256     = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    bucket_generation = 1
    recorded_at_utc   = "2026-07-15T00:00:00Z"
  }

  secret_version_resource_names = {
    sip_password               = "projects/slit-497603/secrets/onnuri-sip-password-staging/versions/1"
    f12_endpoint_credential    = "projects/slit-497603/secrets/f12-endpoint-credential/versions/1"
    f12_mtls_certificate       = "projects/slit-497603/secrets/f12-mtls-certificate/versions/1"
    facade_adapter_credential  = "projects/slit-497603/secrets/facade-adapter-credential/versions/1"
    callback_hmac_key          = "projects/slit-497603/secrets/callback-hmac-key/versions/1"
    tls_private_key            = "projects/slit-497603/secrets/tls-private-key/versions/1"
    stock_local_api_credential = "projects/slit-497603/secrets/stock-local-api-credential/versions/1"
  }

  g008_derivative_receipt = {
    schema_version                  = "recova-g008-derivative-v3"
    backend                         = { image_digest = "sha256:1010101010101010101010101010101010101010101010101010101010101010", receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111" }
    postgres                        = { image_digest = "sha256:2020202020202020202020202020202020202020202020202020202020202020", receipt_sha256 = "2222222222222222222222222222222222222222222222222222222222222222" }
    redis                           = { image_digest = "sha256:3030303030303030303030303030303030303030303030303030303030303030", receipt_sha256 = "3333333333333333333333333333333333333333333333333333333333333333" }
    ingress                         = { image_digest = "sha256:4040404040404040404040404040404040404040404040404040404040404040", receipt_sha256 = "4444444444444444444444444444444444444444444444444444444444444444" }
    derivative_manifest_sha256      = "5555555555555555555555555555555555555555555555555555555555555555"
    candidate_manifest_sha256       = "8888888888888888888888888888888888888888888888888888888888888888"
    receipt_sha256                  = "6666666666666666666666666666666666666666666666666666666666666666"
    receipt_signature_base64        = "YWJj"
    receipt_signer_key_id           = "g008-derivative-signer"
    receipt_verification_key_sha256 = "7777777777777777777777777777777777777777777777777777777777777777"
    receipt_issued_at_utc           = "2026-07-15T00:00:00Z"
    receipt_expires_at_utc          = "2035-07-15T00:00:00Z"
  }

  g008_authority_binding = {
    tenant_digest   = "1111111111111111111111111111111111111111111111111111111111111111"
    account_digest  = "2222222222222222222222222222222222222222222222222222222222222222"
    envelope_digest = "751aff6140c559b91105c9b4be5e834ffb9c12245fb8660376ec955b31f573c0"
    candidate_digest = sha256(jsonencode({
      review_payload_digest     = var.candidate_manifest.review_payload_digest
      candidate_manifest_sha256 = var.candidate_manifest.manifest_sha256
      runtime_image_digest      = var.g009_candidate_receipt.runtime_image_digest
      candidate_receipt_sha256  = var.g009_candidate_receipt.candidate_receipt_sha256
    }))
  }

  g008_f12_contract = {
    origin_https_endpoint_path        = "https://f12-g008.recova.internal/origin"
    readiness_path                    = "/readyz"
    media_wss_endpoint_path           = "wss://f12-g008.recova.internal/media"
    endpoint_san                      = "f12-g008.recova.internal"
    tls_certificate_sha256            = "1111111111111111111111111111111111111111111111111111111111111111"
    mtls_client_certificate_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
    mtls_ca_certificate_sha256        = "3333333333333333333333333333333333333333333333333333333333333333"
    dispatch_algorithm                = "ES256"
    dispatch_key_id                   = "g008-dispatch-key"
    dispatch_public_key_sha256        = "4444444444444444444444444444444444444444444444444444444444444444"
    media_algorithm                   = "ES256"
    media_key_id                      = "g008-media-key"
    media_public_key_sha256           = "5555555555555555555555555555555555555555555555555555555555555555"
    contract_receipt_sha256           = "6666666666666666666666666666666666666666666666666666666666666666"
    contract_receipt_signature_base64 = "YWJj"
    contract_receipt_signer_key_id    = "g008-f12-contract-signer"
    contract_verification_key_sha256  = "7777777777777777777777777777777777777777777777777777777777777777"
    contract_receipt_issued_at_utc    = "2026-07-15T00:00:00Z"
    contract_receipt_expires_at_utc   = "2035-07-15T00:00:00Z"
  }

  g008_secret_version_resource_names = {
    postgres_password                          = "projects/slit-497603/secrets/g008-postgres-password/versions/1"
    redis_password                             = "projects/slit-497603/secrets/g008-redis-password/versions/2"
    f12_tls_private_key                        = "projects/slit-497603/secrets/g008-f12-tls-private-key/versions/3"
    f12_tls_certificate                        = "projects/slit-497603/secrets/g008-f12-tls-certificate/versions/4"
    f12_mtls_private_key                       = "projects/slit-497603/secrets/g008-f12-mtls-private-key/versions/5"
    f12_mtls_certificate                       = "projects/slit-497603/secrets/g008-f12-mtls-certificate/versions/6"
    f12_mtls_ca_certificate                    = "projects/slit-497603/secrets/g008-f12-mtls-ca-certificate/versions/7"
    dispatch_es256_private_key                 = "projects/slit-497603/secrets/g008-dispatch-private-key/versions/8"
    dispatch_es256_public_key                  = "projects/slit-497603/secrets/g008-dispatch-public-key/versions/11"
    media_es256_private_key                    = "projects/slit-497603/secrets/g008-media-private-key/versions/9"
    media_es256_public_key                     = "projects/slit-497603/secrets/g008-media-public-key/versions/12"
    execution_evidence_es256_private_key       = "projects/slit-497603/secrets/g008-execution-evidence-private-key/versions/13"
    execution_evidence_es256_public_key        = "projects/slit-497603/secrets/g008-execution-evidence-public-key/versions/14"
    registration_attestation_es256_private_key = "projects/slit-497603/secrets/g008-registration-attestation-private-key/versions/15"
    registration_attestation_es256_public_key  = "projects/slit-497603/secrets/g008-registration-attestation-public-key/versions/16"
    authority_recovery_key                     = "projects/slit-497603/secrets/g008-authority-recovery-key/versions/17"
    mariadb_root_password                      = "projects/slit-497603/secrets/g009-mariadb-root-password/versions/18"
    webhook_secret                             = "projects/slit-497603/secrets/g009-webhook-secret/versions/19"
    account_api_token                          = "projects/slit-497603/secrets/g009-account-api-token/versions/20"
    registration_egress_proof                  = "projects/slit-497603/secrets/g009-registration-egress-proof/versions/21"
    f12_endpoint_credential                    = "projects/slit-497603/secrets/g008-f12-endpoint-credential/versions/22"
    registration_f12_endpoint_credential       = "projects/slit-497603/secrets/g008-registration-f12-endpoint-credential/versions/23"
    stock_api_token                            = "projects/slit-497603/secrets/g008-stock-api-token/versions/24"
    jambones_mysql_password                    = "projects/slit-497603/secrets/g008-jambones-mysql-password/versions/25"
    jwt_secret                                 = "projects/slit-497603/secrets/g008-jwt-secret/versions/26"
    encryption_secret                          = "projects/slit-497603/secrets/g008-encryption-secret/versions/27"
    drachtio_feature_secret                    = "projects/slit-497603/secrets/g008-drachtio-feature-secret/versions/28"
    drachtio_sip_secret                        = "projects/slit-497603/secrets/g008-drachtio-sip-secret/versions/29"
    freeswitch_esl_password                    = "projects/slit-497603/secrets/g008-freeswitch-esl-password/versions/30"
    execution_request                          = "projects/slit-497603/secrets/g008-execution-request/versions/11"
    execution_sip_username                     = "projects/slit-497603/secrets/g008-sip-username/versions/12"
    execution_sip_password                     = "projects/slit-497603/secrets/g008-sip-password/versions/13"
    execution_sip_realm                        = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
    execution_target                           = "projects/slit-497603/secrets/g008-execution-target/versions/15"
    execution_nonce                            = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
    operator_credential                        = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
  }
  live_window_start_utc              = timeadd(timestamp(), "-1m")
  live_window_end_utc                = timeadd(timestamp(), "59m")
  supplier_signaling_ipv4_cidr       = "192.0.2.10/32"
  supplier_signaling_remote_udp_port = 5060
  candidate_sip_listen_udp_port      = 5090
  candidate_local_rtp_port_min       = 40000
  candidate_local_rtp_port_max       = 40099
  candidate_local_rtcp_port_min      = 40000
  candidate_local_rtcp_port_max      = 40099

  cost_evidence = {
    estimated_total_krw = 1
    observed_total_krw  = 1
    recorded_at_utc     = timeadd(timestamp(), "-1m")
    expires_at_utc      = timeadd(timestamp(), "59m")
    evidence_sha256     = "abababababababababababababababababababababababababababababababab"
    signer_key_id       = "g008-cost-test-signer"
  }

  supplier_rtp_evidence = {
    signaling_ipv4_cidr         = "192.0.2.10/32"
    signaling_udp_port          = 5060
    remote_ipv4_cidrs           = ["198.51.100.0/24"]
    remote_rtp_udp_port_min     = 10000
    remote_rtp_udp_port_max     = 10009
    remote_rtcp_udp_port_min    = 11000
    remote_rtcp_udp_port_max    = 11009
    max_concurrent_calls        = 1
    calls_per_second            = 1
    canonical_receipt_sha256    = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
    verification_receipt_sha256 = "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
    issued_at_utc               = "2026-07-15T00:00:00Z"
    expires_at_utc              = "2035-07-15T00:00:00Z"
  }

  prearm_inventory_receipt = {
    run_id                        = "g008-disabled-smoke"
    project_id                    = "slit-497603"
    network_self_link             = "https://www.googleapis.com/compute/v1/projects/slit-497603/global/networks/recova-onnuri-phase-b-vpc"
    phase_b_manifest_sha256       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    canonical_inventory_sha256    = "0101010101010101010101010101010101010101010101010101010101010101"
    verification_receipt_sha256   = "0202020202020202020202020202020202020202020202020202020202020202"
    external_address_count        = 0
    access_config_count           = 0
    prohibited_connectivity_count = 0
    issued_at_utc                 = "2026-07-15T00:00:00Z"
    expires_at_utc                = "2035-07-15T00:00:00Z"
  }

  supplier_endpoint_binding = {
    run_id                        = "g008-disabled-smoke"
    customer_external_ipv4        = "203.0.113.10"
    signaling_ipv4_cidr           = "192.0.2.10/32"
    signaling_remote_udp_port     = 5060
    candidate_sip_listen_udp_port = 5090
    media_ipv4_cidrs              = ["198.51.100.0/24"]
    remote_rtp_udp_port_min       = 10000
    remote_rtp_udp_port_max       = 10009
    remote_rtcp_udp_port_min      = 11000
    remote_rtcp_udp_port_max      = 11009
    canonical_receipt_sha256      = "0303030303030303030303030303030303030303030303030303030303030303"
    verification_receipt_sha256   = "0404040404040404040404040404040404040404040404040404040404040404"
    issued_at_utc                 = "2026-07-15T00:00:00Z"
    expires_at_utc                = "2035-07-15T00:00:00Z"
  }

  host_policy_receipt = {
    run_id                        = "g008-disabled-smoke"
    policy_sha256                 = "0505050505050505050505050505050505050505050505050505050505050505"
    tuple_binding_sha256          = "0606060606060606060606060606060606060606060606060606060606060606"
    verification_receipt_sha256   = "0707070707070707070707070707070707070707070707070707070707070707"
    candidate_sip_listen_udp_port = 5090
    candidate_local_rtp_port_min  = 40000
    candidate_local_rtp_port_max  = 40099
    candidate_local_rtcp_port_min = 40000
    candidate_local_rtcp_port_max = 40099
    issued_at_utc                 = "2026-07-15T00:00:00Z"
    expires_at_utc                = "2035-07-15T00:00:00Z"
  }

  recova_destination_receipt = {
    run_id                      = "g008-disabled-smoke"
    control_ipv4_cidrs          = ["10.20.30.41/32", "10.20.30.42/32"]
    media_ipv4_cidrs            = ["10.20.30.43/32"]
    control_endpoint_sha256     = "0808080808080808080808080808080808080808080808080808080808080808"
    media_endpoint_sha256       = "0909090909090909090909090909090909090909090909090909090909090909"
    certificate_binding_sha256  = "1010101010101010101010101010101010101010101010101010101010101010"
    canonical_receipt_sha256    = "1111111111111111111111111111111111111111111111111111111111111111"
    verification_receipt_sha256 = "1212121212121212121212121212121212121212121212121212121212121212"
    issued_at_utc               = "2026-07-15T00:00:00Z"
    expires_at_utc              = "2035-07-15T00:00:00Z"
  }

  activation_receipt = {
    run_id                            = "g008-disabled-smoke"
    activation_nonce                  = "g008-activation-nonce-0001"
    successor_review_payload_digest   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
    supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
    host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
    recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
    canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
    verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
    stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
    outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
    inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
    execution_seal_count              = 1
    register_attempt_budget           = 1
    unregister_attempt_budget         = 1
    total_call_attempt_budget         = 3
    contingency_call_budget           = 1
    contingency_authority_required    = true
    retry_count                       = 0
    concurrency_count                 = 1
    call_deadline_seconds             = 60
    issued_at_utc                     = "2026-07-15T00:00:00Z"
    expires_at_utc                    = "2035-07-15T00:00:00Z"
  }
}

run "default_has_no_external_address_or_access_config" {
  command = plan

  assert {
    condition = (
      !var.external_ip_reservation_gate &&
      !var.network_path_arm_gate &&
      length(google_compute_address.candidate_external) == 0 &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == 0 &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      var.g008_execution_trigger == null &&
      google_compute_instance.candidate.metadata["g008-bootstrap-manifest-handle"] == "" &&
      google_compute_instance.candidate.metadata["g008-execution-nonce-sha256"] == "" &&
      var.activation_receipt.successor_review_payload_digest == var.candidate_manifest.review_payload_digest &&
      google_compute_instance.candidate.metadata["g008-review-payload-digest"] == var.activation_receipt.successor_review_payload_digest &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] == "" &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] == "" &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-secret-versions") &&
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      length(google_compute_firewall.sip_ingress) == 1 &&
      google_compute_firewall.sip_ingress[0].disabled &&
      google_compute_firewall.sip_egress[0].disabled &&
      google_compute_firewall.rtp_ingress[0].disabled &&
      google_compute_firewall.rtp_egress[0].disabled &&
      google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      google_compute_firewall.facade_wss_egress[0].disabled &&
      contains(one(google_compute_firewall.rtp_ingress[0].allow).ports, "40000-40099") &&
      length(one(google_compute_firewall.rtp_ingress[0].allow).ports) == 1
    )
    error_message = "Default must have no external address/access configuration, a terminated VM, and every exact allow disabled."
  }
}

run "candidate_manifest_rejects_review_payload_digest_mismatch" {
  command = plan

  variables {
    candidate_manifest = {
      release_id             = "jambonz-oss-g009"
      source_sha256          = "1111111111111111111111111111111111111111111111111111111111111111"
      image_digest           = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      facade_image_digest    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
      sbom_sha256            = "6666666666666666666666666666666666666666666666666666666666666666"
      license_sha256         = "7777777777777777777777777777777777777777777777777777777777777777"
      manifest_sha256        = "8888888888888888888888888888888888888888888888888888888888888888"
      renewed_review_sha256  = "9999999999999999999999999999999999999999999999999999999999999999"
      review_payload_digest  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      review_approval_status = "approved"
      approved_at_utc        = "2026-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.candidate_manifest]
}

run "candidate_manifest_rejects_pending_review_approval" {
  command = plan

  variables {
    candidate_manifest = {
      release_id             = "jambonz-oss-g009"
      source_sha256          = "1111111111111111111111111111111111111111111111111111111111111111"
      image_digest           = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      facade_image_digest    = "sha256:5555555555555555555555555555555555555555555555555555555555555555"
      sbom_sha256            = "6666666666666666666666666666666666666666666666666666666666666666"
      license_sha256         = "7777777777777777777777777777777777777777777777777777777777777777"
      manifest_sha256        = "8888888888888888888888888888888888888888888888888888888888888888"
      renewed_review_sha256  = "9999999999999999999999999999999999999999999999999999999999999999"
      review_payload_digest  = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      review_approval_status = "pending"
      approved_at_utc        = "2026-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.candidate_manifest]

}
run "activation_receipt_rejects_malformed_successor_review_payload_digest" {
  command = plan

  variables {
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "6e759e5e5af876b4ffc561f9f2968203da7d7ae7310e6d29f7f23ddd93266ab8"
      supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 3
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 60
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}

run "activation_receipt_rejects_substituted_successor_review_payload_digest" {
  command = plan

  variables {
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 3
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 60
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}

run "g2_private_boot_remains_zero_public_zero_traffic" {
  command = plan

  variables {
    dependency_manifest_gate = true
    candidate_gate           = true
    endpoint_identity_gate   = true
  }

  assert {
    condition = (
      length(google_compute_address.candidate_external) == 0 &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == 0 &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_instance.candidate.can_ip_forward == false &&
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      google_compute_firewall.sip_ingress[0].disabled &&
      google_compute_firewall.sip_egress[0].disabled &&
      google_compute_firewall.rtp_ingress[0].disabled &&
      google_compute_firewall.rtp_egress[0].disabled &&
      google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      google_compute_firewall.facade_wss_egress[0].disabled
    )
    error_message = "G2 must remain a private-only boot with no external access configuration and no traffic allow."
  }
}

run "reservation_is_unattached_and_non_traffic" {
  command = plan

  variables {
    external_ip_reservation_gate = true
  }

  assert {
    condition = (
      length(google_compute_address.candidate_external) == 1 &&
      google_compute_address.candidate_external[0].address_type == "EXTERNAL" &&
      google_compute_address.candidate_external[0].network_tier == "PREMIUM" &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == 0 &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      google_compute_firewall.sip_ingress[0].disabled &&
      google_compute_firewall.sip_egress[0].disabled &&
      google_compute_firewall.rtp_ingress[0].disabled &&
      google_compute_firewall.rtp_egress[0].disabled &&
      google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      google_compute_firewall.facade_wss_egress[0].disabled
    )
    error_message = "Reservation must create exactly one regional external address without NIC attachment or traffic."
  }
}

run "armed_off_attaches_exact_address_to_terminated_candidate" {
  command = plan

  variables {
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    phase_c_live_preflight_bundle_path = "/tmp/phase-c-live-preflight-test-bundle.json"
  }

  override_data {
    target          = data.external.phase_c_live_plan[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = timeadd(timestamp(), "59m")
        effective_cutoff_utc      = timeadd(timestamp(), "59m")
      }
    }
  }

  override_data {
    target          = data.external.phase_c_live_apply[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = timeadd(timestamp(), "59m")
        effective_cutoff_utc      = timeadd(timestamp(), "59m")
      }
    }
  }

  assert {
    condition = (
      length(google_compute_address.candidate_external) == 1 &&
      length(google_compute_instance.candidate.network_interface[0].access_config) == 1 &&
      !contains(keys(google_compute_instance.candidate.metadata), "candidate-external-ipv4") &&
      !contains(keys(google_compute_instance.candidate.metadata), "candidate-sip-listen-udp-port") &&
      !contains(keys(google_compute_instance.candidate.metadata), "supplier-signaling-ipv4-cidr") &&
      !contains(keys(google_compute_instance.candidate.metadata), "supplier-media-ipv4-cidrs") &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_instance.candidate.can_ip_forward == false &&
      google_compute_firewall.recova_f1_https_ingress.disabled &&
      google_compute_firewall.sip_ingress[0].disabled &&
      google_compute_firewall.sip_egress[0].disabled &&
      google_compute_firewall.rtp_ingress[0].disabled &&
      google_compute_firewall.rtp_egress[0].disabled &&
      google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      google_compute_firewall.facade_wss_egress[0].disabled &&
      length(google_cloud_scheduler_job.watchdog_stop_candidate) == 1 &&
      length(local.watchdog_traffic_firewall_names) == 8 &&
      length(google_cloud_scheduler_job.watchdog_disable_traffic) == 8
    )
    error_message = "Armed/off must attach only the exact receipted address to a terminated VM, keep every allow disabled, and arm all watchdogs."
  }

  assert {
    condition = (
      toset(google_compute_firewall.deny_all_ingress.target_service_accounts) == toset([
        local.service_account_emails.boot,
        local.service_account_emails.runtime,
      ]) &&
      toset(google_compute_firewall.deny_all_egress.target_service_accounts) == toset([
        local.service_account_emails.boot,
        local.service_account_emails.runtime,
      ]) &&
      !google_compute_firewall.deny_all_ingress.disabled &&
      !google_compute_firewall.deny_all_egress.disabled
    )
    error_message = "Permanent deny rules must cover both boot and runtime candidate identities."
  }

  assert {
    condition = (
      data.external.phase_c_live_plan[0].result.verified == "true" &&
      length(data.external.phase_c_live_apply) == 1 &&
      length(terraform_data.phase_c_live_apply_gate) == 1
    )
    error_message = "Armed/off authority must schedule apply-time re-verification and the apply gate after successful plan-time cryptographic verification."
  }

  assert {
    condition = (
      toset(one(google_compute_firewall.sip_ingress[0].allow).ports) == toset([tostring(var.candidate_sip_listen_udp_port)]) &&
      toset(one(google_compute_firewall.sip_egress[0].allow).ports) == toset([tostring(var.supplier_signaling_remote_udp_port)]) &&
      toset(google_compute_firewall.facade_f2_f12_egress[0].destination_ranges) == toset(var.recova_destination_receipt.control_ipv4_cidrs) &&
      toset(google_compute_firewall.facade_wss_egress[0].destination_ranges) == toset(var.recova_destination_receipt.media_ipv4_cidrs) &&
      toset(one(google_compute_firewall.facade_f2_f12_egress[0].allow).ports) == toset(["443"]) &&
      toset(one(google_compute_firewall.facade_wss_egress[0].allow).ports) == toset(["443"]) &&
      toset(google_compute_firewall.facade_f2_f12_egress[0].target_service_accounts) == toset([local.service_account_emails.runtime]) &&
      toset(google_compute_firewall.facade_wss_egress[0].target_service_accounts) == toset([local.service_account_emails.runtime])
    )
    error_message = "SIP local/remote ports and private F2/F12/F3 /32 TCP/443 runtime targets must remain exact."
  }
}

run "wrong_reserved_external_address_hard_fails" {
  command = plan

  variables {
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    phase_c_live_preflight_bundle_path = "/tmp/phase-c-live-preflight-test-bundle.json"
  }

  override_data {
    target          = data.external.phase_c_live_plan[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = timeadd(timestamp(), "59m")
        effective_cutoff_utc      = timeadd(timestamp(), "59m")
      }
    }
  }

  override_data {
    target          = data.external.phase_c_live_apply[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = timeadd(timestamp(), "59m")
        effective_cutoff_utc      = timeadd(timestamp(), "59m")
      }
    }
  }

  override_resource {
    target          = google_compute_address.candidate_external[0]
    override_during = plan
    values = {
      address = "203.0.113.11"
    }
  }

  expect_failures = [google_compute_instance.candidate]
}

run "network_path_arm_without_crypto_bundle_hard_fails" {
  command = plan

  variables {
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    phase_c_live_preflight_bundle_path = null
  }

  expect_failures = [
    google_compute_address.candidate,
    google_compute_address.candidate_external[0],
  ]
}

run "missing_supplier_binding_hard_fails" {
  command = plan

  variables {
    external_ip_reservation_gate = true
    network_path_arm_gate        = true
    supplier_endpoint_binding    = null
  }

  expect_failures = [var.activation_receipt]
}

run "supplier_cidr_mismatch_hard_fails" {
  command = plan

  variables {
    supplier_signaling_ipv4_cidr = "192.0.2.11/32"
  }

  expect_failures = [var.supplier_endpoint_binding]
}

run "supplier_remote_port_mismatch_hard_fails" {
  command = plan

  variables {
    supplier_signaling_remote_udp_port = 5061
  }

  expect_failures = [var.supplier_endpoint_binding]
}

run "candidate_listen_port_mismatch_hard_fails" {
  command = plan

  variables {
    candidate_sip_listen_udp_port = 5091
  }

  expect_failures = [
    var.supplier_endpoint_binding,
    var.host_policy_receipt,
  ]
}

run "local_media_pool_one_port_divergence_hard_fails" {
  command = plan

  variables {
    candidate_local_rtp_port_max = 40098
  }

  expect_failures = [var.candidate_local_rtp_port_max]
}

run "host_policy_one_port_divergence_hard_fails" {
  command = plan

  variables {
    host_policy_receipt = {
      run_id                        = "g008-disabled-smoke"
      policy_sha256                 = "0505050505050505050505050505050505050505050505050505050505050505"
      tuple_binding_sha256          = "0606060606060606060606060606060606060606060606060606060606060606"
      verification_receipt_sha256   = "0707070707070707070707070707070707070707070707070707070707070707"
      candidate_sip_listen_udp_port = 5090
      candidate_local_rtp_port_min  = 40000
      candidate_local_rtp_port_max  = 40099
      candidate_local_rtcp_port_min = 40000
      candidate_local_rtcp_port_max = 40098
      issued_at_utc                 = "2026-07-15T00:00:00Z"
      expires_at_utc                = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.host_policy_receipt]
}

run "non_host_recova_control_destination_hard_fails" {
  command = plan

  variables {
    recova_destination_receipt = {
      run_id                      = "g008-disabled-smoke"
      control_ipv4_cidrs          = ["10.20.30.0/24"]
      media_ipv4_cidrs            = ["10.20.30.43/32"]
      control_endpoint_sha256     = "0808080808080808080808080808080808080808080808080808080808080808"
      media_endpoint_sha256       = "0909090909090909090909090909090909090909090909090909090909090909"
      certificate_binding_sha256  = "1010101010101010101010101010101010101010101010101010101010101010"
      canonical_receipt_sha256    = "1111111111111111111111111111111111111111111111111111111111111111"
      verification_receipt_sha256 = "1212121212121212121212121212121212121212121212121212121212121212"
      issued_at_utc               = "2026-07-15T00:00:00Z"
      expires_at_utc              = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.recova_destination_receipt]
}

run "non_host_recova_media_destination_hard_fails" {
  command = plan

  variables {
    recova_destination_receipt = {
      run_id                      = "g008-disabled-smoke"
      control_ipv4_cidrs          = ["10.20.30.41/32", "10.20.30.42/32"]
      media_ipv4_cidrs            = ["10.20.30.0/24"]
      control_endpoint_sha256     = "0808080808080808080808080808080808080808080808080808080808080808"
      media_endpoint_sha256       = "0909090909090909090909090909090909090909090909090909090909090909"
      certificate_binding_sha256  = "1010101010101010101010101010101010101010101010101010101010101010"
      canonical_receipt_sha256    = "1111111111111111111111111111111111111111111111111111111111111111"
      verification_receipt_sha256 = "1212121212121212121212121212121212121212121212121212121212121212"
      issued_at_utc               = "2026-07-15T00:00:00Z"
      expires_at_utc              = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.recova_destination_receipt]
}

run "missing_host_policy_hard_fails" {
  command = plan

  variables {
    external_ip_reservation_gate = true
    network_path_arm_gate        = true
    host_policy_receipt          = null
  }

  expect_failures = [var.activation_receipt]
}

run "missing_activation_receipt_hard_fails" {
  command = plan

  variables {
    external_ip_reservation_gate = true
    network_path_arm_gate        = true
    activation_receipt           = null
  }

  expect_failures = [var.network_path_arm_gate]
}

run "wrong_activation_supplier_digest_hard_fails" {
  command = plan

  variables {
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      supplier_binding_sha256           = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 3
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 60
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}

run "mixed_four_stage_contract_hard_fails" {
  command = plan

  variables {
    outbound_call_gate = true
    inbound_call_gate  = true
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "inbound_call", "outbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 3
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 60
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}
run "fourth_call_attempt_hard_fails" {
  command = plan

  variables {
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 4
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 60
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}

run "call_deadline_over_sixty_seconds_hard_fails" {
  command = plan

  variables {
    activation_receipt = {
      run_id                            = "g008-disabled-smoke"
      activation_nonce                  = "g008-activation-nonce-0001"
      successor_review_payload_digest   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      supplier_binding_sha256           = "0303030303030303030303030303030303030303030303030303030303030303"
      host_policy_sha256                = "0505050505050505050505050505050505050505050505050505050505050505"
      recova_destination_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
      canonical_receipt_sha256          = "1313131313131313131313131313131313131313131313131313131313131313"
      verification_receipt_sha256       = "1414141414141414141414141414141414141414141414141414141414141414"
      stage_sequence                    = ["register", "outbound_call", "inbound_call", "unregister"]
      outbound_barrier_receipt_sha256   = "2121212121212121212121212121212121212121212121212121212121212121"
      inbound_barrier_receipt_sha256    = "2222222222222222222222222222222222222222222222222222222222222222"
      execution_seal_count              = 1
      register_attempt_budget           = 1
      unregister_attempt_budget         = 1
      total_call_attempt_budget         = 3
      contingency_call_budget           = 1
      contingency_authority_required    = true
      retry_count                       = 0
      concurrency_count                 = 1
      call_deadline_seconds             = 61
      issued_at_utc                     = "2026-07-15T00:00:00Z"
      expires_at_utc                    = "2035-07-15T00:00:00Z"
    }
  }

  expect_failures = [var.activation_receipt]
}

run "startup_source_enforces_deadline_metadata_denial_and_cleanup" {
  command = plan

  assert {
    condition = (
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/bin/timeout --signal=TERM --kill-after=5s \"$${whole_run_seconds}s\"") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/sbin/iptables -C DOCKER-USER -d \"$METADATA_IP/32\" -j REJECT") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/sbin/iptables -C OUTPUT -d \"$METADATA_IP/32\" -j REJECT") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/sbin/iptables -C FORWARD -d \"$METADATA_IP/32\" -j REJECT") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/bin/umount \"$directory\" || cleanup_failed=1") &&
      strcontains(file("${path.module}/startup-g008.sh"), "trap - EXIT HUP INT TERM") &&
      strcontains(file("${path.module}/startup-g008.sh"), "if [ \"$status\" -eq 0 ] && [ \"$cleanup_failed\" -ne 0 ]") &&
      strcontains(file("${path.module}/startup-g008.sh"), "seconds = min(360, int(remaining))") &&
      strcontains(file("${path.module}/startup-g008.sh"), "EXECUTION_KEYS = {\"request\", \"sip_username\", \"sip_password\", \"sip_realm\", \"target\", \"execution_nonce\", \"operator_credential\"}") &&
      strcontains(file("${path.module}/startup-g008.sh"), "--env-file \"$COMPOSE_ENV_FILE\" --project-directory \"$COMPOSE_ROOT\"") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/bin/chmod 0400 \"$EVIDENCE_ROOT/$nonce_digest/execution-bundle.json\"") &&
      strcontains(file("${path.module}/startup-g008.sh"), "checked_bytes(runner_path, runner_digest)") &&
      strcontains(file("${path.module}/startup-g008.sh"), "checked_bytes(keyset_path, keyset_digest)") &&
      strcontains(file("${path.module}/startup-g008.sh"), "checked_bytes(provider_path, provider_digest)") &&
      strcontains(file("${path.module}/startup-g008.sh"), "COMPOSE_ENV_FILE=/opt/recova/g008-compose.env") &&
      strcontains(file("${path.module}/startup-g008.sh"), "os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600") &&
      strcontains(file("${path.module}/startup-g008.sh"), "set(bindings) != required") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/bin/env -i PATH=/usr/bin:/bin HOME=/nonexistent") &&
      strcontains(file("${path.module}/startup-g008.sh"), "/usr/bin/rm -f \"$COMPOSE_ENV_FILE\"")
    )
    error_message = "The audited startup source must enforce a live-window/cost-bounded 360-second whole-run watchdog, seven sealed inputs, frozen artifact digests, exact evidence recovery, metadata denial, and fail-closed cleanup."
  }
}

run "outbound_only_direction_hard_fails" {
  command = plan

  variables {
    outbound_call_gate = true
    inbound_call_gate  = false
  }

  expect_failures = [var.outbound_call_gate]
}

run "inbound_only_direction_hard_fails" {
  command = plan

  variables {
    outbound_call_gate = false
    inbound_call_gate  = true
  }

  expect_failures = [var.inbound_call_gate]
}
run "control_phase_uses_signed_effective_cutoff" {
  command = apply

  variables {
    apply_timestamp_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    destroy_deadline_utc               = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "24h"))
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    control_readiness_gate             = true
    cost_gate                          = true
    live_window_gate                   = true
    phase_c_live_preflight_bundle_path = "/tmp/phase-c-live-preflight-test-bundle.json"
    recova_f12_mtls_endpoint_path      = "https://f12-g008.recova.internal/origin"
    live_window_start_utc              = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    live_window_end_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
    cost_evidence = {
      estimated_total_krw = 1
      observed_total_krw  = 1
      recorded_at_utc     = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
      expires_at_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      evidence_sha256     = "abababababababababababababababababababababababababababababababab"
      signer_key_id       = "g008-cost-test-signer"
    }
  }

  override_data {
    target          = data.external.phase_c_live_plan[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      }
    }
  }

  override_data {
    target          = data.external.phase_c_live_apply[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      }
    }
  }

  assert {
    condition = (
      local.control_phase_ready &&
      local.cutoff_required &&
      !local.bounded_live_ready &&
      local.watchdog_cutoff_utc == local.cost_evidence_watchdog_valid_until_utc &&
      data.external.phase_c_live_apply[0].result.effective_cutoff_utc == local.watchdog_cutoff_utc &&
      google_compute_instance.candidate.desired_status == "TERMINATED" &&
      google_compute_instance.candidate.service_account[0].email == local.service_account_emails.runtime &&
      google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      length(google_cloud_scheduler_job.watchdog_stop_candidate) == 1 &&
      length(google_cloud_scheduler_job.watchdog_disable_traffic) == 8
    )
    error_message = "Control readiness may arm watchdogs but must keep the workload terminated and every allow disabled until the complete execution seal."
  }
}

run "control_phase_cutoff_mismatch_hard_fails" {
  command   = apply
  state_key = "control-phase-cutoff-mismatch"

  variables {
    apply_timestamp_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    destroy_deadline_utc               = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "24h"))
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    control_readiness_gate             = true
    cost_gate                          = true
    live_window_gate                   = true
    phase_c_live_preflight_bundle_path = "/tmp/phase-c-live-preflight-test-bundle.json"
    recova_f12_mtls_endpoint_path      = "https://f12-g008.recova.internal/origin"
    live_window_start_utc              = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    live_window_end_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
    cost_evidence = {
      estimated_total_krw = 1
      observed_total_krw  = 1
      recorded_at_utc     = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
      expires_at_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "1h"))
      evidence_sha256     = "abababababababababababababababababababababababababababababababab"
      signer_key_id       = "g008-cost-test-signer"
    }
  }

  override_data {
    target          = data.external.phase_c_live_plan[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "1h"))
      }
    }
  }

  override_data {
    target          = data.external.phase_c_live_apply[0]
    override_during = plan
    values = {
      result = {
        verified                  = "true"
        bundle_sha256             = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256 = "1616161616161616161616161616161616161616161616161616161616161616"
        expires_at_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      }
    }
  }

  assert {
    condition = (
      local.cutoff_required &&
      data.external.phase_c_live_apply[0].result.effective_cutoff_utc != local.watchdog_cutoff_utc
    )
    error_message = "Cutoff mismatch fixture must exercise distinct effective and watchdog cutoffs."
  }
  expect_failures = [terraform_data.phase_c_live_apply_gate[0]]
}

run "execution_trigger_rejects_latest_version" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/latest"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}

run "execution_trigger_rejects_non_numeric_version" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/v11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}
run "execution_trigger_rejects_manifest_alias" {
  command = plan
  variables {
    g008_bootstrap_manifest_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}

run "execution_trigger_rejects_wrong_project" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/other-project/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}

run "execution_trigger_rejects_wrong_nonce_digest" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "1616161616161616161616161616161616161616161616161616161616161616"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}
run "execution_trigger_rejects_mismatched_activation_receipt" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    }
  }
  expect_failures = [var.g008_execution_trigger]
}

run "live_gate_without_execution_trigger_hard_fails" {
  command = plan
  variables {
    dependency_manifest_gate     = true
    candidate_gate               = true
    endpoint_identity_gate       = true
    cost_gate                    = true
    live_window_gate             = true
    external_ip_reservation_gate = true
    network_path_arm_gate        = true
    sip_register_gate            = true
    g008_execution_trigger       = null
  }
  expect_failures = [
    var.sip_register_gate,
  ]
}

run "execution_trigger_metadata_is_immutable_and_redacted" {
  command = plan
  variables {
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }

  assert {
    condition = (
      google_compute_instance.candidate.metadata["g008-bootstrap-manifest-handle"] == nonsensitive(var.g008_bootstrap_manifest_version_resource_name) &&
      google_compute_instance.candidate.metadata["g008-bootstrap-manifest-binding-sha256"] == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      var.activation_receipt.successor_review_payload_digest == var.candidate_manifest.review_payload_digest &&
      google_compute_instance.candidate.metadata["g008-review-payload-digest"] == var.activation_receipt.successor_review_payload_digest &&
      google_compute_instance.candidate.metadata["g008-execution-nonce-sha256"] == nonsensitive(var.g008_execution_trigger.execution_nonce_sha256) &&
      google_compute_instance.candidate.metadata["g008-execution-request-sha256"] == nonsensitive(var.g008_execution_trigger.execution_request_sha256) &&
      google_compute_instance.candidate.metadata["g008-operator-credential-sha256"] == nonsensitive(var.g008_execution_trigger.operator_credential_sha256) &&
      google_compute_instance.candidate.metadata["g008-execution-runner-sha256"] == nonsensitive(var.g008_execution_trigger.execution_runner_sha256) &&
      google_compute_instance.candidate.metadata["g008-trusted-keyset-sha256"] == nonsensitive(var.g008_execution_trigger.trusted_keyset_sha256) &&
      google_compute_instance.candidate.metadata["g008-provider-script-sha256"] == nonsensitive(var.g008_execution_trigger.provider_script_sha256) &&
      google_compute_instance.candidate.metadata["g008-one-shot-marker-sha256"] == sha256(jsonencode({
        run_id                          = var.run_id
        candidate_manifest_sha256       = var.candidate_manifest.manifest_sha256
        successor_review_payload_digest = var.activation_receipt.successor_review_payload_digest
        candidate_receipt_sha256        = var.g009_candidate_receipt.candidate_receipt_sha256
      })) &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-activation-contract") &&
      !strcontains(jsonencode(google_compute_instance.candidate.metadata), nonsensitive(var.g008_execution_trigger.sip_username_secret_version)) &&
      !strcontains(jsonencode(google_compute_instance.candidate.metadata), nonsensitive(var.g008_execution_trigger.sip_password_secret_version)) &&
      !strcontains(jsonencode(google_compute_instance.candidate.metadata), nonsensitive(var.g008_execution_trigger.sip_realm_secret_version)) &&
      !strcontains(jsonencode(google_compute_instance.candidate.metadata), nonsensitive(var.g008_execution_trigger.target_secret_version)) &&
      !strcontains(lower(join(":", [
        google_compute_instance.candidate.metadata["g008-bootstrap-manifest-handle"],
        google_compute_instance.candidate.metadata["g008-bootstrap-manifest-binding-sha256"],
        google_compute_instance.candidate.metadata["g008-execution-nonce-sha256"],
        google_compute_instance.candidate.metadata["g008-one-shot-marker-sha256"],
      ])), "password") &&
      !strcontains(lower(join(":", [
        google_compute_instance.candidate.metadata["g008-bootstrap-manifest-handle"],
        google_compute_instance.candidate.metadata["g008-bootstrap-manifest-binding-sha256"],
        google_compute_instance.candidate.metadata["g008-execution-nonce-sha256"],
        google_compute_instance.candidate.metadata["g008-one-shot-marker-sha256"],
      ])), "sip:") &&
      google_compute_instance.candidate.metadata["g008-exact-binding-receipt-sha256"] == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] == "" &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] == ""
    )
    error_message = "Disabled execution metadata must expose only the opaque manifest handle and binding digests, with no secret inventory or runtime secret authority."
  }
}

run "live_gate_without_external_iam_receipt_hard_fails" {
  command = plan

  variables {
    sip_register_gate                      = true
    g008_external_iam_provisioning_receipt = null
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "2525252525252525252525252525252525252525252525252525252525252525"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
  }

  expect_failures = [
    var.sip_register_gate,
  ]
}

run "self_derived_external_iam_receipt_hard_fails_validation" {
  command = plan

  variables {
    g008_external_iam_provisioning_receipt = {
      schema_version                            = "recova-g008-external-iam-provisioning-receipt-v1"
      bootstrap_manifest_binding_sha256         = "1111111111111111111111111111111111111111111111111111111111111111"
      runtime_service_account_email             = "onnuri-c-g008-disable-runtime@slit-497603.iam.gserviceaccount.com"
      transaction_service_account_email         = "onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
      live_window_start_utc                     = "2030-07-15T01:00:00Z"
      live_window_end_utc                       = "2030-07-15T02:00:00Z"
      destruction_deadline_utc                  = "2030-07-16T01:00:00Z"
      candidate_manifest_sha256                 = "8888888888888888888888888888888888888888888888888888888888888888"
      review_payload_digest                     = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      run_id                                    = "g008-disabled-smoke"
      activation_nonce_sha256                   = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      activation_receipt_sha256                 = "1313131313131313131313131313131313131313131313131313131313131313"
      exact_policy_result_sha256                = "1111111111111111111111111111111111111111111111111111111111111111"
      provisioning_outcome                      = "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS"
      issuer_key_id                             = "external-g008-iam-provisioner-v1"
      issuer_key_fingerprint_sha256             = "2424242424242424242424242424242424242424242424242424242424242424"
      issued_at_utc                             = "2030-07-15T00:00:00Z"
      expires_at_utc                            = "2030-07-15T03:00:00Z"
      canonical_receipt_sha256                  = "1111111111111111111111111111111111111111111111111111111111111111"
      cryptographic_verification_receipt_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
    }
  }

  expect_failures = [var.g008_external_iam_provisioning_receipt]
}
run "live_external_exact_iam_receipt_is_redacted_and_legacy_iam_is_bounded" {
  command = plan

  variables {
    apply_timestamp_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    destroy_deadline_utc               = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "24h"))
    dependency_manifest_gate           = true
    candidate_gate                     = true
    endpoint_identity_gate             = true
    external_ip_reservation_gate       = true
    network_path_arm_gate              = true
    control_readiness_gate             = true
    cost_gate                          = true
    live_window_gate                   = true
    sip_register_gate                  = true
    rtp_gate                           = true
    outbound_call_gate                 = true
    inbound_call_gate                  = true
    phase_c_live_preflight_bundle_path = "/tmp/phase-c-live-preflight-test-bundle.json"
    recova_f12_mtls_endpoint_path      = "https://f12-g008.recova.internal/origin"
    live_window_start_utc              = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
    live_window_end_utc                = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
    cost_evidence = {
      estimated_total_krw = 1
      observed_total_krw  = 1
      recorded_at_utc     = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
      expires_at_utc      = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      evidence_sha256     = "abababababababababababababababababababababababababababababababab"
      signer_key_id       = "g008-cost-test-signer"
    }
    g008_execution_trigger = {
      schema_version                          = "recova-g008-execution-seal-v1"
      execution_request_version_resource_name = "projects/slit-497603/secrets/g008-execution-request/versions/11"
      sip_username_secret_version             = "projects/slit-497603/secrets/g008-sip-username/versions/12"
      sip_password_secret_version             = "projects/slit-497603/secrets/g008-sip-password/versions/13"
      sip_realm_secret_version                = "projects/slit-497603/secrets/g008-sip-realm/versions/14"
      target_secret_version                   = "projects/slit-497603/secrets/g008-execution-target/versions/15"
      execution_nonce_secret_version          = "projects/slit-497603/secrets/g008-execution-nonce/versions/16"
      operator_credential_secret_version      = "projects/slit-497603/secrets/g008-operator-credential/versions/17"
      execution_request_sha256                = "2323232323232323232323232323232323232323232323232323232323232323"
      sip_username_sha256                     = "2828282828282828282828282828282828282828282828282828282828282828"
      sip_password_sha256                     = "2929292929292929292929292929292929292929292929292929292929292929"
      sip_realm_sha256                        = "3030303030303030303030303030303030303030303030303030303030303030"
      target_sha256                           = "3131313131313131313131313131313131313131313131313131313131313131"
      execution_nonce_sha256                  = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      operator_credential_sha256              = "2424242424242424242424242424242424242424242424242424242424242424"
      execution_runner_sha256                 = "701abd428b6c5fa8058f69f87cd620dc605b2ab8dd13a96d881c925e0b39e202"
      trusted_keyset_sha256                   = "2626262626262626262626262626262626262626262626262626262626262626"
      provider_script_sha256                  = "2727272727272727272727272727272727272727272727272727272727272727"
      candidate_receipt_sha256                = "4444444444444444444444444444444444444444444444444444444444444444"
      review_payload_digest                   = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      candidate_manifest_sha256               = "8888888888888888888888888888888888888888888888888888888888888888"
      runtime_image_digest                    = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
      execution_runner_receipt_sha256         = "1515151515151515151515151515151515151515151515151515151515151515"
      activation_receipt_sha256               = "1313131313131313131313131313131313131313131313131313131313131313"
    }
    g008_external_iam_provisioning_receipt = {
      schema_version                    = "recova-g008-external-iam-provisioning-receipt-v1"
      bootstrap_manifest_binding_sha256 = "80e1ea4433a9d5d2f12471b438f0efb0b919c9a0a510a6b6a0a41f0a7b056de0"
      runtime_service_account_email     = "onnuri-c-g008-disable-runtime@slit-497603.iam.gserviceaccount.com"
      transaction_service_account_email = "onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
      live_window_start_utc             = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
      live_window_end_utc               = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      destruction_deadline_utc          = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "24h"))
      candidate_manifest_sha256         = "8888888888888888888888888888888888888888888888888888888888888888"
      review_payload_digest             = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
      run_id                            = "g008-disabled-smoke"
      activation_nonce_sha256           = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
      activation_receipt_sha256         = "1313131313131313131313131313131313131313131313131313131313131313"
      exact_policy_result_sha256        = "2323232323232323232323232323232323232323232323232323232323232323"
      provisioning_outcome              = "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS"
      issuer_key_id                     = "recova-g008-iam-provisioning-v1"
      issuer_key_fingerprint_sha256     = "619ea6c111ac0172161251dba08843b4a182e412a1f66a43a3418abe793aa5ac"
      issued_at_utc                     = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "-1h"))
      expires_at_utc                    = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "3h"))
      canonical_receipt_sha256 = sha256(jsonencode({
        schema_version                    = "recova-g008-external-iam-provisioning-receipt-v1"
        bootstrap_manifest_binding_sha256 = "80e1ea4433a9d5d2f12471b438f0efb0b919c9a0a510a6b6a0a41f0a7b056de0"
        runtime_service_account_email     = "onnuri-c-g008-disable-runtime@slit-497603.iam.gserviceaccount.com"
        transaction_service_account_email = "onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
        live_window_start_utc             = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timestamp())
        live_window_end_utc               = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        destruction_deadline_utc          = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "24h"))
        candidate_manifest_sha256         = "8888888888888888888888888888888888888888888888888888888888888888"
        review_payload_digest             = "sha256:35c604e3bd5991b91bb2cef426c231a26f00672fa6fed05d07d62691ba92f5b0"
        run_id                            = "g008-disabled-smoke"
        activation_nonce_sha256           = "953c0dcda93b27ea71f26b0c614378936f0eeae6a7f6a54ad674bbca53e2cf2b"
        activation_receipt_sha256         = "1313131313131313131313131313131313131313131313131313131313131313"
        provisioning_outcome              = "EXACT_BOUNDED_POLICY_APPLIED_NO_BROADER_BINDINGS"
        exact_policy_result_sha256        = "2323232323232323232323232323232323232323232323232323232323232323"
        issuer_key_id                     = "recova-g008-iam-provisioning-v1"
        issuer_key_fingerprint_sha256     = "619ea6c111ac0172161251dba08843b4a182e412a1f66a43a3418abe793aa5ac"
        issued_at_utc                     = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "-1h"))
        expires_at_utc                    = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "3h"))
      }))
      cryptographic_verification_receipt_sha256 = "2626262626262626262626262626262626262626262626262626262626262626"
    }
    g008_external_iam_trusted_issuer_key_id                 = "recova-g008-iam-provisioning-v1"
    g008_external_iam_trusted_issuer_key_fingerprint_sha256 = "619ea6c111ac0172161251dba08843b4a182e412a1f66a43a3418abe793aa5ac"
  }

  override_data {
    target          = data.external.phase_c_live_plan[0]
    override_during = plan
    values = {
      result = {
        verified                        = "true"
        bundle_sha256                   = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256       = "1616161616161616161616161616161616161616161616161616161616161616"
        iam_provisioning_payload_sha256 = "2626262626262626262626262626262626262626262626262626262626262626"
        expires_at_utc                  = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      }
    }
  }

  override_data {
    target          = data.external.phase_c_live_apply[0]
    override_during = plan
    values = {
      result = {
        verified                        = "true"
        bundle_sha256                   = "1515151515151515151515151515151515151515151515151515151515151515"
        authorized_context_sha256       = "1616161616161616161616161616161616161616161616161616161616161616"
        iam_provisioning_payload_sha256 = "2626262626262626262626262626262626262626262626262626262626262626"
        expires_at_utc                  = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
        effective_cutoff_utc            = formatdate("YYYY-MM-DD'T'hh:00:00'Z'", timeadd(timestamp(), "2h"))
      }
    }
  }

  # g008_execution_trigger is diagnosed by its input variable validation.
  assert {
    condition     = local.g008_authority_ready
    error_message = "G008 authority readiness conjunct must be true."
  }

  assert {
    condition     = local.g008_secrets_ready
    error_message = "G008 secrets readiness conjunct must be true."
  }

  assert {
    condition     = local.g008_external_iam_receipt_context_valid
    error_message = "G008 external IAM receipt context-valid conjunct must be true."
  }

  assert {
    condition     = local.g008_external_iam_receipt_fresh
    error_message = "G008 external IAM receipt freshness conjunct must be true."
  }

  assert {
    condition     = local.g008_external_iam_canonical_digest_valid
    error_message = "G008 external IAM receipt canonical-digest-valid conjunct must be true."
  }

  assert {
    condition     = local.g008_external_iam_verification_digest_valid
    error_message = "G008 external IAM receipt verification-digest-valid conjunct must be true."
  }

  assert {
    condition     = local.exact_four_stage_contract_ready
    error_message = "Exact four-stage contract readiness conjunct must be true."
  }

  assert {
    condition     = local.sip_ready
    error_message = "SIP readiness conjunct must be true."
  }

  assert {
    condition     = local.rtp_ready
    error_message = "RTP readiness conjunct must be true."
  }

  override_resource {
    target          = google_service_account.transaction_authority
    override_during = plan
    values = {
      name   = "projects/slit-497603/serviceAccounts/onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
      email  = "onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
      member = "serviceAccount:onnuri-c-g008-disable-txn-auth@slit-497603.iam.gserviceaccount.com"
    }
  }

  assert {
    condition = (
      local.bounded_live_ready &&
      local.outbound_live_enabled &&
      local.inbound_live_enabled &&
      local.exact_four_stage_contract_ready &&
      google_compute_instance.candidate.desired_status == "RUNNING" &&
      !google_compute_firewall.recova_f1_https_ingress.disabled &&
      !google_compute_firewall.sip_ingress[0].disabled &&
      !google_compute_firewall.sip_egress[0].disabled &&
      !google_compute_firewall.rtp_ingress[0].disabled &&
      !google_compute_firewall.rtp_egress[0].disabled &&
      !google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      !google_compute_firewall.facade_wss_egress[0].disabled &&
      length(google_compute_firewall.restricted_google_egress) == 1 &&
      toset(google_compute_firewall.restricted_google_egress[0].destination_ranges) == toset(["199.36.153.4/30"]) &&
      toset(one(google_compute_firewall.restricted_google_egress[0].allow).ports) == toset(["443"]) &&
      toset(local.watchdog_traffic_firewall_names) == toset([
        local.immutable_names.recova_ingress_firewall,
        local.immutable_names.sip_ingress_firewall,
        local.immutable_names.sip_egress_firewall,
        local.immutable_names.rtp_ingress_firewall,
        local.immutable_names.rtp_egress_firewall,
        local.immutable_names.recova_control_egress_firewall,
        local.immutable_names.recova_media_egress_firewall,
        local.immutable_names.google_out_firewall,
      ]) &&
      strcontains(google_project_iam_member.containment.condition[0].expression, "global/firewalls/${local.immutable_names.google_out_firewall}") &&
      length(google_service_account_iam_member.runtime_mints_transaction_token) == 1
    )
    error_message = "Bounded-live runtime and network gate must be fully active."
  }

  assert {
    condition = (
      nonsensitive(local.phase_c_live_expected_context.bootstrap.g008_bootstrap_manifest_handle) == nonsensitive(local.g008_bootstrap_manifest_handle) &&
      nonsensitive(local.phase_c_live_expected_context.bootstrap.g008_bootstrap_manifest_binding_sha256) == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      local.phase_c_live_expected_context.successor_review_payload_digest == var.activation_receipt.successor_review_payload_digest &&
      local.phase_c_live_expected_context.successor_review_payload_digest == var.candidate_manifest.review_payload_digest &&
      local.phase_c_live_expected_context.bootstrap.review_payload_digest == var.candidate_manifest.review_payload_digest &&
      local.phase_c_live_expected_context.bootstrap.successor_review_payload_digest == var.activation_receipt.successor_review_payload_digest &&
      toset(nonsensitive(keys(local.phase_c_live_expected_context.bootstrap))) == toset(["g008_bootstrap_manifest_handle", "g008_bootstrap_manifest_binding_sha256", "review_payload_digest", "successor_review_payload_digest"]) &&
      toset(nonsensitive(keys(local.phase_c_live_expected_context.secrets))) == toset(["legacy"]) &&
      toset(keys(local.phase_c_live_expected_context.candidate_boot)) == toset(["image_self_link", "image_id", "image_generation", "source_sha256", "export_sha256", "derivative_sha256", "runtime_image_digest", "facade_image_digest", "candidate_manifest_sha256", "candidate_receipt_sha256", "candidate_receipt_signature_base64", "candidate_receipt_signer_key_id", "candidate_receipt_verification_key_sha256", "candidate_receipt_issued_at_utc", "candidate_receipt_expires_at_utc", "compose_sha256", "startup_sha256"]) &&
      local.phase_c_live_expected_context.candidate_boot.image_self_link == var.g009_candidate_receipt.image_self_link &&
      local.phase_c_live_expected_context.candidate_boot.image_id == tostring(var.g009_candidate_receipt.image_id) &&
      local.phase_c_live_expected_context.candidate_boot.image_generation == tostring(var.g009_candidate_receipt.image_generation) &&
      local.phase_c_live_expected_context.candidate_boot.runtime_image_digest == var.g009_candidate_receipt.runtime_image_digest &&
      local.phase_c_live_expected_context.candidate_boot.source_sha256 == var.g009_candidate_receipt.source_sha256 &&
      local.phase_c_live_expected_context.execution.versions.request == var.g008_execution_trigger.execution_request_version_resource_name &&
      local.phase_c_live_expected_context.execution.versions.sip_username == var.g008_execution_trigger.sip_username_secret_version &&
      local.phase_c_live_expected_context.execution.versions.sip_password == var.g008_execution_trigger.sip_password_secret_version &&
      local.phase_c_live_expected_context.execution.versions.sip_realm == var.g008_execution_trigger.sip_realm_secret_version &&
      local.phase_c_live_expected_context.execution.versions.target == var.g008_execution_trigger.target_secret_version &&
      local.phase_c_live_expected_context.execution.versions.execution_nonce == var.g008_execution_trigger.execution_nonce_secret_version &&
      local.phase_c_live_expected_context.execution.versions.operator_credential == var.g008_execution_trigger.operator_credential_secret_version &&
      local.phase_c_live_expected_context.execution.review_payload_digest == var.candidate_manifest.review_payload_digest &&
      local.phase_c_live_expected_context.execution.candidate_manifest_sha256 == var.candidate_manifest.manifest_sha256 &&
      local.phase_c_live_expected_context.execution.runtime_image_digest == var.g009_candidate_receipt.runtime_image_digest &&
      local.phase_c_live_expected_context.execution.candidate_receipt_sha256 == var.g009_candidate_receipt.candidate_receipt_sha256 &&
      toset(keys(var.g008_secret_version_resource_names)) == local.g008_all_secret_keys &&
      length(local.g008_secret_mounts) == 29 &&
      length(local.g008_all_secret_keys) == 36 &&
      local.g008_execution_input_secret_keys == toset([
        "execution_request",
        "execution_sip_username",
        "execution_sip_password",
        "execution_sip_realm",
        "execution_target",
        "execution_nonce",
        "operator_credential",
      ]) &&
      toset(keys(local.g008_secret_mounts)) == local.g008_required_secret_keys &&
      length(setintersection(toset(keys(local.g008_secret_mounts)), local.g008_execution_input_secret_keys)) == 0
    )
    error_message = "Signed bootstrap and candidate context must contain the exact current receipt fields without raw execution inventory."
  }

  assert {
    condition = (
      local.g008_external_iam_receipt_ready &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] == var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256 &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] == var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256 &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] != local.g008_bootstrap_manifest_binding_sha256 &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] != local.g008_bootstrap_manifest_binding_sha256 &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-secret-versions") &&
      toset(keys(google_secret_manager_secret_iam_member.runtime)) == local.runtime_secret_keys &&
      alltrue([
        for purpose, binding in google_secret_manager_secret_iam_member.runtime :
        binding.condition[0].expression == format(
          "resource.name == '%s' && request.time >= timestamp('%s') && request.time < timestamp('%s') && request.time < timestamp('%s')",
          local.bound_legacy_secret_versions[purpose],
          var.live_window_start_utc,
          var.live_window_end_utc,
          var.destroy_deadline_utc,
        )
      ]) &&
      toset(google_project_iam_custom_role.runtime.permissions) == toset(["secretmanager.versions.access"]) &&
      local.g008_provider_child_secret_keys == toset(["dispatch_es256_public_key", "media_es256_public_key"]) &&
      !contains(local.g008_provider_child_secret_keys, "registration_attestation_es256_public_key") &&
      contains(local.g008_backend_secret_keys, "registration_attestation_es256_public_key") &&
      !contains(local.g008_backend_secret_keys, "registration_attestation_es256_private_key") &&
      contains(local.g008_transaction_authority_secret_keys, "registration_attestation_es256_private_key") &&
      !contains(local.g008_runtime_secret_keys, "registration_attestation_es256_private_key")
    )
    error_message = "Terraform must retain only exact bounded legacy runtime bindings while G008 exact-version IAM stays external and requires independent redacted canonical and cryptographic verification receipt digests."
  }

  assert {
    condition = (
      local.bounded_live_ready &&
      local.outbound_live_enabled &&
      local.inbound_live_enabled &&
      local.exact_four_stage_contract_ready &&
      google_compute_instance.candidate.desired_status == "RUNNING" &&
      !google_compute_firewall.recova_f1_https_ingress.disabled &&
      !google_compute_firewall.sip_ingress[0].disabled &&
      !google_compute_firewall.sip_egress[0].disabled &&
      !google_compute_firewall.rtp_ingress[0].disabled &&
      !google_compute_firewall.rtp_egress[0].disabled &&
      !google_compute_firewall.facade_f2_f12_egress[0].disabled &&
      !google_compute_firewall.facade_wss_egress[0].disabled &&
      length(google_compute_firewall.restricted_google_egress) == 1 &&
      toset(google_compute_firewall.restricted_google_egress[0].destination_ranges) == toset(["199.36.153.4/30"]) &&
      toset(one(google_compute_firewall.restricted_google_egress[0].allow).ports) == toset(["443"]) &&
      length(google_service_account_iam_member.runtime_mints_transaction_token) == 1
    )
    error_message = "Bounded-live runtime and network gate must be fully active."
  }

  assert {
    condition = (
      nonsensitive(local.phase_c_live_expected_context.bootstrap.g008_bootstrap_manifest_handle) == nonsensitive(local.g008_bootstrap_manifest_handle) &&
      nonsensitive(local.phase_c_live_expected_context.bootstrap.g008_bootstrap_manifest_binding_sha256) == nonsensitive(local.g008_bootstrap_manifest_binding_sha256) &&
      local.phase_c_live_expected_context.successor_review_payload_digest == var.activation_receipt.successor_review_payload_digest &&
      local.phase_c_live_expected_context.successor_review_payload_digest == var.candidate_manifest.review_payload_digest &&
      local.phase_c_live_expected_context.bootstrap.review_payload_digest == var.candidate_manifest.review_payload_digest &&
      local.phase_c_live_expected_context.bootstrap.successor_review_payload_digest == var.activation_receipt.successor_review_payload_digest &&
      toset(nonsensitive(keys(local.phase_c_live_expected_context.bootstrap))) == toset(["g008_bootstrap_manifest_handle", "g008_bootstrap_manifest_binding_sha256", "review_payload_digest", "successor_review_payload_digest"]) &&
      toset(nonsensitive(keys(local.phase_c_live_expected_context.secrets))) == toset(["legacy"]) &&
      toset(keys(local.phase_c_live_expected_context.candidate_boot)) == toset(["image_self_link", "image_id", "image_generation", "source_sha256", "export_sha256", "derivative_sha256", "runtime_image_digest", "facade_image_digest", "candidate_manifest_sha256", "candidate_receipt_sha256", "candidate_receipt_signature_base64", "candidate_receipt_signer_key_id", "candidate_receipt_verification_key_sha256", "candidate_receipt_issued_at_utc", "candidate_receipt_expires_at_utc", "compose_sha256", "startup_sha256"]) &&
      local.phase_c_live_expected_context.candidate_boot.source_sha256 == var.g009_candidate_receipt.source_sha256 &&
      local.phase_c_live_expected_context.candidate_boot.compose_sha256 == filesha256("${path.module}/../../deploy/onnuri-jambonz-oss/compose.yaml") &&
      local.phase_c_live_expected_context.candidate_boot.startup_sha256 == filesha256("${path.module}/startup-g008.sh") &&
      toset(keys(var.g008_secret_version_resource_names)) == local.g008_all_secret_keys &&
      length(local.g008_secret_mounts) == 29 &&
      length(local.g008_all_secret_keys) == 36 &&
      toset(keys(local.g008_secret_mounts)) == local.g008_required_secret_keys &&
      length(setintersection(toset(keys(local.g008_secret_mounts)), local.g008_execution_input_secret_keys)) == 0 &&
      local.g008_external_iam_receipt_context_valid &&
      local.g008_external_iam_receipt_fresh &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-canonical-sha256"] == var.g008_external_iam_provisioning_receipt.canonical_receipt_sha256 &&
      google_compute_instance.candidate.metadata["g008-iam-receipt-verification-sha256"] == var.g008_external_iam_provisioning_receipt.cryptographic_verification_receipt_sha256 &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-request-version") &&
      !contains(keys(google_compute_instance.candidate.metadata), "g008-execution-secret-versions") &&
      local.phase_c_live_expected_context.execution.versions.request == var.g008_execution_trigger.execution_request_version_resource_name &&
      local.phase_c_live_expected_context.execution.versions.sip_username == var.g008_execution_trigger.sip_username_secret_version &&
      local.phase_c_live_expected_context.execution.versions.sip_password == var.g008_execution_trigger.sip_password_secret_version &&
      local.phase_c_live_expected_context.execution.versions.sip_realm == var.g008_execution_trigger.sip_realm_secret_version &&
      local.phase_c_live_expected_context.execution.versions.target == var.g008_execution_trigger.target_secret_version &&
      local.phase_c_live_expected_context.execution.versions.execution_nonce == var.g008_execution_trigger.execution_nonce_secret_version &&
      local.phase_c_live_expected_context.execution.versions.operator_credential == var.g008_execution_trigger.operator_credential_secret_version &&
      local.phase_c_live_expected_context.execution.content_sha256.request == var.g008_execution_trigger.execution_request_sha256 &&
      local.phase_c_live_expected_context.execution.content_sha256.operator_credential == var.g008_execution_trigger.operator_credential_sha256
    )
    error_message = "Opaque bootstrap context and two independent redacted IAM receipt digests must match without projecting raw execution inventory into Terraform-managed metadata or expected context."
  }

  assert {
    condition = (
      local.g008_provider_child_secret_keys == toset(["dispatch_es256_public_key", "media_es256_public_key"]) &&
      !contains(local.g008_provider_child_secret_keys, "registration_attestation_es256_public_key") &&
      contains(local.g008_backend_secret_keys, "registration_attestation_es256_public_key") &&
      !contains(local.g008_backend_secret_keys, "registration_attestation_es256_private_key") &&
      contains(local.g008_transaction_authority_secret_keys, "registration_attestation_es256_private_key") &&
      !contains(local.g008_runtime_secret_keys, "registration_attestation_es256_private_key")
    )
    error_message = "Transaction attestation purpose must remain isolated while its exact-version IAM authority stays outside Terraform state."
  }
}