mock_provider "google" {}
run "reject_empty_project_id" {
  command = plan

  variables {
    project_id               = ""
    region                   = "asia-northeast3"
    subnet_ipv4_cidr         = "10.73.96.0/24"
    deployer_service_account = "phaseb-deployer@slit-497603.iam.gserviceaccount.com"
  }

  expect_failures = [var.project_id]
}

run "reject_non_rfc1918_subnet" {
  command = plan

  variables {
    project_id               = "slit-497603"
    region                   = "asia-northeast3"
    subnet_ipv4_cidr         = "203.0.113.0/24"
    deployer_service_account = "phaseb-deployer@slit-497603.iam.gserviceaccount.com"
  }

  expect_failures = [var.subnet_ipv4_cidr]
}

run "reject_non_24_subnet" {
  command = plan

  variables {
    project_id               = "slit-497603"
    region                   = "asia-northeast3"
    subnet_ipv4_cidr         = "10.0.0.0/25"
    deployer_service_account = "phaseb-deployer@slit-497603.iam.gserviceaccount.com"
  }

  expect_failures = [var.subnet_ipv4_cidr]
}
