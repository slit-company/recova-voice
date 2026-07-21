terraform {
  required_version = "= 1.15.8"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.39.0"
    }
    external = {
      source  = "hashicorp/external"
      version = "= 2.3.5"
    }
  }
}
