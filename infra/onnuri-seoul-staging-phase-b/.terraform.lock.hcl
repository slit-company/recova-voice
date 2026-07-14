# This lock file is intentionally source-only. The offline verifier rejects a
# mirror whose package bytes do not match these checksums.
provider "registry.terraform.io/hashicorp/google" {
  version     = "7.39.0"
  constraints = "= 7.39.0"
  hashes = [
    "zh:0000000000000000000000000000000000000000000000000000000000000000",
  ]
}
