terraform {
  # Bucket and prefix are supplied by the leader-owned backend configuration.
  backend "gcs" {}
}
