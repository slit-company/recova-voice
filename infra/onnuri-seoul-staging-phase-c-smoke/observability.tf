locals {
  evidence_bucket_id = "${local.name_stem}-evidence"
  evidence_view_name = "${local.name_stem}-activity"
  audit_log_filter = join("\n", [
    "resource.type=(\"gce_instance\" OR \"gce_firewall_rule\")",
    "log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/system_event\")",
    "protoPayload.resourceName:\"${local.name_stem}\"",
  ])
}

resource "google_logging_project_bucket_config" "evidence" {
  project          = var.project_id
  location         = "global"
  bucket_id        = local.evidence_bucket_id
  retention_days   = 7
  description      = "Short-lived Phase C administrative evidence only; no packet, audio, SIP, token, peer, or free-text application logs."
  enable_analytics = false
}

resource "google_logging_project_sink" "evidence" {
  name                   = "${local.name_stem}-evidence"
  project                = var.project_id
  destination            = "logging.googleapis.com/${google_logging_project_bucket_config.evidence.id}"
  filter                 = local.audit_log_filter
  unique_writer_identity = true
  description            = "Allowlisted Phase C Compute administrative activity and system events only."
}


resource "google_logging_log_view" "evidence" {
  name        = local.evidence_view_name
  bucket      = google_logging_project_bucket_config.evidence.id
  description = "Phase C administrative activity only."
  filter      = "SOURCE(\"projects/${var.project_id}\") AND LOG_ID(\"cloudaudit.googleapis.com%2Factivity\")"
}

resource "google_logging_log_view_iam_member" "evidence" {
  parent   = google_logging_log_view.evidence.parent
  location = google_logging_log_view.evidence.location
  bucket   = google_logging_log_view.evidence.bucket
  name     = google_logging_log_view.evidence.name
  role     = google_project_iam_custom_role.evidence.name
  member   = google_service_account.evidence.member

  condition {
    title       = "read-dedicated-evidence-before-expiry"
    description = "Evidence access is limited to the dedicated allowlisted log view and immutable Phase C TTL."
    expression  = "request.time < timestamp('${var.destroy_deadline_utc}')"
  }
}

resource "google_logging_metric" "containment_stop" {
  name        = "${local.name_stem}-containment-stop"
  project     = var.project_id
  description = "Count stop operations against the one named Phase C VM; exports no labels."
  filter = join(" AND ", [
    "log_id(\"cloudaudit.googleapis.com/activity\")",
    "protoPayload.methodName=\"v1.compute.instances.stop\"",
    "protoPayload.resourceName:\"/instances/${local.immutable_names.instance}\"",
  ])

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "Phase C named VM stop count"
  }
}

resource "google_logging_metric" "firewall_mutation" {
  name        = "${local.name_stem}-firewall-mutation"
  project     = var.project_id
  description = "Count administrative updates to named Phase C firewall rules; exports no labels."
  filter = join(" AND ", [
    "log_id(\"cloudaudit.googleapis.com/activity\")",
    "protoPayload.methodName=(\"v1.compute.firewalls.patch\" OR \"v1.compute.firewalls.update\")",
    "protoPayload.resourceName:\"${local.name_stem}\"",
  ])

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "Phase C firewall mutation count"
  }
}

resource "google_monitoring_alert_policy" "unexpected_firewall_mutation" {
  project      = var.project_id
  display_name = "${local.name_stem} unexpected firewall mutation"
  combiner     = "OR"
  enabled      = true
  severity     = "CRITICAL"

  documentation {
    content   = "A named Phase C firewall rule changed. G001 grants no firewall mutation authority; keep rules disabled and stop the named VM."
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Any named Phase C firewall update"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.firewall_mutation.name}\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  user_labels = {
    application = "recova"
    environment = "staging"
    phase       = "c-smoke"
    category    = "containment"
  }
}

resource "google_monitoring_alert_policy" "containment_stop" {
  project      = var.project_id
  display_name = "${local.name_stem} containment stop observed"
  combiner     = "OR"
  enabled      = true
  severity     = "WARNING"

  documentation {
    content   = "The dedicated containment identity stopped the named Phase C VM. Confirm dispatch, REGISTER, and media remain closed."
    mime_type = "text/markdown"
  }

  conditions {
    display_name = "Named Phase C VM stopped"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.containment_stop.name}\" AND resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period     = "60s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
      }

      trigger {
        count = 1
      }
    }
  }

  user_labels = {
    application = "recova"
    environment = "staging"
    phase       = "c-smoke"
    category    = "containment"
  }
}
check "observability_is_bounded" {
  assert {
    condition = (
      google_logging_project_bucket_config.evidence.retention_days == 7 &&
      google_logging_project_bucket_config.evidence.enable_analytics == false &&
      length(google_logging_metric.containment_stop.metric_descriptor[0].labels) == 0 &&
      length(google_logging_metric.firewall_mutation.metric_descriptor[0].labels) == 0
    )
    error_message = "Evidence retention must remain seven days with analytics off and metrics must export no caller-controlled labels."
  }
}
