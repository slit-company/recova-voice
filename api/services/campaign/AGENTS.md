# Campaign Service

Outbound campaigns are a core Recova B2B surface. Treat this package as
production call-center orchestration, not a demo dialer.

## Where to Look

| Task | Location | Notes |
| ---- | -------- | ----- |
| Scheduler process | `campaign_orchestrator.py` | Long-running loop that decides what to dial |
| Dispatch one call | `campaign_call_dispatcher.py` | Converts eligible campaign contacts into call attempts |
| Campaign run flow | `runner.py` | Campaign execution coordination |
| Failure protection | `circuit_breaker.py` | Stops waste/reputation damage when failures spike |
| Rate limits | `rate_limiter.py` | Concurrency and pacing behavior |
| Source sync | `source_sync.py`, `source_sync_factory.py`, `sources/` | Contact import/update paths |
| Events | `campaign_event_protocol.py`, `campaign_event_publisher.py` | Status/event contracts |

## Recova Rules

- Always validate campaign, workflow, telephony configuration, and contact rows
  through `organization_id`. Campaigns cross several tenant-scoped resources.
- Respect configured call windows and pacing. Korean B2B outbound changes should
  avoid assumptions about US time zones, number formats, or retry norms.
- Keep circuit-breaker behavior conservative. A bad campaign can burn cost,
  damage caller reputation, and create customer-impacting call storms.
- Do not add provider-specific telephony logic here. Resolve providers through
  `api/services/telephony/` and keep provider behavior in provider packages.
- Prefer idempotent transitions and explicit status writes. The orchestrator and
  workers may observe the same campaign/contact state at different times.

## Verification

For backend-only campaign changes, run targeted campaign tests when available
and include adjacent route/service tests for touched behavior:

```bash
source venv/bin/activate && set -a && source api/.env.test && set +a && python -m pytest api/tests/ -k campaign
```
