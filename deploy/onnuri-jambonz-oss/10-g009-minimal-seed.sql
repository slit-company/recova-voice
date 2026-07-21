-- G009 base seed for the pinned jambonz-api-server schema (0.9.7).
-- Load jambones-sql.sql first. This seed intentionally creates no users or routes.
-- The loader must set nonempty @g009_webhook_secret and
-- @g009_account_api_token session variables from runtime secret files.
-- The NOT NULL inserts below fail closed when either value is absent.

INSERT INTO schema_version (version) VALUES ('0.9.7');

INSERT INTO permissions (permission_sid, name, description) VALUES
  ('ffbc342a-546a-11ed-bdc3-0242ac120002', 'VIEW_ONLY', 'Can view data but not make changes'),
  ('ffbc3a10-546a-11ed-bdc3-0242ac120002', 'PROVISION_SERVICES', 'Can provision services'),
  ('ffbc3c5e-546a-11ed-bdc3-0242ac120002', 'PROVISION_USERS', 'Can provision users');

INSERT INTO service_providers (service_provider_sid, name, description, root_domain) VALUES
  ('70090000-0000-4000-8000-000000000001', 'onnuri-private',
   'Private default-deny G009 service provider', 'onnuri-jambonz.internal');

INSERT INTO accounts (
  account_sid, service_provider_sid, name, sip_realm, webhook_secret,
  is_active, plan_type, disable_cdrs, record_all_calls, enable_debug_log
) VALUES (
  '70090000-0000-4000-8000-000000000002',
  '70090000-0000-4000-8000-000000000001',
  'onnuri-private-default', 'onnuri-jambonz.internal', @g009_webhook_secret,
  1, 'free', 1, 0, 0
);

INSERT INTO api_keys (api_key_sid, token, account_sid, service_provider_sid) VALUES (
  '70090000-0000-4000-8000-000000000003', @g009_account_api_token,
  '70090000-0000-4000-8000-000000000002', NULL
);

INSERT INTO webhooks (webhook_sid, url, method) VALUES
  ('70090000-0000-4000-8000-000000000004',
   'http://facade:8080/v1/jambonz-contract/hooks/inbound/commit-inbound-answer-intent-and-mint-media', 'POST'),
  ('70090000-0000-4000-8000-000000000005',
   'http://facade:8080/v1/jambonz-contract/hooks/status', 'POST');

INSERT INTO applications (
  application_sid, account_sid, name, call_hook_sid, call_status_hook_sid,
  record_all_calls
) VALUES (
  '70090000-0000-4000-8000-000000000006',
  '70090000-0000-4000-8000-000000000002',
  'onnuri-private-default',
  '70090000-0000-4000-8000-000000000004',
  '70090000-0000-4000-8000-000000000005', 0
);

INSERT INTO system_information (
  domain_name, sip_domain_name, monitoring_domain_name, private_network_cidr,
  log_level
) VALUES (
  'onnuri-jambonz-api.internal', 'onnuri-jambonz.internal',
  'onnuri-jambonz-monitoring.internal', '10.0.0.0/8', 'info'
);
