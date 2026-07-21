-- G009 opt-in registration template. Load 10-g009-minimal-seed.sql first.
-- Before sourcing, set every @g009_registration_* session variable below.
-- This template neither generates nor selects credentials.

DELIMITER //
CREATE PROCEDURE g009_require_registration_values()
BEGIN
  IF @g009_registration_carrier_sid IS NULL
    OR @g009_registration_gateway_sid IS NULL
    OR @g009_registration_account_sid IS NULL
    OR @g009_registration_application_sid IS NULL
    OR @g009_registration_username IS NULL
    OR @g009_registration_sip_realm IS NULL
    OR @g009_registration_password IS NULL
    OR @g009_registration_gateway_ipv4 IS NULL THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'G009 registration template requires all runtime session values';
  END IF;

  IF @g009_registration_carrier_sid NOT REGEXP '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    OR @g009_registration_gateway_sid NOT REGEXP '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    OR @g009_registration_account_sid <> '70090000-0000-4000-8000-000000000002'
    OR @g009_registration_application_sid <> '70090000-0000-4000-8000-000000000006'
    OR @g009_registration_username = ''
    OR @g009_registration_sip_realm = ''
    OR @g009_registration_password = ''
    OR @g009_registration_gateway_ipv4 NOT REGEXP '^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])[.]){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$' THEN
    SIGNAL SQLSTATE '45000'
      SET MESSAGE_TEXT = 'G009 registration template received invalid runtime values';
  END IF;
END//
CALL g009_require_registration_values()//
DROP PROCEDURE g009_require_registration_values//
DELIMITER ;

INSERT INTO voip_carriers (
  voip_carrier_sid, name, account_sid, application_sid, requires_register,
  register_username, register_sip_realm, register_password, is_active,
  outbound_sip_proxy, trunk_type
) VALUES (
  @g009_registration_carrier_sid, 'g009-opt-in-registration',
  @g009_registration_account_sid, @g009_registration_application_sid, 1,
  @g009_registration_username, @g009_registration_sip_realm,
  @g009_registration_password, 1, NULL, 'reg'
);

INSERT INTO sip_gateways (
  sip_gateway_sid, ipv4, netmask, port, inbound, outbound, voip_carrier_sid,
  is_active
) VALUES (
  @g009_registration_gateway_sid, @g009_registration_gateway_ipv4, 32, 5060,
  0, 1, @g009_registration_carrier_sid, 1
);
