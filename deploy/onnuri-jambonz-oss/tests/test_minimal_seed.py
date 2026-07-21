"""Static safety contracts for the G009 private Jambonz seed."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).parents[1]
BASE = ROOT / "10-g009-minimal-seed.sql"
REGISTRATION = ROOT / "20-g009-registration-template.sql"
UPSTREAM_SCHEMA = Path(
    "/Users/slit/.local/share/recova-candidates/g009-src/"
    "jambonz-api-server/db/jambones-sql.sql"
)


class MinimalSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = BASE.read_text(encoding="utf-8")
        self.registration = REGISTRATION.read_text(encoding="utf-8")

    def test_base_has_exact_private_default_deny_invariants(self) -> None:
        self.assertIn("INSERT INTO schema_version (version) VALUES ('0.9.7')", self.base)
        self.assertEqual(self.base.count("INSERT INTO service_providers"), 1)
        self.assertEqual(self.base.count("INSERT INTO accounts ("), 1)
        self.assertEqual(self.base.count("INSERT INTO api_keys"), 1)
        self.assertEqual(self.base.count("INSERT INTO applications ("), 1)
        self.assertIn("1, 'free', 1, 0, 0", self.base)
        self.assertIn("'onnuri-jambonz-api.internal'", self.base)
        self.assertIn("'info'", self.base)
        self.assertIn("@g009_webhook_secret", self.base)
        self.assertIn("@g009_account_api_token", self.base)
        self.assertIn(
            "'http://facade:8080/v1/jambonz-contract/hooks/inbound/"
            "commit-inbound-answer-intent-and-mint-media'",
            self.base,
        )
        self.assertIn(
            "'http://facade:8080/v1/jambonz-contract/hooks/status'",
            self.base,
        )

    def test_base_contains_no_fixed_credentials_or_public_provider_material(self) -> None:
        forbidden = (
            "jambonz.cloud",
            "public-apps",
            "https://",
            "INSERT INTO users",
            "INSERT INTO user_permissions",
            "INSERT INTO voip_carriers",
            "INSERT INTO sip_gateways",
            "INSERT INTO predefined_carriers",
            "INSERT INTO predefined_sip_gateways",
            "INSERT INTO predefined_smpp_gateways",
            "INSERT INTO smpp_gateways",
            "INSERT INTO speech_credentials",
            "INSERT INTO account_offers",
            "INSERT INTO account_products",
            "INSERT INTO account_subscriptions",
            "bucket_credential",
            "recording",
            "backup",
            "export",
            "log_level, 'debug'",
        )
        for value in forbidden:
            self.assertNotIn(value.lower(), self.base.lower(), value)
        self.assertNotRegex(
            self.base,
            r"VALUES\s*\(\s*'70090000-0000-4000-8000-000000000003'\s*,\s*'",
        )
        self.assertNotRegex(self.base, r"webhook_secret[^\n]*'wh_")

    def test_base_uses_only_standard_permissions_and_no_global_key(self) -> None:
        permissions = re.findall(
            r"'([A-Z_]+)'\s*,\s*'Can [^']+'", self.base
        )
        self.assertEqual(
            permissions,
            ["VIEW_ONLY", "PROVISION_SERVICES", "PROVISION_USERS"],
        )
        key_values = re.search(
            r"INSERT INTO api_keys.*?VALUES\s*\((.*?)\);",
            self.base,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(key_values)
        self.assertIn("@g009_account_api_token", key_values.group(1))
        self.assertIn("'70090000-0000-4000-8000-000000000002'", key_values.group(1))
        self.assertIn("NULL", key_values.group(1))

    def test_registration_isolated_and_requires_runtime_values(self) -> None:
        self.assertNotIn("g009_registration", self.base)
        self.assertIn("SIGNAL SQLSTATE '45000'", self.registration)
        for variable in (
            "@g009_registration_carrier_sid",
            "@g009_registration_gateway_sid",
            "@g009_registration_account_sid",
            "@g009_registration_application_sid",
            "@g009_registration_username",
            "@g009_registration_sip_realm",
            "@g009_registration_password",
            "@g009_registration_gateway_ipv4",
        ):
            self.assertIn(variable, self.registration)
        self.assertIn("requires_register,", self.registration)
        self.assertIn("1, NULL, 'reg'", self.registration)
        self.assertIn("0, 1, @g009_registration_carrier_sid, 1", self.registration)
        self.assertNotIn("predefined_", self.registration)
        self.assertNotIn("smpp", self.registration.lower())
        self.assertNotIn("UUID()", self.registration)

    def test_seed_columns_exist_in_the_pinned_schema(self) -> None:
        if not UPSTREAM_SCHEMA.is_file():
            self.skipTest("pinned upstream schema is unavailable")
        schema = UPSTREAM_SCHEMA.read_text(encoding="utf-8")
        expected = {
            "schema_version": {"version"},
            "permissions": {"permission_sid", "name", "description"},
            "service_providers": {"service_provider_sid", "name", "description", "root_domain"},
            "accounts": {
                "account_sid", "service_provider_sid", "name", "sip_realm",
                "webhook_secret", "is_active", "plan_type", "disable_cdrs",
                "record_all_calls", "enable_debug_log",
            },
            "api_keys": {"api_key_sid", "token", "account_sid", "service_provider_sid"},
            "webhooks": {"webhook_sid", "url", "method"},
            "applications": {
                "application_sid", "account_sid", "name", "call_hook_sid",
                "call_status_hook_sid", "record_all_calls",
            },
            "system_information": {
                "domain_name", "sip_domain_name", "monitoring_domain_name",
                "private_network_cidr", "log_level",
            },
        }
        for table, columns in expected.items():
            block = re.search(
                rf"CREATE TABLE {table}\s*\((.*?)\n\)\s*(?:COMMENT=.*)?;",
                schema,
                re.DOTALL,
            )
            self.assertIsNotNone(block, table)
            actual = set(re.findall(r"^\s*([a-z_]+)\s", block.group(1), re.MULTILINE))
            self.assertTrue(columns <= actual, f"{table}: {columns - actual}")


if __name__ == "__main__":
    unittest.main()
