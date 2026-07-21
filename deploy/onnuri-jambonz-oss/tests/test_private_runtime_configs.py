"""Static contracts for private drachtio and FreeSWITCH runtime configurations."""
from __future__ import annotations

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).parents[1]
FEATURE_CONFIG = ROOT / "drachtio-feature.xml"
SIP_CONFIG = ROOT / "drachtio-sip.xml"
CONFIGS = (FEATURE_CONFIG, SIP_CONFIG)
FREESWITCH_CONFIG = ROOT / "freeswitch-conf" / "freeswitch.xml"
FREESWITCH_AUTOLOAD = ROOT / "freeswitch-conf" / "autoload_configs"
FREESWITCH_MODULES = ROOT / "freeswitch-modules.conf.xml"
FREESWITCH_DOCKERFILE = ROOT / "Dockerfile.freeswitch"
DRACHTIO_DOCKERFILE = ROOT / "Dockerfile.drachtio"
RTPENGINE_DOCKERFILE = ROOT / "Dockerfile.rtpengine"
COMPOSE = ROOT / "compose.yaml"
FREESWITCH_CONFIGS = (
    FREESWITCH_CONFIG,
    FREESWITCH_AUTOLOAD / "console.conf.xml",
    FREESWITCH_AUTOLOAD / "event_socket.conf.xml",
    FREESWITCH_AUTOLOAD / "sofia.conf.xml",
)
FORBIDDEN_TAGS = {
    "blacklist",
    "capture-server",
    "file",
    "monitoring",
    "outbound-proxy",
    "syslog",
    "tls",
}
FORBIDDEN_VALUES = ("0.0.0.0", "::", "homer")


class PrivateRuntimeConfigTests(unittest.TestCase):
    def parse(self, path: Path) -> ET.Element:
        self.assertTrue(path.is_file(), path)
        return ET.parse(path).getroot()

    def test_configs_are_minimal_private_drachtio_documents(self) -> None:
        for path in CONFIGS:
            root = self.parse(path)
            self.assertEqual(root.tag, "drachtio")

            admin = root.find("admin")
            self.assertIsNotNone(admin)
            assert admin is not None
            self.assertEqual(admin.text, "127.0.0.1")
            self.assertEqual(admin.attrib, {"port": "9022", "secret": ""})

            self.assertEqual(root.findtext("cdrs"), "false")
            self.assertEqual(root.findtext("logging/sofia-loglevel"), "0")
            self.assertEqual(root.findtext("logging/loglevel"), "error")
            self.assertIsNone(root.find("logging/console"))
            self.assertIsNone(root.find("logging/file"))

            for element in root.iter():
                self.assertNotIn(element.tag, FORBIDDEN_TAGS, path)
                for value in element.attrib.values():
                    self.assertNotIn("external-ip", value, path)
                if element.text:
                    normalized = element.text.strip().lower()
                    self.assertFalse(
                        any(value in normalized for value in FORBIDDEN_VALUES),
                        f"{path}: forbidden public or telemetry endpoint {normalized!r}",
                    )

    def test_feature_config_has_only_a_local_sip_contact_for_feature_server_and_mrf(self) -> None:
        root = self.parse(FEATURE_CONFIG)
        contacts = root.findall("sip/contacts/contact")
        self.assertEqual(
            [contact.text for contact in contacts],
            ["sip:172.30.0.10:5060;transport=udp,tcp"],
        )
        self.assertIsNone(root.find("request-handlers"))

    def test_sip_config_routes_only_to_the_local_call_router(self) -> None:
        root = self.parse(SIP_CONFIG)
        handler = root.find("request-handlers/request-handler")
        self.assertIsNotNone(handler)
        assert handler is not None
        self.assertEqual(handler.attrib, {"sip-method": "INVITE", "http-method": "POST"})
        self.assertEqual(handler.text, "http://call-router:3000")
        self.assertEqual(
            [contact.text for contact in root.findall("sip/contacts/contact")],
            ["sip:172.30.0.20:5060;transport=udp,tcp"],
        )
    def test_freeswitch_config_tree_contains_only_the_dedicated_mrf_documents(self) -> None:
        self.assertEqual(
            {path.relative_to(ROOT / "freeswitch-conf") for path in FREESWITCH_CONFIGS},
            {
                Path("freeswitch.xml"),
                Path("autoload_configs/console.conf.xml"),
                Path("autoload_configs/event_socket.conf.xml"),
                Path("autoload_configs/sofia.conf.xml"),
            },
        )
        self.assertEqual(
            {path.relative_to(ROOT / "freeswitch-conf") for path in (ROOT / "freeswitch-conf").rglob("*.xml")},
            {
                Path("freeswitch.xml"),
                Path("autoload_configs/console.conf.xml"),
                Path("autoload_configs/event_socket.conf.xml"),
                Path("autoload_configs/sofia.conf.xml"),
            },
        )
        for path in FREESWITCH_CONFIGS:
            self.parse(path)
            content = path.read_text(encoding="utf-8").lower()
            self.assertFalse(
                any(
                    re.search(rf"\b{re.escape(value)}\b", content)
                    for value in (
                        "cluecon",
                        "default",
                        "external",
                        "public",
                        "nat",
                        "record",
                        "cdr",
                        "storage",
                        "syslog",
                        "voicemail",
                        "conference",
                        "xml_rpc",
                    )
                ),
                path,
            )

    def test_freeswitch_loads_only_required_dynamic_modules(self) -> None:
        root = self.parse(FREESWITCH_MODULES)
        self.assertEqual(
            [module.attrib for module in root.findall("modules/load")],
            [
                {"module": "mod_event_socket"},
                {"module": "mod_sofia"},
                {"module": "mod_dialplan_xml"},
                {"module": "mod_commands"},
                {"module": "mod_dptools"},
                {"module": "mod_expr"},
                {"module": "mod_hash"},
                {"module": "mod_console"},
                {"module": "mod_audio_fork"},
            ],
        )

    def test_freeswitch_event_socket_is_loopback_and_uses_an_injected_secret(self) -> None:
        root = self.parse(FREESWITCH_AUTOLOAD / "event_socket.conf.xml")
        self.assertEqual(
            {
                param.attrib["name"]: param.attrib["value"]
                for param in root.findall("settings/param")
            },
            {
                "listen-ip": "127.0.0.1",
                "listen-port": "8021",
                "password": "$${FREESWITCH_EVENT_SOCKET_PASSWORD}",
            },
        )

        document = self.parse(FREESWITCH_CONFIG)
        directive = document.find("section[@name='configuration']/X-PRE-PROCESS")
        self.assertIsNotNone(directive)
        assert directive is not None
        self.assertEqual(
            directive.attrib,
            {
                "cmd": "env-set",
                "data": (
                    "FREESWITCH_EVENT_SOCKET_PASSWORD="
                    "$FREESWITCH_EVENT_SOCKET_PASSWORD"
                ),
            },
        )
    def test_freeswitch_console_logs_only_errors(self) -> None:
        root = self.parse(FREESWITCH_AUTOLOAD / "console.conf.xml")
        self.assertEqual(
            {
                param.attrib["name"]: param.attrib["value"]
                for param in root.findall("settings/param")
            },
            {"loglevel": "error", "colorize": "false"},
        )

    def test_freeswitch_sofia_has_one_loopback_profile_and_bounded_rtp(self) -> None:
        root = self.parse(FREESWITCH_AUTOLOAD / "sofia.conf.xml")
        profiles = root.findall("profiles/profile")
        self.assertEqual(
            [profile.attrib for profile in profiles],
            [{"name": "drachtio_mrf"}],
        )
        self.assertEqual(
            {
                param.attrib["name"]: param.attrib["value"]
                for param in profiles[0].findall("settings/param")
            },
            {
                "sip-ip": "127.0.0.1",
                "rtp-ip": "127.0.0.1",
                "sip-port": "5080",
                "rtp-start-port": "40000",
                "rtp-end-port": "40099",
                "dbname": "/run/freeswitch/sofia-drachtio-mrf.db",
                "context": "jambonz",
                "dialplan": "XML",
                "disable-register": "true",
                "auth-calls": "false",
            },
        )

    def test_freeswitch_dialplan_hands_only_fsmrf_calls_to_advertised_esl(self) -> None:
        root = self.parse(FREESWITCH_CONFIG)
        condition = root.find("section[@name='dialplan']/context/extension/condition")
        self.assertIsNotNone(condition)
        assert condition is not None
        self.assertEqual(
            condition.attrib,
            {
                "field": "${sip_user_agent}",
                "expression": "^drachtio-fsmrf:(.*)$",
            },
        )
        actions = condition.findall("action")
        self.assertEqual(actions[0].attrib, {"application": "answer"})
        self.assertEqual(
            actions[-1].attrib,
            {
                "application": "socket",
                "data": "${sip_h_X-esl-outbound} async full",
            },
        )

    def test_drachtio_scratch_runtime_keeps_protocol_databases(self) -> None:
        content = DRACHTIO_DOCKERFILE.read_text(encoding="utf-8")
        for runtime_file in ("/etc/protocols", "/etc/services", "/etc/nsswitch.conf"):
            self.assertIn(runtime_file, content)
        self.assertIn("USER 65532:65532", content)
        self.assertIn("debian:12-slim@sha256:", content)
        self.assertNotIn("FROM scratch", content)
        self.assertIn("libtool-bin", content)

    def test_rtpengine_build_and_runtime_enable_sidecar_dtmf_events(self) -> None:
        dockerfile = RTPENGINE_DOCKERFILE.read_text(encoding="utf-8")
        compose = COMPOSE.read_text(encoding="utf-8")
        self.assertIn("with_transcoding=yes", dockerfile)
        self.assertNotIn("with_transcoding=no", dockerfile)
        self.assertIn("--dtmf-log-dest=127.0.0.1:22223", compose)
        self.assertIn("RTPENGINE_DTMF_LOG_PORT: '22223'", compose)

    def test_freeswitch_image_replaces_vanilla_configuration_and_runs_unprivileged(self) -> None:
        content = FREESWITCH_DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("rm -rf /usr/local/freeswitch/conf", content)
        self.assertIn("COPY freeswitch-conf/ /usr/local/freeswitch/conf/", content)
        self.assertIn("COPY freeswitch-modules.conf.xml", content)
        self.assertIn("applications/mod_audio_fork", content)
        self.assertIn("USER freeswitch", content)
        self.assertIn("TMPDIR=/run/freeswitch", content)
        self.assertIn("test -w /tmp", content)
        self.assertIn("mkdir -p /run/freeswitch", content)
        self.assertIn('"-run", "/run/freeswitch"', content)


if __name__ == "__main__":
    unittest.main()
