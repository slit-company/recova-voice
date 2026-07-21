#!/usr/bin/env python3
"""Offline, deterministic hardening for a mounted Jambonz mini v10.2.2 rootfs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

ARCHIVE_SHA256 = "106c4544fdd0450d7f9c4383f0d8028c490ee949173bc0ce1c507c3339400c73"
SOURCE_IMAGE_ID = "8849856699999487269"
ACQUISITION_RECEIPT_SHA256 = "2efa15251a1828af0ef7798f1265044db21dedd5a092feb8fcbf1818d3fffeb2"
SEALED_PATCH_MANIFEST_SHA256 = "8d2c7deaff80817313aae5918a9f44f8272849929443160981b96caa23132e3f"
KERNEL_BACKPORT_MANIFEST_SHA256 = "2118deb529483bba68c09b2eefc8dacef1c0c2ad986b94cf0f7c35decfe1f662"
OBSERVED_SENTINELS = {
    "etc/os-release": "59a77b5f2666d9c85c489bd1911a6eebbd91ef22fe48b90a3b75f1b21f3844d4",
    "etc/rtpengine/rtpengine.conf": "d6a2efb4625740a7cb40fb5952ab28230cfac16db078ae9465b32cfc62a96dce",
    "etc/systemd/system/rtpengine.service": "086baa48fb870cb90b3aced503201e39146c3169de9021498236630a948d9df9",
    "home/jambonz/apps/ecosystem.config.js": "af76b8341f2828efab82d429078871e0cef8c2fa9cc90fc12326a52400c5e383",
    "home/jambonz/apps/sbc-sip-sidecar/package.json": "a7caa9a33e2e1ffa2fa0dce46892a9333948b07f3733cb5fcb94204666480c69",
    "home/jambonz/apps/feature-server/package.json": "e7c963635b08830b5f8f7678aafd8c015948fb7c58bfa8d9ef368f75e0c34d8d",
    "home/jambonz/apps/api-server/package.json": "e38bd6c3d42ba33adc632362d796da80c855356c6e6893508ea3419773839bf3",
}
RELEASE = "10.2.2"
RECEIPT_SCHEMA = "recova-jambonz-mini-stock-export/v3"
DERIVATIVE_SCHEMA = "recova-jambonz-mini-derivative/v1"
DERIVATIVE_RECEIPT = "usr/share/recova/derivative-receipt.json"
RTP_START, RTP_END = 40000, 40099
KERNEL_RELEASE = "6.12.95+deb12-cloud-amd64"
OLD_KERNEL_RELEASE = "6.1.0-49-cloud-amd64"
APP_ROOT = "/home/jambonz/apps"
FREESWITCH_BIN = "/usr/local/freeswitch/bin/freeswitch"
DRACHTIO_BIN = "/usr/bin/drachtio"
DRACHTIO_CONFIG = "/etc/drachtio.conf.xml"
APP_SCRIPTS = {
    "api-server": "api-server/app.js",
    "sbc-call-router": "sbc-call-router/app.js",
    "sbc-sip-sidecar": "sbc-sip-sidecar/app.js",
    "inbound": "inbound/app.js",
    "outbound": "outbound/app.js",
    "sbc-rtpengine-sidecar": "sbc-rtpengine-sidecar/app.js",
    "feature-server": "feature-server/app.js",
}
RUNTIME_UNITS = tuple(f"recova-{name}.service" for name in APP_SCRIPTS) + (
    "recova-mariadb.service", "recova-redis.service",
    "recova-freeswitch.service", "recova-drachtio.service", "recova-rtpengine.service",
)
MASKED_UNITS = (
    "apt-daily.service", "apt-daily.timer", "apt-daily-upgrade.service", "apt-daily-upgrade.timer",
    "unattended-upgrades.service", "certbot.service", "certbot.timer", "google-startup-scripts.service",
    "google-shutdown-scripts.service", "google-osconfig-agent.service", "google-guest-agent.service",
    "google-guest-agent-manager.service", "google-guest-compat-manager.service", "ssh.service",
    "sshd.service", "nginx.service", "cassandra.service", "postgresql.service", "mysql.service",
    "mariadb.service", "redis.service",
    "redis-server.service", "influxdb.service", "influxd.service", "telegraf.service",
    "grafana-server.service", "jaeger.service", "jaeger-query.service", "jaeger-collector.service",
    "homer-app.service", "heplify-server.service", "heplify-restart.service", "heplify.service",
    "pcap.service", "pcap-server.service", "upload-recordings.service", "upload_recordings.service",
    "jambonz-updater.service", "dpkg-backup.service", "drachtio.service", "drachtio-5070.service",
    "freeswitch.service", "jambonz-rtpengine.service", "rtpengine.service", "rtpengine-recording.service",
    "rtpengine.timer", "rtpengine-cleanup.timer", "rtpengine-rotate.timer", "pm2-jambonz.service",
)
DELETE_PATHS = (
    "var/lib/mysql", "var/lib/redis", "var/lib/cassandra", "var/lib/postgresql", "var/lib/influxdb",
    "var/cache/apt", "var/lib/apt/lists", "var/cache/jambonz", "var/cache/rtpengine", "var/spool/cron",
    "var/spool/recordings", "var/lib/recordings", "var/lib/pcap", "var/lib/heplify",
    "var/spool/rtpengine", "var/lib/rtpengine", "var/spool/rtpengine-recording",
    "var/lib/rtpengine-recording", "home/admin/go", "usr/local/go", "home/jambonz/.pm2",
    "home/admin/.pm2", "home/jambonz/apps/webapp", "home/jambonz/apps/portal",
    "etc/grafana", "usr/share/grafana", "var/log/grafana", "etc/cassandra", "usr/share/cassandra",
    "var/log/cassandra", "etc/influxdb", "etc/influxdb2", "usr/share/influxdb", "var/log/influxdb",
    "etc/telegraf", "usr/share/telegraf", "var/log/telegraf", "etc/jaeger", "usr/share/jaeger",
    "var/log/jaeger", "etc/heplify", "usr/share/heplify", "var/log/heplify", "etc/homer",
    "usr/share/homer", "var/log/pcap",
    "home/jambonz/apps/admin", "opt/jambonz/webapp", "opt/jambonz/portal",
    "opt/jambonz/management", "opt/jambonz/admin", "root/.cache", "opt/google-cloud-sdk",
    "usr/lib/google-cloud-sdk", "usr/share/google-cloud-sdk", "usr/local/cassandra",
    "usr/src", "usr/local/src", "home/jambonz/.npm", "home/jambonz/.cache",
    "var/log", "usr/local/freeswitch/htdocs",
    "usr/local/bin/pcap-server", "usr/local/bin/jaeger-query", "usr/local/bin/jaeger-collector",
    "usr/local/bin/heplify-server", "usr/local/bin/apiban", "usr/lib/google/guest_agent",
    "usr/bin/google_guest_agent", "usr/bin/google_osconfig_agent", "usr/bin/google_metadata_script_runner",
    "usr/bin/gce_metadata_script_runner", "usr/bin/gce_compat_metadata_script_runner",
    "usr/bin/gce_workload_cert_refresh", "usr/bin/ggactl_plugin",
    "usr/bin/google_guest_agent_manager", "usr/bin/google_guest_compat_manager",
)
SENSITIVE_FILE_PATHS = (
    "var/lib/dkms/mok.key", "var/lib/shim-signed/mok/MOK.priv",
    "etc/ssl/private/ssl-cert-snakeoil.key", "etc/ssh/ssh_host_rsa_key",
    "etc/ssh/ssh_host_ecdsa_key", "etc/ssh/ssh_host_ed25519_key",
    "etc/recova/runtime.env", "usr/bin/gcloud", "usr/bin/gsutil", "usr/bin/bq",
    "heplify-server-key.pem", "usr/local/share/libwebsockets-test-server",
    "usr/share/cmake-3.25/Templates/Windows/Windows_TemporaryKey.pfx",
    "etc/modules-load.d/rtpengine.conf",
)
FORBIDDEN_INSTALLED_PACKAGES = frozenset({
    "google-cloud-cli",
    "grafana",
    "influxdb",
    "jambonz-monitoring-agent",
    "nginx",
    "nginx-common",
    "python3-certbot-nginx",
    "telegraf",
    "linux-compiler-gcc-12-x86",
    "apache2-utils",
})


SHA256_HEX = set("0123456789abcdef")
MUTATED_STOCK_PATHS = {"etc/rtpengine/rtpengine.conf", "etc/systemd/system/rtpengine.service"}


class HardeningError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HardeningError(f"unsafe path: {value!r}")
    return path
ALLOWED_READ_SYMLINKS = {
    "etc/os-release": (
        "usr/lib/os-release",
        frozenset({"/usr/lib/os-release", "../usr/lib/os-release"}),
    ),
}
ALLOWED_EXECUTABLE_SYMLINKS = {
    "usr/bin/redis-server": ("redis-check-rdb", "usr/bin/redis-check-rdb"),
}






def root_path(root: Path, relative: str, required: bool = False) -> Path:
    current = root
    for part in safe_relative(relative).parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            if required:
                raise HardeningError(f"missing required path: {relative}")
            return root / safe_relative(relative)
        if stat.S_ISLNK(mode):
            raise HardeningError(f"symlink refused: {relative}")
    return current


def read_regular(root: Path, relative: str) -> bytes:
    allowed = ALLOWED_READ_SYMLINKS.get(relative)
    candidate = root / safe_relative(relative)
    if allowed and candidate.is_symlink():
        target = os.readlink(candidate)
        canonical_target, accepted_targets = allowed
        if target not in accepted_targets:
            raise HardeningError(f"symlink refused: {relative}")
        path = root_path(root, canonical_target, required=True)
    else:
        path = root_path(root, relative, required=True)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise HardeningError(f"not a regular file: {relative}")
    return path.read_bytes()


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_stock_receipt(filename: str) -> dict[str, Any]:
    path = Path(filename)
    if path.is_symlink():
        raise HardeningError("stock receipt symlink refused")
    try:
        value = json.loads(path.read_bytes(), object_pairs_hook=no_duplicates)
    except (OSError, ValueError) as error:
        raise HardeningError("invalid stock receipt") from error
    required = {
        "schema_version", "stock_identity", "release", "export_digest",
        "acquisition_receipt_digest", "source_image_id", "sealed_patch_manifest_digest",
        "kernel_backport_manifest_digest", "post_patch_package_versions", "sentinels",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise HardeningError("stock receipt has an invalid shape")
    if (value["schema_version"], value["stock_identity"], value["release"]) != (RECEIPT_SCHEMA, "jambonz-mini", RELEASE):
        raise HardeningError("stock receipt does not identify jambonz mini v10.2.2")
    if value["export_digest"] != ARCHIVE_SHA256:
        raise HardeningError("stock receipt does not bind the observed archive")
    if value["acquisition_receipt_digest"] != ACQUISITION_RECEIPT_SHA256:
        raise HardeningError("stock receipt does not bind the acquisition receipt")
    if value["sealed_patch_manifest_digest"] != SEALED_PATCH_MANIFEST_SHA256:
        raise HardeningError("stock receipt does not bind the sealed patch manifest")
    if value["kernel_backport_manifest_digest"] != KERNEL_BACKPORT_MANIFEST_SHA256:
        raise HardeningError("stock receipt does not bind the sealed kernel backport manifest")
    if value["source_image_id"] != SOURCE_IMAGE_ID:
        raise HardeningError("stock receipt does not bind the observed source image ID")
    versions = value["post_patch_package_versions"]
    if not isinstance(versions, dict) or not versions or any(not isinstance(name, str) or not isinstance(version, str) or not version for name, version in versions.items()):
        raise HardeningError("stock receipt has invalid post-patch package versions")
    sentinels = value["sentinels"]
    if not isinstance(sentinels, dict) or sentinels != OBSERVED_SENTINELS:
        raise HardeningError("stock receipt does not bind the observed sentinels")
    return value


def verify_stock(root: Path, stock: dict[str, Any]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for name, expected in sorted(stock["sentinels"].items()):
        actual = digest(read_regular(root, name))
        if actual != expected:
            raise HardeningError(f"stock sentinel mismatch: {name}")
        hashes[name] = actual
    return hashes
def verify_package_versions(root: Path, expected: dict[str, str]) -> None:
    installed: dict[str, str] = {}
    status = read_regular(root, "var/lib/dpkg/status").decode("utf-8", "strict")
    for stanza in status.split("\n\n"):
        fields: dict[str, str] = {}
        for line in stanza.splitlines():
            if ": " in line and not line.startswith((" ", "\t")):
                key, value = line.split(": ", 1)
                fields[key] = value
        if fields.get("Status") == "install ok installed" and "Package" in fields and "Version" in fields:
            installed[fields["Package"]] = fields["Version"]
    mismatches = sorted(
        name for name, version in expected.items()
        if installed.get(name) != version
    )
    if mismatches:
        raise HardeningError(
            "post-patch package version mismatch: " + ",".join(mismatches)
        )
    forbidden = sorted(FORBIDDEN_INSTALLED_PACKAGES & installed.keys())
    if forbidden:
        raise HardeningError("disabled packages must be purged before hardening: " + ",".join(forbidden))




def require_regular(root: Path, absolute_path: str) -> None:
    relative = absolute_path.removeprefix("/")
    path = root_path(root, relative, required=True)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise HardeningError(f"required regular file is absent: {absolute_path}")


def require_executable(root: Path, absolute_path: str) -> None:
    relative = absolute_path.removeprefix("/")
    candidate = root / safe_relative(relative)
    allowed = ALLOWED_EXECUTABLE_SYMLINKS.get(relative)
    if allowed and candidate.is_symlink():
        expected_target, canonical_target = allowed
        if os.readlink(candidate) != expected_target:
            raise HardeningError(f"symlink refused: {relative}")
        path = root_path(root, canonical_target, required=True)
    else:
        path = root_path(root, relative, required=True)
    if not stat.S_ISREG(path.lstat().st_mode) or not path.stat().st_mode & 0o111:
        raise HardeningError(f"required executable is absent or non-executable: {absolute_path}")


def post_mutation_digest(root: Path, relative: str) -> str:
    path = root / safe_relative(relative)
    if path.is_symlink():
        return digest(f"symlink:{os.readlink(path)}".encode("utf-8"))
    return digest(read_regular(root, relative))


def remove_tree(root: Path, relative: str) -> bool:
    path = root_path(root, relative)
    if not path.exists():
        return False
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()
    return True
def remove_exact(root: Path, relative: str) -> bool:
    path = root / safe_relative(relative)
    parent = root_path(root, path.parent.relative_to(root).as_posix())
    if not parent.exists():
        return False
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return False
    if stat.S_ISDIR(mode):
        shutil.rmtree(path)
    else:
        path.unlink()
    return True


def kernel_sort_key(release: str) -> tuple[tuple[tuple[int, int | str], ...], str]:
    parts = tuple(
        (0, int(part)) if part.isdigit() else (1, part)
        for part in re.findall(r"\d+|[^\d]+", release)
    )
    return parts, release


def remove_stale_kernels(root: Path) -> list[str]:
    modules_relative = None
    for candidate in ("lib/modules", "usr/lib/modules"):
        try:
            path = root_path(root, candidate)
        except HardeningError:
            continue
        if path.is_dir():
            modules_relative = candidate
            break
    if modules_relative is None:
        return []
    modules = root_path(root, modules_relative)
    releases = sorted(
        entry.name for entry in modules.iterdir()
        if entry.is_dir() and re.fullmatch(r"[0-9][0-9A-Za-z.+~-]*", entry.name)
    )
    if len(releases) < 2:
        return []
    retained = max(releases, key=kernel_sort_key)
    deleted: list[str] = []
    for release in releases:
        if release == retained:
            continue
        candidates = (
            f"{modules_relative}/{release}", f"usr/src/linux-headers-{release}",
            f"usr/src/linux-headers-{release}-common", f"boot/vmlinuz-{release}",
            f"boot/initrd.img-{release}", f"boot/config-{release}", f"boot/System.map-{release}",
        )
        for candidate in candidates:
            if remove_exact(root, candidate):
                deleted.append(candidate)
    return deleted




def remove_forbidden_descendants(root: Path) -> list[str]:
    deleted: list[str] = []
    for relative in DELETE_PATHS + SENSITIVE_FILE_PATHS:
        if remove_exact(root, relative):
            deleted.append(relative)
    deleted.extend(remove_stale_kernels(root))
    return sorted(set(deleted))


def remove_stale_wants(root: Path) -> list[str]:
    system = root_path(root, "etc/systemd/system")
    if not system.exists():
        return []
    deleted: list[str] = []
    for base, _, files in os.walk(system, topdown=True, followlinks=False):
        for name in files:
            path = Path(base) / name
            if path.is_symlink() and path.parent.name.endswith(".wants") and name in MASKED_UNITS:
                deleted.append(path.relative_to(root).as_posix())
                path.unlink()
    return sorted(deleted)


def write_file(root: Path, relative: str, content: bytes, mode: int = 0o644) -> None:
    path = root_path(root, relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    root_path(root, path.parent.relative_to(root).as_posix())
    if path.exists() and path.is_symlink():
        raise HardeningError(f"symlink refused: {relative}")
    path.write_bytes(content)
    os.chmod(path, mode)


def mask_unit(root: Path, name: str) -> None:
    parent = root_path(root, "etc/systemd/system")
    parent.mkdir(parents=True, exist_ok=True)
    root_path(root, "etc/systemd/system", required=True)
    path = parent / name
    if path.is_symlink():
        if os.readlink(path) == "/dev/null":
            return
        path.unlink()
    if path.exists():
        path.unlink()
    os.symlink("/dev/null", path)


def sandbox(runtime_name: str, user: str = "jambonz", group: str = "jambonz") -> str:
    return (f"User={user}\nGroup={group}\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
            "ProtectHome=read-only\nProtectKernelTunables=yes\nProtectKernelModules=yes\n"
            "ProtectControlGroups=yes\nProtectProc=invisible\nProcSubset=pid\nRestrictSUIDSGID=yes\n"
            "RestrictNamespaces=yes\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nLimitCORE=0\nUMask=0077\n"
            f"RuntimeDirectory=recova-{runtime_name}\nRuntimeDirectoryMode=0700\n"
            "RuntimeDirectoryPreserve=no\nStandardOutput=null\nStandardError=null\n")


def runtime_environment(name: str) -> str:
    return f"EnvironmentFile=/run/recova-credentials/{name}.env\n"


def app_unit(name: str, script: str) -> bytes:
    restart = "no" if name == "sbc-sip-sidecar" else "on-failure"
    api_bind = "Environment=RECOVA_API_BIND=127.0.0.1\n" if name == "api-server" else ""
    one_shot = "Environment=RECOVA_ONE_SHOT_REGISTER=1\n" if name == "sbc-sip-sidecar" else ""
    executable = "/usr/bin/node"
    if name == "sbc-sip-sidecar":
        executable = "/usr/bin/env RECOVA_ONE_SHOT_REGISTER=1 /usr/bin/node"
    return ("[Unit]\nRequires=nftables.service\nAfter=nftables.service network.target recova-mariadb.service recova-redis.service\n"
            f"[Service]\n{runtime_environment(name)}{one_shot}{api_bind}WorkingDirectory={APP_ROOT}/{name}\n"
            f"ExecStart={executable} --jitless {APP_ROOT}/{script}\nRestart={restart}\nRestartSec=2\n" +
            sandbox(name) + "[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def pm2_ecosystem() -> bytes:
    apps = []
    for name, script in APP_SCRIPTS.items():
        apps.append({"name": name, "script": f"{APP_ROOT}/{script}", "cwd": f"{APP_ROOT}/{name}",
                     "interpreter": "/usr/bin/node", "autorestart": name != "sbc-sip-sidecar",
                     "out_file": "/dev/null", "error_file": "/dev/null", "merge_logs": False})
    return canonical({"apps": apps}) + b"\n"


def base_unit(
    description: str,
    command: str,
    runtime_name: str,
    extra: str = "",
    *,
    user: str = "jambonz",
    group: str = "jambonz",
) -> bytes:
    return (f"[Unit]\nDescription={description}\nRequires=nftables.service\nAfter=nftables.service network.target\n"
            f"[Service]\n{runtime_environment(runtime_name)}ExecStart={command}\nRestart=on-failure\n"
            f"RestartSec=2\n{extra}{sandbox(runtime_name, user, group)}[Install]\nWantedBy=multi-user.target\n").encode("ascii")


def rtp_config() -> bytes:
    return ("[rtpengine]\ntable = -1\n"
            "listen-ng = 127.0.0.1:2223\nlisten-cli = 127.0.0.1:9900\n"
            "port-min = 40000\nport-max = 40099\nlog-level = 3\n").encode("ascii")


def nftables() -> bytes:
    return ("flush ruleset\n"
            "table inet recova {\n"
            " chain input { type filter hook input priority 0; policy drop; iif lo accept; }\n"
            " chain forward { type filter hook forward priority 0; policy drop; }\n"
            " chain output { type filter hook output priority 0; policy drop; oif lo accept; }\n"
            "}\n").encode("ascii")


def nftables_entrypoint() -> bytes:
    return b'include "/etc/nftables.d/*.nft"\n'


def enable_nftables(root: Path) -> None:
    wants = root_path(root, "etc/systemd/system/multi-user.target.wants")
    wants.mkdir(parents=True, exist_ok=True)
    root_path(root, "etc/systemd/system/multi-user.target.wants", required=True)
    link = wants / "nftables.service"
    if link.is_symlink():
        if os.readlink(link) == "/lib/systemd/system/nftables.service":
            return
        link.unlink()
    elif link.exists():
        raise HardeningError("nftables enablement path is not a symlink")
    os.symlink("/lib/systemd/system/nftables.service", link)


def runtime_contract() -> bytes:
    return ("schema_version=recova-runtime-contract/v2\ncredentials_dir=/run/recova-credentials\n"
            "service_runtime_dirs=/run/recova-<service>\nmysql_dir=/run/recova-mariadb/mysql\n"
            "redis_dir=/run/recova-redis/redis\nlog_output=/dev/null\napi_bind=127.0.0.1\n"
            "listen.wsAuth=Basic\naudio=L16,8000,mono,bidirectional\nrtp=udp:40000-40099\n"
            "firewall=default-deny-loopback-only\n").encode("ascii")


def patch_grub_config(root: Path) -> None:
    relative = "boot/grub/grub.cfg"
    raw = read_regular(root, relative)
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise HardeningError("GRUB configuration is not UTF-8") from error
    if OLD_KERNEL_RELEASE in text:
        if text.count(OLD_KERNEL_RELEASE) < 6:
            raise HardeningError("unrecognized GRUB kernel entry shape")
        write_file(root, relative, text.replace(OLD_KERNEL_RELEASE, KERNEL_RELEASE).encode("utf-8"))
    elif KERNEL_RELEASE not in text:
        raise HardeningError("GRUB does not reference the retained kernel")


def disable_kernel_rtpengine_module(root: Path) -> None:
    relative = "etc/modules"
    path = root_path(root, relative)
    if not path.exists():
        return
    lines = read_regular(root, relative).decode("utf-8", "strict").splitlines()
    filtered = [line for line in lines if line.strip() not in {"nft_rtpengine", "xt_RTPENGINE"}]
    write_file(root, relative, ("\n".join(filtered) + "\n").encode("utf-8"))


def existing_receipt(root: Path) -> dict[str, Any] | None:
    path = root_path(root, DERIVATIVE_RECEIPT)
    if not path.exists():
        return None
    raw = read_regular(root, DERIVATIVE_RECEIPT)
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicates)
    except ValueError as error:
        raise HardeningError("invalid existing derivative receipt") from error
    if not isinstance(value, dict) or value.get("schema_version") != DERIVATIVE_SCHEMA or raw != canonical(value) + b"\n":
        raise HardeningError("existing derivative receipt is not recognized")
    return value


def harden(root: Path, stock: dict[str, Any]) -> dict[str, Any]:
    prior = existing_receipt(root)
    if prior is None:
        before = verify_stock(root, stock)
    else:
        before = prior.get("before_sentinel_hashes")
        if prior.get("stock_export_digest") != ARCHIVE_SHA256:
            raise HardeningError("existing derivative receipt has different archive identity")
        for name, expected in stock["sentinels"].items():
            if name not in MUTATED_STOCK_PATHS and digest(read_regular(root, name)) != expected:
                raise HardeningError(f"derivative sentinel mismatch: {name}")
    if before != stock["sentinels"]:
        raise HardeningError("existing derivative receipt has different sentinels")
    verify_package_versions(root, stock["post_patch_package_versions"])
    require_executable(root, "/usr/bin/node")
    require_executable(root, "/usr/bin/rtpengine")
    require_executable(root, "/usr/sbin/mariadbd")
    require_executable(root, "/usr/bin/redis-server")
    require_executable(root, FREESWITCH_BIN)
    require_executable(root, DRACHTIO_BIN)
    for script in APP_SCRIPTS.values():
        require_regular(root, f"{APP_ROOT}/{script}")
    removed_now = remove_forbidden_descendants(root) + remove_stale_wants(root)
    log_dir = root_path(root, "var/log")
    log_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(log_dir, 0o755)
    deleted = sorted(set(prior.get("deleted_paths", []) if prior is not None else []) | set(removed_now))
    for unit in MASKED_UNITS:
        mask_unit(root, unit)
    write_file(root, "etc/recova/ecosystem.json", pm2_ecosystem())
    write_file(root, "etc/recova/runtime-contract.conf", runtime_contract())
    write_file(root, "etc/rtpengine/rtpengine.conf", rtp_config())
    patch_grub_config(root)
    write_file(root, "etc/nftables.conf", nftables_entrypoint())
    disable_kernel_rtpengine_module(root)
    write_file(root, "etc/nftables.d/recova-default-deny.nft", nftables())
    enable_nftables(root)
    for name, script in APP_SCRIPTS.items():
        write_file(root, f"etc/systemd/system/recova-{name}.service", app_unit(name, script))
    write_file(
        root,
        "etc/systemd/system/recova-rtpengine.service",
        base_unit(
            "Recova bounded RTP engine",
            "/usr/bin/rtpengine --config-file=/etc/rtpengine/rtpengine.conf --interface=private/${RECOVA_PRIVATE_INTERFACE} --interface=public/${RECOVA_PRIVATE_INTERFACE}!${RECOVA_PUBLIC_INTERFACE}",
            "rtpengine",
        ),
    )
    write_file(
        root,
        "etc/systemd/system/recova-mariadb.service",
        base_unit(
            "Recova ephemeral MariaDB",
            "/usr/sbin/mariadbd --datadir=/run/recova-mariadb/mysql --bind-address=127.0.0.1 --skip-log-bin --general-log=0 --slow-query-log=0",
            "mariadb",
            "ExecStartPre=/usr/bin/install -d -o mysql -g mysql -m 0700 /run/recova-mariadb/mysql\n"
            "ExecStartPre=/usr/bin/mariadb-install-db --user=mysql --datadir=/run/recova-mariadb/mysql --skip-test-db\n"
            "ReadWritePaths=/run/recova-mariadb/mysql\n",
            user="mysql",
            group="mysql",
        ),
    )
    write_file(
        root,
        "etc/systemd/system/recova-redis.service",
        base_unit(
            "Recova ephemeral Redis",
            "/usr/bin/redis-server --bind 127.0.0.1 --dir /run/recova-redis/redis --save '' --appendonly no --logfile /dev/null",
            "redis",
            "ExecStartPre=/usr/bin/install -d -o redis -g redis -m 0700 /run/recova-redis/redis\n"
            "ReadWritePaths=/run/recova-redis/redis\n",
            user="redis",
            group="redis",
        ),
    )
    write_file(
        root,
        "etc/systemd/system/recova-freeswitch.service",
        base_unit(
            "Recova FreeSWITCH",
            f"{FREESWITCH_BIN} -nonat -nc",
            "freeswitch",
            "Environment=RECOVA_LOG_OUTPUT=/dev/null\nEnvironment=RECOVA_CDR_OUTPUT=/dev/null\n"
            "ReadWritePaths=/run/recova-freeswitch\n",
        ),
    )
    write_file(
        root,
        "etc/systemd/system/recova-drachtio.service",
        base_unit(
            "Recova drachtio",
            f"{DRACHTIO_BIN} --config {DRACHTIO_CONFIG}",
            "drachtio",
            "Environment=RECOVA_LOG_OUTPUT=/dev/null\nEnvironment=RECOVA_CDR_OUTPUT=/dev/null\n"
            "ReadWritePaths=/run/recova-drachtio\n",
        ),
    )
    after = {name: post_mutation_digest(root, name) for name in sorted(before)}
    mutation_paths = (
        "etc/nftables.conf", "etc/nftables.d/recova-default-deny.nft",
        "etc/recova/runtime-contract.conf", "etc/rtpengine/rtpengine.conf", "boot/grub/grub.cfg", "etc/modules",
    )
    receipt = {"schema_version": DERIVATIVE_SCHEMA, "classification": "jambonz-mini-v10.2.2-recova-hardened-derivative",
               "stock_export_digest": stock["export_digest"], "acquisition_receipt_digest": stock["acquisition_receipt_digest"],
               "source_image_id": stock["source_image_id"], "sealed_patch_manifest_digest": stock["sealed_patch_manifest_digest"],
               "kernel_backport_manifest_digest": stock["kernel_backport_manifest_digest"],
               "post_patch_package_versions": stock["post_patch_package_versions"], "before_sentinel_hashes": before,
               "after_sentinel_hashes": after,
               "mutations": sorted([f"masked:{unit}" for unit in MASKED_UNITS] +
                                   [f"installed:{unit}" for unit in RUNTIME_UNITS] +
                                   [f"configured:{path}" for path in mutation_paths] +
                                   ["enabled:nftables.service",
                                    "hardened:per-service-runtime-directories",
                                    "hardened:runtime-credentials-from-run",
                                    "hardened:recova-sbc-sip-sidecar-one-shot-register",
                                    "hardened:telephony-null-log-cdr"]),
               "deleted_paths": sorted(set(deleted)), "retained_units": list(RUNTIME_UNITS),
               "purged_disabled_packages": sorted(FORBIDDEN_INSTALLED_PACKAGES),
               "rtp": {"protocol": "udp", "port_start": RTP_START, "port_end": RTP_END, "control_listeners": ["127.0.0.1:2223", "127.0.0.1:9900"]}}
    write_file(root, DERIVATIVE_RECEIPT, canonical(receipt) + b"\n")
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs")
    parser.add_argument("--stock-receipt", required=True)
    parser.add_argument("--receipt")
    args = parser.parse_args(argv)
    try:
        root = Path(args.rootfs)
        if root.is_symlink() or not root.is_dir():
            raise HardeningError("rootfs must be a real directory")
        result = canonical(harden(root.resolve(), validate_stock_receipt(args.stock_receipt))) + b"\n"
        if args.receipt:
            output = Path(args.receipt)
            if output.is_symlink():
                raise HardeningError("receipt output symlink refused")
            output.write_bytes(result)
        else:
            sys.stdout.buffer.write(result)
    except HardeningError as error:
        print(f"harden_candidate_rootfs: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
