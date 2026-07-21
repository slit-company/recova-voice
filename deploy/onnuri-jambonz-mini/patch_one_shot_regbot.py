#!/usr/bin/env python3
"""Offline, hash-locked patcher for the reviewed Jambonz registration derivative."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Final

REG: Final = PurePosixPath("home/jambonz/apps/sbc-sip-sidecar/lib/regbot.js")
TRUNK: Final = PurePosixPath("home/jambonz/apps/sbc-sip-sidecar/lib/sip-trunk-register.js")
APP: Final = PurePosixPath("home/jambonz/apps/sbc-sip-sidecar/app.js")
APPROVED_REGBOT_SHA256: Final = "76dc84e1b1f67bd5787c79e0ba10de5b91b3a539c82929df4e6b84216b497c77"
APPROVED_TRUNK_SHA256: Final = "9a00cbb30e601ad838ae00bdd424187568012b495391e1781332ab92b8929bab"
APPROVED_APP_SHA256: Final = "1265bd98f943a662e093ca748cd237f9036d1805cac5b54ef1e1d5e78fd9a6f1"
_HEX = frozenset("0123456789abcdef")


class Refusal(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def approved(value: str, expected: str, label: str) -> None:
    if len(value) != 64 or any(c not in _HEX for c in value):
        raise Refusal(f"{label} must be lowercase SHA-256")
    if value != expected:
        raise Refusal(f"{label} is not the selected reviewed export")


def regular(root: Path, rel: PurePosixPath) -> Path:
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise Refusal("root must be an absolute non-symlink directory")
    path = root
    for part in rel.parts:
        if part in ("", ".", ".."):
            raise Refusal("unsafe reviewed path")
        path /= part
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError as error:
            raise Refusal("reviewed source is missing") from error
        if stat.S_ISLNK(mode):
            raise Refusal("symlink refused")
    if not stat.S_ISREG(path.lstat().st_mode):
        raise Refusal("reviewed source must be regular")
    return path


def source(root: Path, rel: PurePosixPath, expected: str) -> tuple[Path, str]:
    path = regular(root, rel)
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise Refusal("reviewed source digest mismatch")
    try:
        return path, raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal("reviewed source is not UTF-8") from error


def once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise Refusal(f"unrecognized {label} anchor")
    return text.replace(old, new, 1)


def patch_regbot(stock: str) -> str:
    """Patch only the reviewed `async register(srf)` source shape."""
    required = ("async register(srf)", "dns.resolve4", "dns.resolveSrv", "updateVoipCarriersRegisterStatus", "createEphemeralGateway", "updateCarrierBySid", "module.exports = Regbot;")
    if "RECOVA_ONE_SHOT_REGISTER" in stock or any(anchor not in stock for anchor in required):
        raise Refusal("unrecognized regbot selected-export shape")
    text = once(stock, "const useragent = JAMBONES_REGBOT_USER_AGENT || `Jambonz ${version}`;", """const useragent = JAMBONES_REGBOT_USER_AGENT || `Jambonz ${version}`;
const recovaOneShot = process.env.RECOVA_ONE_SHOT_REGISTER === '1';
const RECOVA_ONE_SHOT_DEADLINE_MS = 32000;
let recovaOneShotStarted = false;
let recovaDeadlineMonotonicMs = null;
let recovaDeadlineTimer = null;
let recovaTerminalStatus = null;
const recovaMonotonicMs = () => Number(process.hrtime.bigint() / 1000000n);
const recovaTerminal = (regbot, outcome) => {
  if (recovaTerminalStatus) return recovaTerminalStatus;
  if (recovaDeadlineMonotonicMs === null) recovaDeadlineMonotonicMs = recovaMonotonicMs() + RECOVA_ONE_SHOT_DEADLINE_MS;
  if (recovaDeadlineTimer) clearTimeout(recovaDeadlineTimer);
  recovaDeadlineTimer = null;
  recovaTerminalStatus = Object.freeze({
    outcome, deadline_monotonic_ms: recovaDeadlineMonotonicMs, finished_monotonic_ms: recovaMonotonicMs()
  });
  regbot.status = outcome === 'success' ? 'registered' : 'fail';
  regbot.oneShotStatus = recovaTerminalStatus;
  if (regbot.oneShotResolve) regbot.oneShotResolve(recovaTerminalStatus);
  return recovaTerminalStatus;
};
const recovaBegin = (regbot) => {
  recovaDeadlineMonotonicMs = recovaMonotonicMs() + RECOVA_ONE_SHOT_DEADLINE_MS;
  regbot.oneShotCompletion = new Promise((resolve) => { regbot.oneShotResolve = resolve; });
  recovaDeadlineTimer = setTimeout(() => recovaTerminal(regbot, 'timeout'), RECOVA_ONE_SHOT_DEADLINE_MS);
};
const recovaChallengeRefused = (res) => /stale\\s*=\\s*true/i.test(String(
  (res.get && (res.get('www-authenticate') || res.get('proxy-authenticate'))) || ''
));
const recovaLogger = (logger) => !recovaOneShot ? logger : {
  debug: () => {}, info: () => {}, warn: () => {}, error: () => {}
};""", "regbot prelude")
    text = once(text, "    this.logger = logger;", "    this.logger = recovaLogger(logger);", "regbot logger")
    text = once(text, """  async start(srf) {
    assert(!this.timer);

    this.logger.info(`starting regbot for ${this.fromUser}@${this.sip_realm}`);
    this.register(srf);
  }""", """  async start(srf) {
    assert(!this.timer);
    if (recovaOneShot) {
      if (recovaOneShotStarted || !isValidIPv4(this.ipv4)) throw new Error('one-shot registration refused');
      recovaOneShotStarted = true;
      this.retired = false;
      return this.register(srf);
    }
    this.logger.info(`starting regbot for ${this.fromUser}@${this.sip_realm}`);
    return this.register(srf);
  }""", "regbot start")
    text = once(text, """  configKey() {
    return [""", """  configKey() {
    if (recovaOneShot) return 'recova-one-shot';
    return [""", "regbot config key")
    text = once(text, """  static configKeyFromOpts(opts) {
    const sip_realm""", """  static configKeyFromOpts(opts) {
    if (recovaOneShot) return 'recova-one-shot';
    const sip_realm""", "regbot static config key")
    text = once(text, "      const req = await srf.request(", "      if (recovaOneShot) recovaBegin(this);\n      const req = await srf.request(", "regbot transaction")
    text = once(text, """      req.on('response', async(res) => {
        if (this.retired) {""", """      req.on('response', async(res) => {
        if (recovaOneShot) {
          if (recovaTerminalStatus) return recovaTerminalStatus;
          if (res.status === 401 || res.status === 407) {
            if (this.oneShotChallengeSeen || recovaChallengeRefused(res)) return recovaTerminal(this, 'refused');
            this.oneShotChallengeSeen = true;
            return;
          }
          return recovaTerminal(this, res.status === 200 ? 'success' : 'failure');
        }
        if (this.retired) {""", "regbot response")
    text = once(text, """      });
    } catch (err) {""", """      });
      if (recovaOneShot) return this.oneShotCompletion;
    } catch (err) {""", "regbot completion")
    text = once(text, """    } catch (err) {
      this.logger.error({ err }, `${this.aor}: Error registering to ${this.ipv4}:${this.port}`);""", """    } catch (err) {
      if (recovaOneShot) return recovaTerminal(this, 'exception');
      this.logger.error({ err }, `${this.aor}: Error registering to ${this.ipv4}:${this.port}`);""", "regbot exception")
    return text


def patch_trunk(stock: str) -> str:
    required = ("const Regbot = require('./regbot');", "const { sleepFor } = require('./utils');", "setInterval(getLocalSIPDomain, 300000", "Math.random()", "addKeyNx", "setInterval(checkStatus", "updateCarrierRegbots", "module.exports = async(logger, srf) => {")
    if "RECOVA_ONE_SHOT_REGISTER" in stock or any(anchor not in stock for anchor in required):
        raise Refusal("unrecognized sip-trunk-register selected-export shape")
    text = once(stock, "const { sleepFor } = require('./utils');", """const { sleepFor, isValidIPv4 } = require('./utils');
const recovaOneShot = process.env.RECOVA_ONE_SHOT_REGISTER === '1';""", "trunk imports")
    text = once(text, """module.exports = async(logger, srf) => {
  if (initialized) return;
  initialized = true;""", """module.exports = async(logger, srf) => {
  if (initialized) return;
  initialized = true;
  if (recovaOneShot) return recovaRunOnce(srf);""", "trunk entry")
    text = once(text, "const checkStatus = async(logger, srf) => {", """const recovaRunOnce = async(srf) => {
  if (!recovaOneShot) throw new Error('one-shot registration refused');
  const { lookupAllVoipCarriers, lookupSipGatewaysByCarrier } = srf.locals.dbHelpers;
  const carriers = (await lookupAllVoipCarriers()).filter((c) => c.requires_register && c.is_active);
  if (carriers.length !== 1) throw new Error('one-shot requires exactly one carrier');
  const carrier = carriers[0];
  const gateways = (await lookupSipGatewaysByCarrier(carrier.voip_carrier_sid))
    .filter((gw) => gw.outbound && gw.is_active);
  if (gateways.length !== 1 || !isValidIPv4(gateways[0].ipv4) ||
      (carrier.outbound_sip_proxy && carrier.outbound_sip_proxy !== gateways[0].ipv4)) {
    throw new Error('one-shot requires one IPv4 gateway and no alternate proxy');
  }
  const gw = gateways[0];
  const rb = new Regbot({debug: () => {}, info: () => {}, warn: () => {}, error: () => {}}, {
    voip_carrier_sid: carrier.voip_carrier_sid, ipv4: gw.ipv4, port: gw.port, protocol: gw.protocol,
    use_sips_scheme: gw.use_sips_scheme, username: carrier.register_username, password: carrier.register_password,
    sip_realm: carrier.register_sip_realm, from_user: carrier.register_from_user,
    from_domain: carrier.register_from_domain, use_public_ip_in_contact: carrier.register_public_ip_in_contact,
    outbound_sip_proxy: carrier.outbound_sip_proxy, trunk_type: carrier.trunk_type, sip_gateway_sid: gw.sip_gateway_sid
  });
  srf.locals.regbot = {active: true, one_shot: true};
  srf.locals.regbotStatus = () => rb.oneShotStatus;
  await rb.start(srf);
  return rb.oneShotStatus;
};

const checkStatus = async(logger, srf) => {""", "trunk one-shot function")
    return text
def patch_app(stock: str) -> str:
    """Disable only registration-adjacent recurrent/app management behavior."""
    required = (
        "require('./lib/sip-trunk-register')(logger, srf);",
        "require('./lib/sip-trunk-options-ping')(logger, srf);",
        "srf.use('register', [", "srf.use('options', [",
        "require('./lib/cli/runtime-config').initialize(srf.locals, logger);",
        "setInterval(async() => {", "srf.register(require('./lib/register')({logger}));",
        "srf.options(require('./lib/options')({srf, logger}));",
    )
    if "RECOVA_ONE_SHOT_REGISTER" in stock or any(anchor not in stock for anchor in required):
        raise Refusal("unrecognized app selected-export shape")
    text = once(stock, "} = require('./lib/config');", """} = require('./lib/config');
const recovaOneShot = process.env.RECOVA_ONE_SHOT_REGISTER === '1';
const recovaRejectInbound = (req, res, next) => {
  if (!recovaOneShot) return next();
  return res.send(403);
};""", "app prelude")
    text = once(text, """  /* start regbot */
  require('./lib/sip-trunk-register')(logger, srf);
  // Start Options bot
  require('./lib/sip-trunk-options-ping')(logger, srf);""", """  /* Registration remains stock-owned; one-shot omits the OPTIONS bot. */
  require('./lib/sip-trunk-register')(logger, srf);
  if (!recovaOneShot) require('./lib/sip-trunk-options-ping')(logger, srf);""", "app bot startup")
    text = once(text, "srf.use('register', [", "srf.use('register', [recovaRejectInbound,", "app register middleware")
    text = once(text, "srf.use('options', [", "srf.use('options', [recovaRejectInbound,", "app options middleware")
    text = once(text, """// Start CLI runtime config server with access to srf.locals
require('./lib/cli/runtime-config').initialize(srf.locals, logger);

setInterval(async() => {""", """// The one-shot derivative has no CLI reload endpoint or recurring statistics timer.
if (!recovaOneShot) {
  require('./lib/cli/runtime-config').initialize(srf.locals, logger);
  setInterval(async() => {""", "app recurring start")
    text = once(text, """  stats.gauge('sbc.users.count', parseInt(count));
}, 30000);""", """    stats.gauge('sbc.users.count', parseInt(count));
  }, 30000);
}""", "app recurring end")
    return text




def atomic(path: Path, data: bytes) -> None:
    metadata = path.stat()
    tmp = path.with_name(f".{path.name}.recova-new")
    if tmp.exists() or tmp.is_symlink():
        raise Refusal("temporary patch path already exists")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IMODE(metadata.st_mode))
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


def patch_tree(
    root: Path,
    regbot_sha256: str = APPROVED_REGBOT_SHA256,
    sip_trunk_register_sha256: str = APPROVED_TRUNK_SHA256,
    app_sha256: str = APPROVED_APP_SHA256,
    derivative_id: str = "",
) -> dict[str, object]:
    approved(regbot_sha256, APPROVED_REGBOT_SHA256, "regbot SHA-256")
    approved(sip_trunk_register_sha256, APPROVED_TRUNK_SHA256, "sip-trunk-register SHA-256")
    approved(app_sha256, APPROVED_APP_SHA256, "app SHA-256")
    if len(derivative_id) != 64 or any(c not in _HEX for c in derivative_id): raise Refusal("derivative identity must be lowercase SHA-256")
    if root.is_symlink() or not root.is_absolute():
        raise Refusal("root must be an absolute non-symlink directory")
    root = root.resolve(strict=True)
    reg_path, reg = source(root, REG, regbot_sha256)
    trunk_path, trunk = source(root, TRUNK, sip_trunk_register_sha256)
    app_path, app = source(root, APP, app_sha256)
    new_reg, new_trunk, new_app = patch_regbot(reg).encode(), patch_trunk(trunk).encode(), patch_app(app).encode()
    atomic(reg_path, new_reg); atomic(trunk_path, new_trunk); atomic(app_path, new_app)
    receipt = {"derivative_id": derivative_id, "format": "recova-one-shot-regbot-receipt-v1", "outputs": {str(REG): sha(new_reg), str(TRUNK): sha(new_trunk), str(APP): sha(new_app)}, "reviewed_inputs": {str(REG): regbot_sha256, str(TRUNK): sip_trunk_register_sha256, str(APP): app_sha256}}
    receipt["receipt_sha256"] = sha(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode())
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline selected-export one-shot patcher")
    parser.add_argument("--root", required=True, type=Path); parser.add_argument("--regbot-sha256", default=APPROVED_REGBOT_SHA256); parser.add_argument("--sip-trunk-register-sha256", default=APPROVED_TRUNK_SHA256); parser.add_argument("--app-sha256", default=APPROVED_APP_SHA256); parser.add_argument("--derivative-id", required=True); parser.add_argument("--receipt", type=Path)
    args = parser.parse_args(argv)
    try:
        output = json.dumps(patch_tree(args.root, args.regbot_sha256, args.sip_trunk_register_sha256, args.app_sha256, args.derivative_id), sort_keys=True, separators=(",", ":")) + "\n"
        if args.receipt:
            if args.receipt.is_symlink(): raise Refusal("receipt symlink refused")
            args.receipt.write_text(output, encoding="utf-8")
        else: sys.stdout.write(output)
        return 0
    except (OSError, Refusal) as error:
        print(f"refused: {error}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
