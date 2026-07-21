"""Offline source-shape and generated-JavaScript contracts for the one-shot patch."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[1] / "patch_one_shot_regbot.py"
spec = importlib.util.spec_from_file_location("one_shot_patcher", MODULE)
assert spec and spec.loader
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)

# Relevant exact v10.2.2 source shapes, reduced only by replacing unrelated bodies.
REG = r'''const dns = require('dns').promises;
const {isValidDomainOrIP, isValidIPv4} = require('./utils');
const useragent = JAMBONES_REGBOT_USER_AGENT || `Jambonz ${version}`;
class Regbot {
  constructor(logger, opts) {
    this.logger = logger;
    this.ipv4 = opts.ipv4; this.port = opts.port; this.protocol = opts.protocol;
    this.status = 'none'; this.fromUser = opts.username; this.sip_realm = opts.sip_realm;
  }
  async start(srf) {
    assert(!this.timer);

    this.logger.info(`starting regbot for ${this.fromUser}@${this.sip_realm}`);
    this.register(srf);
  }
  configKey() {
    return [this.username, this.password].join('|');
  }
  static configKeyFromOpts(opts) {
    const sip_realm = opts.sip_realm || opts.ipv4;
    return [opts.username, opts.password, sip_realm].join('|');
  }
  async register(srf) {
    const { createEphemeralGateway } = srf.locals.realtimeDbHelpers;
    const { updateVoipCarriersRegisterStatus } = srf.locals.dbHelpers;
    try {
      const req = await srf.request('sip:synthetic', {method: 'REGISTER', auth: {username: this.username, password: this.password}});
      req.on('response', async(res) => {
        if (this.retired) { return; }
        let expires;
        if (res.status !== 200) { this.timer = setTimeout(this.register.bind(this, srf), 300000); }
        else { this.timer = setTimeout(this.register.bind(this, srf), 300000); }
        updateVoipCarriersRegisterStatus(this.voip_carrier_sid, JSON.stringify({expires}));
        if (this.trunk_type === 'reg') { await createEphemeralGateway(this.ipv4, this.voip_carrier_sid, expires); }
        await updateCarrierBySid(this.voip_carrier_sid, {});
      });
    } catch (err) {
      this.logger.error({ err }, `${this.aor}: Error registering to ${this.ipv4}:${this.port}`);
      this.timer = setTimeout(this.register.bind(this, srf), 300000);
      updateVoipCarriersRegisterStatus(this.voip_carrier_sid, JSON.stringify({status: 'fail'}));
    }
  }
}
const dnsResolverA = async(logger, hostname) => { return dns.resolve4(hostname); };
const dnsResolverSrv = async(logger, hostname, transport) => { return dns.resolveSrv(hostname); };
module.exports = Regbot;
'''
TRUNK = r'''const Regbot = require('./regbot');
const { sleepFor } = require('./utils');
const MAX_INITIAL_DELAY = 15;
const REGBOT_STATUS_CHECK_INTERVAL = 60;
let initialized = false;
const regbots = [];
const updateCarrierRegbots = async(logger, srf) => {};
module.exports = async(logger, srf) => {
  if (initialized) return;
  initialized = true;
  const { addKeyNx } = srf.locals.realtimeDbHelpers;
  setInterval(getLocalSIPDomain, 300000, logger, srf);
  const ms = Math.floor(Math.random() * MAX_INITIAL_DELAY) * 1000;
  await waitFor(ms);
  const result = await addKeyNx(regbotKey, myToken, REGBOT_STATUS_CHECK_INTERVAL + 10);
  setInterval(checkStatus.bind(null, logger, srf), REGBOT_STATUS_CHECK_INTERVAL * 1000);
  updateCarrierRegbots(logger, srf);
};
const checkStatus = async(logger, srf) => {};
'''
APP = r'''const {
  NODE_ENV,
  SBC_PUBLIC_ADDRESS_KEEP_ALIVE_IN_MILISECOND
} = require('./lib/config');
srf.connect({}, () => {
  /* start regbot */
  require('./lib/sip-trunk-register')(logger, srf);
  // Start Options bot
  require('./lib/sip-trunk-options-ping')(logger, srf);
});
srf.use('register', [
  initLocals
]);
srf.use('options', [
  initLocals
]);
srf.register(require('./lib/register')({logger}));
srf.options(require('./lib/options')({srf, logger}));
// Start CLI runtime config server with access to srf.locals
require('./lib/cli/runtime-config').initialize(srf.locals, logger);

setInterval(async() => {
  const count = await srf.locals.registrar.getCountOfUsers();
  stats.gauge('sbc.users.count', parseInt(count));
}, 30000);
'''


class OneShotPatchContracts(unittest.TestCase):
    def test_real_shape_anchors_patch_and_stock_paths_survive(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertIn("async register(srf)", patched)
        self.assertIn("const req = await srf.request", patched)  # stock transaction owner
        self.assertIn("RECOVA_ONE_SHOT_DEADLINE_MS = 32000", patched)
        self.assertIn("process.env.RECOVA_ONE_SHOT_REGISTER === '1'", patched)
        self.assertIn("Object.freeze({", patched)
        self.assertIn("finished_monotonic_ms: recovaMonotonicMs()", patched)

    def test_terminal_transition_is_single_stable_redacted_object_and_clears_deadline(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertEqual(patched.count("const recovaTerminal ="), 1)
        terminal = patched[patched.index("const recovaTerminal ="):patched.index("const recovaBegin =")]
        self.assertIn("if (recovaTerminalStatus) return recovaTerminalStatus;", terminal)
        self.assertIn("clearTimeout(recovaDeadlineTimer)", terminal)
        self.assertIn("deadline_monotonic_ms: recovaDeadlineMonotonicMs", terminal)
        self.assertIn("finished_monotonic_ms: recovaMonotonicMs()", terminal)
        self.assertNotIn("username", terminal)
        self.assertNotIn("password", terminal)
    def test_timeout_is_the_only_one_shot_timer_and_uses_the_fixed_deadline(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertIn("setTimeout(() => recovaTerminal(regbot, 'timeout'), RECOVA_ONE_SHOT_DEADLINE_MS)", patched)
        self.assertIn("recovaMonotonicMs() + RECOVA_ONE_SHOT_DEADLINE_MS", patched)
        self.assertNotIn("this.timer = setTimeout", patched[patched.index("if (recovaOneShot) recovaBegin(this);"):patched.index("if (this.retired)", patched.index("req.on('response'"))])
        self.assertIn("clearTimeout(recovaDeadlineTimer)", patched)

    def test_one_stock_transaction_and_terminal_paths_bypass_all_side_effects(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertEqual(patched.count("srf.request("), 1)
        response = patched.index("if (recovaOneShot) {", patched.index("req.on('response'"))
        body = patched[response:]
        mutations = [body.index(name) for name in ("updateVoipCarriersRegisterStatus", "createEphemeralGateway", "updateCarrierBySid", "dns.resolve4", "dns.resolveSrv")]
        self.assertTrue(all(body.index("return recovaTerminal", 0, mutation) >= 0 for mutation in mutations))
        self.assertIn("return recovaTerminal(this, 'exception')", patched)
        self.assertIn("if (recovaOneShot) return this.oneShotCompletion;", patched)

    def test_duplicate_start_and_challenge_replay_or_stale_challenge_refuse(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertIn("recovaOneShotStarted || !isValidIPv4(this.ipv4)", patched)
        self.assertIn("throw new Error('one-shot registration refused')", patched)
        self.assertIn("res.status === 401 || res.status === 407", patched)
        self.assertIn("this.oneShotChallengeSeen || recovaChallengeRefused(res)", patched)
        self.assertIn("recovaTerminal(this, 'refused')", patched)
        self.assertIn("/stale\\s*=\\s*true/i", patched)

    def test_one_shot_entry_precedes_random_delay_redis_intervals_and_polling(self) -> None:
        patched = patcher.patch_trunk(TRUNK)
        entry = patched.index("if (recovaOneShot) return recovaRunOnce(srf);")
        for stock_side_effect in ("addKeyNx", "setInterval(getLocalSIPDomain", "Math.random()", "setInterval(checkStatus", "updateCarrierRegbots(logger, srf);"):
            self.assertLess(entry, patched.index(stock_side_effect))
        self.assertIn("if (!recovaOneShot) throw new Error('one-shot registration refused');", patched)
        self.assertIn("carriers.length !== 1", patched)
        self.assertIn("gateways.length !== 1 || !isValidIPv4", patched)
        self.assertIn("await rb.start(srf)", patched)

    def test_terminal_status_accessor_has_no_started_state_or_fresh_timestamp(self) -> None:
        patched = patcher.patch_trunk(TRUNK)
        one_shot = patched[patched.index("const recovaRunOnce"):patched.index("const checkStatus")]
        self.assertIn("srf.locals.regbotStatus = () => rb.oneShotStatus;", one_shot)
        self.assertIn("return rb.oneShotStatus;", one_shot)
        self.assertNotIn("started", one_shot)
        self.assertNotIn("recovaDeadline", patched)

    def test_duplicate_and_restart_claims_are_refused_and_keys_are_redacted(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertIn("return 'recova-one-shot';", patched)
        one_shot_start = patched[patched.index("if (recovaOneShot) {", patched.index("async start")):patched.index("this.logger.info", patched.index("async start"))]
        self.assertNotIn("username", one_shot_start)
        self.assertNotIn("password", one_shot_start)
        self.assertNotIn("fromUser", one_shot_start)
        self.assertNotIn("sip_realm", one_shot_start)

    def test_app_disables_options_inbound_register_options_cli_and_stats_only_in_mode(self) -> None:
        patched = patcher.patch_app(APP)
        self.assertIn("if (!recovaOneShot) require('./lib/sip-trunk-options-ping')(logger, srf);", patched)
        self.assertIn("srf.use('register', [recovaRejectInbound,", patched)
        self.assertIn("srf.use('options', [recovaRejectInbound,", patched)
        self.assertIn("if (!recovaOneShot) {\n  require('./lib/cli/runtime-config')", patched)
        self.assertIn("return res.send(403);", patched)

    def test_one_shot_proxy_must_match_the_only_ipv4_gateway(self) -> None:
        self.assertIn("carrier.outbound_sip_proxy !== gateways[0].ipv4", patcher.patch_trunk(TRUNK))
    def test_app_selected_export_identity_and_sidecar_anchors_are_locked(self) -> None:
        self.assertEqual(
            patcher.APPROVED_APP_SHA256,
            "1265bd98f943a662e093ca748cd237f9036d1805cac5b54ef1e1d5e78fd9a6f1",
        )
        with self.assertRaises(patcher.Refusal):
            patcher.approved("0" * 64, patcher.APPROVED_APP_SHA256, "app")
        self.assertIn("require('./lib/sip-trunk-register')(logger, srf);", APP)
        self.assertIn("require('./lib/sip-trunk-options-ping')(logger, srf);", APP)

    def test_unexpected_shape_and_nonallowlisted_input_refuse(self) -> None:
        with self.assertRaises(patcher.Refusal): patcher.patch_regbot(REG.replace("async register(srf)", "async register()"))
        with self.assertRaises(patcher.Refusal): patcher.approved("0" * 64, patcher.APPROVED_REGBOT_SHA256, "regbot")

    def test_atomic_patch_preserves_mode_and_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.js"
            path.write_bytes(b"stock\n")
            path.chmod(0o640)
            before = path.stat()

            patcher.atomic(path, b"patched\n")

            after = path.stat()
            self.assertEqual(path.read_bytes(), b"patched\n")
            self.assertEqual(after.st_mode & 0o777, before.st_mode & 0o777)
            self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))

    @unittest.skipUnless(os.environ.get("NODE_BINARY"), "Node is provided only by explicit test subprocess")
    def test_generated_regbot_executes_terminal_challenge_refusal_and_timeout_contracts(self) -> None:
        harness = r"""
const assert = require('assert');
const {EventEmitter} = require('events');
global.assert = assert;
global.JAMBONES_REGBOT_USER_AGENT = '';
global.version = '10.2.2';
process.env.RECOVA_ONE_SHOT_REGISTER = '1';
const Regbot = require('./regbot');
const scenario = process.env.SCENARIO;
const req = new EventEmitter();
let requests = 0;
const response = (status) => ({
  status,
  get: () => '',
  has: () => false,
  getParsedHeader: () => []
});
const srf = {
  locals: {
    realtimeDbHelpers: {createEphemeralGateway: async() => {}},
    dbHelpers: {updateVoipCarriersRegisterStatus: async() => {}},
    writeAlerts: () => {},
    localSIPDomain: null,
    sbcPublicIpAddress: {udp: '192.0.2.10'}
  },
  request: async() => {
    requests += 1;
    setTimeout(() => {
      if (scenario === 'success') {
        req.emit('response', response(401));
        setTimeout(() => req.emit('response', response(200)), 0);
      } else if (scenario === 'repeated-challenge') {
        req.emit('response', response(401));
        setTimeout(() => req.emit('response', response(407)), 0);
      }
    }, 0);
    return req;
  }
};
const logger = {debug() {}, info() {}, warn() {}, error() {}};
const rb = new Regbot(logger, {
  voip_carrier_sid: 'carrier', ipv4: '192.0.2.20', port: 5060,
  username: 'opaque-user', password: 'opaque-secret', protocol: 'udp',
  sip_realm: '192.0.2.20', from_user: 'opaque-user',
  outbound_sip_proxy: null, trunk_type: 'reg', sip_gateway_sid: 'gateway'
});
(async() => {
  const result = await rb.start(srf);
  const expected = scenario === 'success' ? 'success' :
    scenario === 'repeated-challenge' ? 'refused' : 'timeout';
  assert.strictEqual(result.outcome, expected);
  assert.strictEqual(result, rb.oneShotStatus);
  assert(Object.isFrozen(result));
  assert.strictEqual(requests, 1);
  assert(!JSON.stringify(result).includes('opaque-'));
  await assert.rejects(() => rb.start(srf), /one-shot registration refused/);
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = patcher.patch_regbot(REG)
            generated = generated.replace("const RECOVA_ONE_SHOT_DEADLINE_MS = 32000;", "const RECOVA_ONE_SHOT_DEADLINE_MS = 20;")
            (root / "regbot.js").write_text(generated, encoding="utf-8")
            (root / "config.js").write_text(
                "module.exports={JAMBONES_REGBOT_DEFAULT_EXPIRES_INTERVAL:3600,"
                "JAMBONES_REGBOT_MIN_EXPIRES_INTERVAL:30,REGISTER_RESPONSE_REMOVE:[],"
                "JAMBONES_REGBOT_USER_AGENT:'test',JAMBONES_REGBOT_FAILURE_RETRY_INTERVAL:300,"
                "JAMBONES_REGBOT_REGISTER_FAILURE_THRESHOLD:3};",
                encoding="utf-8",
            )
            (root / "utils.js").write_text(
                "module.exports={isValidDomainOrIP:()=>true,isValidIPv4:(v)=>/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(v)};",
                encoding="utf-8",
            )
            (root / "package.json").write_text('{"version":"10.2.2"}', encoding="utf-8")
            script = root / "harness.js"
            script.write_text(harness, encoding="utf-8")
            for scenario in ("success", "repeated-challenge", "timeout"):
                result = subprocess.run(
                    [os.environ["NODE_BINARY"], str(script)],
                    cwd=root,
                    env={**os.environ, "SCENARIO": scenario},
                    text=True,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, f"{scenario}: {result.stderr}")

    @unittest.skipUnless(os.environ.get("NODE_BINARY"), "Node is provided only by explicit test subprocess")
    def test_generated_outputs_pass_node_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for name, source in (("regbot.js", patcher.patch_regbot(REG)), ("sip-trunk-register.js", patcher.patch_trunk(TRUNK)), ("app.js", patcher.patch_app(APP))):
                path = Path(directory, name); path.write_text(source)
                result = subprocess.run([os.environ["NODE_BINARY"], "--check", str(path)], text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__": unittest.main()
