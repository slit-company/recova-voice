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
      const req = await srf.request('sip:synthetic', {
        method: 'REGISTER',
        headers: {
          'Contact': `<sip:synthetic;transport=udp>;expires=${DEFAULT_EXPIRES}`,
          'Expires': DEFAULT_EXPIRES
        },
        auth: {username: this.username, password: this.password}
      });
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
const client = {};
const srf = {
  connect: () => {},
  on: () => {},
  use: () => {},
  register: () => {},
  options: () => {}
};
srf.connect({ host: DRACHTIO_HOST, port: DRACHTIO_PORT, secret: DRACHTIO_SECRET });
srf.on('connect', (err, hp, version, localHostports) => {
  if (err) return logger.error({ err }, 'Error connecting to drachtio server');
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
    def test_generated_source_separates_operations_and_bounds_the_flow(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertEqual(patched.count("srf.request("), 1)
        self.assertIn("RECOVA_ONE_SHOT_OPERATION_KIND", patched)
        self.assertIn("recovaOperationKind === 'unregister' ? 0 : DEFAULT_EXPIRES", patched)
        self.assertIn(";expires=${recovaExpires}", patched)
        self.assertIn("'Expires': recovaExpires", patched)
        self.assertIn("recovaResponseCount > 2", patched)
        self.assertIn("transaction_count: 1", patched)
        self.assertIn("retry_count: 0", patched)
        self.assertNotIn("const recovaUnregister", patched)
        one_shot = patched[patched.index("const recovaTerminal ="):]
        for mutation in (
            "updateVoipCarriersRegisterStatus", "createEphemeralGateway",
            "updateCarrierBySid", "dns.resolve4", "dns.resolveSrv",
        ):
            self.assertLess(one_shot.index("return recovaTerminal", one_shot.index("req.on('response'")),
                            one_shot.index(mutation, one_shot.index("req.on('response'")))

    def test_challenge_deadline_and_single_terminal_are_fail_closed(self) -> None:
        patched = patcher.patch_regbot(REG)
        self.assertIn("res.status === 401 || res.status === 407", patched)
        self.assertIn("this.oneShotChallengeSeen || recovaChallengeRefused(res)", patched)
        self.assertIn("/stale\\s*=\\s*true/i", patched)
        self.assertIn("setTimeout(() => recovaTerminal(regbot, 'timeout'), remainingMs)", patched)
        self.assertIn("if (recovaTerminalStatus) return recovaTerminalStatus;", patched)
        self.assertIn("if (recovaResponseCount > 2) return recovaTerminal(this, 'refused');", patched)
        self.assertNotIn("this.timer = setTimeout", patched[
            patched.index("if (!recovaBegin(this, srf)) return this.oneShotCompletion;"):
            patched.index("if (this.retired)", patched.index("req.on('response'"))
        ])

    def test_entry_bypasses_all_recurring_registration_authority(self) -> None:
        patched = patcher.patch_trunk(TRUNK)
        entry = patched.index("if (recovaOneShot) return recovaRunOnce(srf);")
        for side_effect in (
            "addKeyNx", "setInterval(getLocalSIPDomain", "Math.random()",
            "setInterval(checkStatus", "updateCarrierRegbots(logger, srf);",
        ):
            self.assertLess(entry, patched.index(side_effect))
        self.assertIn("carriers.length !== 1", patched)
        self.assertIn("gateways.length !== 1 || !isValidIPv4", patched)
        self.assertIn("await rb.start(srf)", patched)

    def test_app_validates_operation_before_traffic_and_emits_no_authority_receipt(self) -> None:
        patched = patcher.patch_app(APP)
        connect = patched.index("srf.connect({ host:")

        self.assertLess(
            patched.index("RECOVA_ONE_SHOT_OPERATION_KIND"),
            connect,
        )
        self.assertLess(
            patched.index("throw new Error('invalid one-shot operation kind')"),
            connect,
        )
        for forbidden in (
            "RECOVA_ONE_SHOT_OPERATION_UUID",
            "RECOVA_ONE_SHOT_REQUEST_DIGEST",
            "RECOVA_ONE_SHOT_CANDIDATE_DIGEST",
            "RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST",
            "RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST",
            "RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID",
            "process.stdout.write",
        ):
            self.assertNotIn(forbidden, patched)
        finish = patched[patched.index("const recovaFinish ="):connect]
        self.assertIn("if (recovaFinished) return;", finish)
        self.assertIn("process.exit(terminalOutcome === 'succeeded' ? 0 : 1)", finish)
        self.assertNotIn("JSON.stringify", finish)
        self.assertIn("srf.locals.recovaOneShotDeadlineMonotonicMs = recovaDeadlineMonotonicMs", patched)
        self.assertIn("srf.use('register', [recovaRejectInbound,", patched)
        self.assertIn("srf.use('options', [recovaRejectInbound,", patched)

    def test_source_hashes_shape_and_atomicity_remain_locked(self) -> None:
        self.assertEqual(
            patcher.APPROVED_APP_SHA256,
            "1a9eac835b9fe26184267286f0ff257a4a4bde972408533d78db29e4ef3f4671",
        )
        with self.assertRaises(patcher.Refusal):
            patcher.approved("0" * 64, patcher.APPROVED_APP_SHA256, "app")
        with self.assertRaises(patcher.Refusal):
            patcher.patch_regbot(REG.replace("async register(srf)", "async register()"))
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
    def test_generated_regbot_behavior_for_both_operations_and_adversarial_responses(self) -> None:
        harness = r"""
const assert = require('assert');
const {EventEmitter} = require('events');
global.assert = assert;
global.DEFAULT_EXPIRES = 3600;
global.JAMBONES_REGBOT_USER_AGENT = '';
global.version = '10.2.2';
const Regbot = require('./regbot');
const scenario = process.env.SCENARIO;
const req = new EventEmitter();
let requests = 0;
let sent;
const response = (status, header = '') => ({
  status,
  get: () => header,
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
  request: async(uri, opts) => {
    requests += 1;
    sent = opts;
    setTimeout(() => {
      if (scenario === 'challenge-success') {
        req.emit('response', response(401));
        setTimeout(() => req.emit('response', response(200)), 0);
      } else if (scenario === 'stale') {
        req.emit('response', response(401, 'Digest stale=true'));
      } else if (scenario === 'repeated-challenge') {
        req.emit('response', response(401));
        setTimeout(() => req.emit('response', response(407)), 0);
      } else if (scenario === 'too-many') {
        req.emit('response', response(401));
        req.emit('response', response(200));
        req.emit('response', response(200));
      } else if (scenario === 'timeout') {
        req.emit('response', response(401));
      } else {
        req.emit('response', response(500));
      }
    }, 0);
    return req;
  }
};
const rb = new Regbot({debug() {}, info() {}, warn() {}, error() {}}, {
  voip_carrier_sid: 'carrier', ipv4: '192.0.2.20', port: 5060,
  username: 'opaque-user', password: 'opaque-secret', protocol: 'udp',
  sip_realm: '192.0.2.20', from_user: 'opaque-user',
  outbound_sip_proxy: null, trunk_type: 'reg', sip_gateway_sid: 'gateway'
});
(async() => {
  const result = await rb.start(srf);
  const expected = scenario === 'challenge-success' ? 'succeeded' :
    scenario === 'failure' ? 'failure' :
    scenario === 'timeout' ? 'timeout' : 'refused';
  assert.strictEqual(result.outcome, expected);
  assert.strictEqual(result, rb.oneShotStatus);
  assert(Object.isFrozen(result));
  assert.strictEqual(requests, 1);
  assert.strictEqual(result.transaction_count, 1);
  assert.strictEqual(result.retry_count, 0);
  assert(result.response_count >= 1 && result.response_count <= 2);
  assert.strictEqual(sent.headers.Expires,
    process.env.RECOVA_ONE_SHOT_OPERATION_KIND === 'unregister' ? 0 : 3600);
  assert.strictEqual(result.deregistered,
    expected === 'succeeded' && process.env.RECOVA_ONE_SHOT_OPERATION_KIND === 'unregister');
  assert(!JSON.stringify(result).includes('opaque-'));
  await assert.rejects(() => rb.start(srf), /one-shot operation refused/);
})().catch((error) => { console.error(error); process.exitCode = 1; });
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            generated = patcher.patch_regbot(REG).replace(
                "const RECOVA_ONE_SHOT_DEADLINE_MS = 32000;",
                "const RECOVA_ONE_SHOT_DEADLINE_MS = 20;",
            )
            (root / "regbot.js").write_text(generated, encoding="utf-8")
            (root / "config.js").write_text(
                "module.exports={JAMBONES_REGBOT_DEFAULT_EXPIRES_INTERVAL:3600,"
                "JAMBONES_REGBOT_MIN_EXPIRES_INTERVAL:30,REGISTER_RESPONSE_REMOVE:[],"
                "JAMBONES_REGBOT_USER_AGENT:'test',JAMBONES_REGBOT_FAILURE_RETRY_INTERVAL:300,"
                "JAMBONES_REGBOT_REGISTER_FAILURE_THRESHOLD:3};",
                encoding="utf-8",
            )
            (root / "utils.js").write_text(
                "module.exports={isValidDomainOrIP:()=>true,isValidIPv4:(v)=>"
                "/^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(v)};",
                encoding="utf-8",
            )
            (root / "package.json").write_text('{"version":"10.2.2"}', encoding="utf-8")
            script = root / "harness.js"
            script.write_text(harness, encoding="utf-8")
            for operation in ("register", "unregister"):
                for scenario in (
                    "challenge-success", "stale", "repeated-challenge",
                    "too-many", "failure", "timeout",
                ):
                    result = subprocess.run(
                        [os.environ["NODE_BINARY"], str(script)],
                        cwd=root,
                        env={
                            **os.environ,
                            "SCENARIO": scenario,
                            "RECOVA_ONE_SHOT_OPERATION_KIND": operation,
                        },
                        text=True,
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                    self.assertEqual(
                        result.returncode, 0,
                        f"{operation}/{scenario}: {result.stderr}",
                    )

    @unittest.skipUnless(os.environ.get("NODE_BINARY"), "Node is provided only by explicit test subprocess")
    def test_generated_outputs_pass_node_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for name, source in (
                ("regbot.js", patcher.patch_regbot(REG)),
                ("sip-trunk-register.js", patcher.patch_trunk(TRUNK)),
                ("app.js", patcher.patch_app(APP)),
            ):
                path = Path(directory, name)
                path.write_text(source)
                result = subprocess.run(
                    [os.environ["NODE_BINARY"], "--check", str(path)],
                    text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__": unittest.main()
