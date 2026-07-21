'use strict';

const path = require('path');
const fs = require('fs');
const https = require('https');
const net = require('net');
const crypto = require('crypto');
const {verifyAuthorization, fail} = require('./verify-registration-egress-proof');
const {
  canonical,
  sha256,
  signExecutionAttestation,
  startRegistrationProxy,
} = require('./registration-sip-attestor');

const MAX_BODY_BYTES = 8192;
const APP_DEADLINE_MS = 32000;
const CONTROL_DIRECTORY = '/run/g008-registration-control';
const HANDOFF_SCHEMA = 'recova-g008-registration-handoff-v1';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const HANDOFF_KEYS = [
  'candidate_digest', 'execution_nonce_digest', 'execution_seal_uuid',
  'gate_envelope_digest', 'opaque_authorization', 'operation_kind',
  'operation_uuid', 'ordinal', 'organization_id', 'prior_register_gate_id',
  'prior_register_operation_uuid', 'registration_gate_id', 'request_digest',
  'schema_version', 'stage',
];
const consumedHandoffs = new Set();
const CONTROL_SCHEMA = 'recova-g008-transaction-broker-control-v1';
const CONTROL_RESPONSE_SCHEMA = 'recova-g008-transaction-broker-receipt-v1';
function readyPath(operation) {
  if (operation !== 'register' && operation !== 'unregister') fail();
  return path.join(CONTROL_DIRECTORY, `${operation}.ready`);
}
const pendingHandoffs = new Map();
let expectedOperation = 'register';

const handoffWaiters = new Map();

function required(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) fail();
  return value;
}

function rejectAmbientSecretEnvironment() {
  for (const name of [
    'G009_JAMBONES_MYSQL_PASSWORD', 'G009_JWT_SECRET', 'G009_ENCRYPTION_SECRET',
    'G009_DRACHTIO_FEATURE_SECRET', 'G009_DRACHTIO_SIP_SECRET',
    'G009_FREESWITCH_ESL_PASSWORD',
  ]) {
    if (Object.prototype.hasOwnProperty.call(process.env, name)) fail();
  }
}

function positivePort(name) {
  const value = required(name);
  if (!/^[0-9]+$/.test(value)) fail();
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) fail();
  return port;
}

function readFileNoLink(path, encoding = null) {
  const stat = fs.lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) fail();
  return fs.readFileSync(path, encoding || undefined);
}

function readSecret(path) {
  const raw = readFileNoLink(path, 'utf8');
  const value = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
  if (!value || value.includes('\n') || value.trim() !== value) fail();
  return value;
}

function authorityUrl(pathname) {
  const base = new URL(required('RECOVA_REGISTRATION_F12_BASE_URL'));
  if (base.protocol !== 'https:' || base.username || base.password || base.search ||
      base.hash || base.pathname !== '/' || base.hostname !== 'f12-ingress') fail();
  return new URL(pathname, base);
}

function postOnce(url, body, tls, deadlineMs) {
  return new Promise((resolve, reject) => {
    const remainingMs = deadlineMs - Date.now();
    if (remainingMs <= 0) return reject(new Error('authorization_expired'));
    const encoded = Buffer.from(canonical(body));
    let deadlineTimer;
    const request = https.request(url, {
      method: 'POST',
      agent: false,
      ca: tls.ca,
      cert: tls.cert,
      key: tls.key,
      servername: url.hostname,
      headers: {
        'content-type': 'application/json',
        'content-length': String(encoded.length),
        'x-recova-verified-mtls-identity': tls.identity,
        'x-recova-verified-mtls-issuer': tls.issuer,
        'x-recova-onnuri-endpoint-credential': tls.credential,
      },
      timeout: Math.min(5000, remainingMs),
    }, (response) => {
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY_BYTES) request.destroy(new Error('response_too_large'));
        else chunks.push(chunk);
      });
      response.on('end', () => {
        clearTimeout(deadlineTimer);
        if (response.statusCode !== 200) return reject(new Error('authority_rejected'));
        try {
          const text = Buffer.concat(chunks).toString('utf8');
          const parsed = JSON.parse(text);
          if (JSON.stringify(parsed) !== text) throw new Error('noncanonical_response');
          resolve(parsed);
        } catch (_) {
          reject(new Error('invalid_authority_response'));
        }
      });
    });
    deadlineTimer = setTimeout(
      () => request.destroy(new Error('authorization_expired')), remainingMs,
    );
    request.once('timeout', () => request.destroy(new Error('authority_timeout')));
    request.once('error', (error) => {
      clearTimeout(deadlineTimer);
      reject(error);
    });
    request.end(encoded);
  });
}

function exactObject(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail();
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = Object.keys(expected).sort();
  if (actualKeys.join(',') !== expectedKeys.join(',')) fail();
  for (const [key, binding] of Object.entries(expected)) {
    if (binding !== undefined && value[key] !== binding) fail();
  }
}

function consumeBody(authorization, claims) {
  return {
    opaque_authorization: authorization,
    organization_id: claims.organization_id,
    registration_gate_id: claims.registration_gate_id,
    operation_uuid: claims.operation_uuid,
    operation_kind: claims.operation_kind,
    request_digest: claims.request_digest,
    candidate_digest: claims.candidate_digest,
    gate_envelope_digest: claims.gate_envelope_digest,
    nonce_digest: claims.nonce_digest,
    prior_register_gate_id: claims.prior_register_gate_id,
    prior_register_operation_uuid: claims.prior_register_operation_uuid,
  };
}

function consumeBinding(claims) {
  return {
    registration_gate_id: claims.registration_gate_id,
    operation_uuid: claims.operation_uuid,
    operation_kind: claims.operation_kind,
    request_digest: claims.request_digest,
    candidate_digest: claims.candidate_digest,
    gate_envelope_digest: claims.gate_envelope_digest,
    nonce_digest: claims.nonce_digest,
    prior_register_gate_id: claims.prior_register_gate_id,
    prior_register_operation_uuid: claims.prior_register_operation_uuid,
    state: 'started',
    challenged: true,
    transaction_count: 1,
    retry_count: 0,
    concurrency_count: 1,
  };
}

function loadPrivateKey(path) {
  const key = crypto.createPrivateKey(readFileNoLink(path));
  if (key.asymmetricKeyType !== 'ec' ||
      !key.asymmetricKeyDetails ||
      !['prime256v1', 'P-256'].includes(key.asymmetricKeyDetails.namedCurve)) fail();
  return key;
}

function deliverHandoff(operation, handoff) {
  const waiter = handoffWaiters.get(operation);
  if (waiter) {
    handoffWaiters.delete(operation);
    waiter(handoff);
    return;
  }
  if (pendingHandoffs.has(operation)) fail();
  pendingHandoffs.set(operation, handoff);
}

function awaitControlHandoff(operation, deadlineMs) {
  const pending = pendingHandoffs.get(operation);
  if (pending) {
    pendingHandoffs.delete(operation);
    return Promise.resolve(pending);
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      handoffWaiters.delete(operation);
      reject(new Error('broker_handoff_timeout'));
    }, Math.max(0, deadlineMs - Date.now()));
    handoffWaiters.set(operation, (handoff) => {
      clearTimeout(timer);
      resolve(handoff);
    });
  });
}

function startControlServer() {
  const host = required('G008_TRANSACTION_CONTROL_HOST');
  const port = positivePort('G008_TRANSACTION_CONTROL_PORT');
  if (host !== '172.32.0.2') fail();
  const server = net.createServer({allowHalfOpen: true}, (socket) => {
    if (socket.remoteAddress !== '172.32.0.3' &&
        socket.remoteAddress !== '::ffff:172.32.0.3') {
      socket.destroy();
      return;
    }
    socket.setTimeout(5000, () => socket.destroy());
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > 32768) socket.destroy();
    });
    socket.on('end', () => {
      socket.setTimeout(0);
      try {
        const raw = buffer.toString('utf8');
        if (!raw.endsWith('\n') || raw.indexOf('\n') !== raw.length - 1) fail();
        const request = JSON.parse(raw.slice(0, -1));
        if (canonical(request) !== raw.slice(0, -1)) fail();
        exactObject(request, {
          schema_version: CONTROL_SCHEMA,
          action: 'consume',
          proof: undefined,
        });
        exactObject(
          request.proof,
          Object.fromEntries(HANDOFF_KEYS.map((key) => [key, undefined])),
        );
        if (!request.proof || typeof request.proof !== 'object') fail();
        const operation = request.proof.operation_kind;
        if (operation !== expectedOperation || consumedHandoffs.has(operation)) fail();
        consumedHandoffs.add(operation);
        expectedOperation = operation === 'register' ? 'unregister' : null;
        deliverHandoff(operation, {
          proof: request.proof,
          respond(receipt) {
            socket.end(canonical(receipt) + '\n');
          },
        });
      } catch (_) {
        socket.destroy();
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      resolve(server);
    });
  });
}

function verifyHandoff(proof, operation) {
  if (proof.schema_version !== HANDOFF_SCHEMA ||
      proof.operation_kind !== operation || proof.stage !== operation ||
      proof.ordinal !== (operation === 'register' ? 1 : 4) ||
      !Number.isSafeInteger(proof.organization_id) || proof.organization_id < 1 ||
      !Number.isSafeInteger(proof.registration_gate_id) ||
      proof.registration_gate_id < 1 ||
      !UUID.test(proof.execution_seal_uuid) || !UUID.test(proof.operation_uuid) ||
      !DIGEST.test(proof.execution_nonce_digest) ||
      !DIGEST.test(proof.candidate_digest) ||
      !DIGEST.test(proof.gate_envelope_digest) ||
      !DIGEST.test(proof.request_digest) ||
      typeof proof.opaque_authorization !== 'string' ||
      !proof.opaque_authorization || proof.opaque_authorization.includes('\n')) fail();
  const linked = Number.isSafeInteger(proof.prior_register_gate_id) &&
    proof.prior_register_gate_id > 0 &&
    typeof proof.prior_register_operation_uuid === 'string' &&
    UUID.test(proof.prior_register_operation_uuid);
  if ((operation === 'unregister') !== linked ||
      (operation === 'register' &&
       (proof.prior_register_gate_id !== null ||
        proof.prior_register_operation_uuid !== null))) fail();
  process.env.RECOVA_ONE_SHOT_OPERATION_KIND = operation;
  process.env.RECOVA_ONE_SHOT_ORGANIZATION_ID = String(proof.organization_id);
  process.env.RECOVA_ONE_SHOT_REGISTRATION_GATE_ID =
    String(proof.registration_gate_id);
  process.env.RECOVA_ONE_SHOT_OPERATION_UUID = proof.operation_uuid;
  process.env.RECOVA_ONE_SHOT_REQUEST_DIGEST = proof.request_digest;
  process.env.RECOVA_ONE_SHOT_CANDIDATE_DIGEST = proof.candidate_digest;
  process.env.RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST =
    proof.gate_envelope_digest;
  process.env.RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST =
    proof.execution_nonce_digest;
  process.env.RECOVA_ONE_SHOT_PRIOR_REGISTER_GATE_ID =
    proof.prior_register_gate_id === null ? '' : String(proof.prior_register_gate_id);
  process.env.RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID =
    proof.prior_register_operation_uuid === null ?
      '' : proof.prior_register_operation_uuid;

  const temporary = path.join(
    '/tmp', `.registration-proof-${process.pid}-${operation}`,
  );
  const descriptor = fs.openSync(
    temporary,
    fs.constants.O_WRONLY | fs.constants.O_CREAT |
      fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o400,
  );
  try {
    fs.writeFileSync(descriptor, proof.opaque_authorization);
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  try {
    process.env.G009_REGISTRATION_EGRESS_PROOF_PATH = temporary;
    const verified = verifyAuthorization();
    if (verified.authorization !== proof.opaque_authorization) fail();
    return verified;
  } finally {
    delete process.env.G009_REGISTRATION_EGRESS_PROOF_PATH;
    try { fs.unlinkSync(temporary); } catch (_) {}
  }
}

async function runTransaction(operation, tls, runtime) {
  const handoffDeadlineMs = Date.now() + 60000;
  const {proof, respond} = await awaitControlHandoff(operation, handoffDeadlineMs);
  const {authorization, claims, expiresAtMs} = verifyHandoff(proof, operation);
  const deadlineMs = Math.min(expiresAtMs, Date.now() + APP_DEADLINE_MS);
  if (deadlineMs <= Date.now()) fail();

  const consume = await postOnce(
    authorityUrl('/api/v1/internal/onnuri-smoke/registration/consume'),
    consumeBody(authorization, claims), tls, deadlineMs,
  );
  exactObject(consume, consumeBinding(claims));

  const startedAt = Date.now();
  const transactionDeadlineMs = deadlineMs - 5000;
  if (transactionDeadlineMs <= startedAt) fail();
  const observation = await startRegistrationProxy({
    claims,
    startedAt,
    deadlineMs: transactionDeadlineMs,
    endpointDigest: runtime.endpointDigest,
    upstreamIpv4: runtime.upstreamIpv4,
    upstreamPort: runtime.upstreamPort,
    ingressIpv4: runtime.ingressIpv4,
    ingressPort: runtime.ingressPort,
    providerIpv4: runtime.providerIpv4,
    onReady: () => fs.writeFileSync(
      readyPath(operation), 'operation-bound\n', {flag: 'wx', mode: 0o444},
    ),
  });
  const opaque = signExecutionAttestation(
    claims, observation, runtime.keyId, runtime.attestationKey,
  );
  const terminal = await postOnce(
    authorityUrl('/api/v1/internal/onnuri-smoke/registration/finalize'),
    {opaque_execution_attestation: opaque}, tls, deadlineMs,
  );
  exactObject(terminal, {
    registration_gate_id: claims.registration_gate_id,
    operation_uuid: claims.operation_uuid,
    operation_kind: claims.operation_kind,
    outcome: observation.outcome,
    recovered: undefined,
  });
  if (terminal.recovered !== false) fail();
  if (terminal.outcome !== 'succeeded') fail();
  respond({
    schema_version: CONTROL_RESPONSE_SCHEMA,
    status: 'finalized',
    operation_kind: claims.operation_kind,
    operation_uuid: claims.operation_uuid,
    candidate_digest: claims.candidate_digest,
    gate_envelope_digest: claims.gate_envelope_digest,
    execution_nonce_digest: claims.nonce_digest,
    outcome: terminal.outcome,
    registration_consumption: consume,
    opaque_execution_attestation: opaque,
    execution_attestation_sha256: sha256(Buffer.from(opaque)),
  });
  try { fs.unlinkSync(readyPath(operation)); } catch (_) {}
}


async function main({
  startControlServerFn = startControlServer,
  runTransactionFn = runTransaction,
} = {}) {
  let controlServer;
  try {
    rejectAmbientSecretEnvironment();
    for (const operation of ['register', 'unregister']) {
      try { fs.unlinkSync(readyPath(operation)); } catch (error) {
        if (error.code !== 'ENOENT') fail();
      }
    }
    const tls = {
      ca: readFileNoLink(required('RECOVA_F12_CA_CERTIFICATE_PATH')),
      cert: readFileNoLink(required('RECOVA_F12_CLIENT_CERTIFICATE_PATH')),
      key: readFileNoLink(required('RECOVA_F12_CLIENT_KEY_PATH')),
      credential: readSecret(required('RECOVA_F12_ENDPOINT_CREDENTIAL_PATH')),
      identity: required('RECOVA_F12_VERIFIED_IDENTITY'),
      issuer: required('RECOVA_F12_VERIFIED_ISSUER'),
    };
    const keyId = required('ONNURI_SMOKE_REGISTRATION_ATTESTATION_KEY_ID');
    if (!/^registration-attestation-[A-Za-z0-9._-]{1,96}$/.test(keyId)) fail();
    const attestationKey = loadPrivateKey(
      required('ONNURI_SMOKE_REGISTRATION_ATTESTATION_PRIVATE_KEY_FILE'),
    );
    const upstreamIpv4 = required('G009_REGISTRATION_SUPPLIER_IPV4');
    const ingressIpv4 = required('G009_REGISTRATION_AUTHORITY_INGRESS_IPV4');
    const providerIpv4 = required('G009_REGISTRATION_PROVIDER_IPV4');
    if (net.isIP(upstreamIpv4) !== 4 || net.isIP(ingressIpv4) !== 4 ||
        net.isIP(providerIpv4) !== 4) fail();
    const upstreamPort = positivePort('G009_REGISTRATION_SUPPLIER_PORT');
    const ingressPort = positivePort('G009_REGISTRATION_AUTHORITY_INGRESS_PORT');
    if (required('G009_REGISTRATION_SUPPLIER_TRANSPORT') !== 'udp') fail();
    const endpointDigest = sha256(Buffer.from(canonical({
      ipv4: upstreamIpv4,
      port: upstreamPort,
      transport: 'udp',
    })));
    if (endpointDigest !== required(
      'ONNURI_SMOKE_REGISTRATION_UPSTREAM_ENDPOINT_SHA256',
    )) fail();
    const runtime = {
      keyId, attestationKey, upstreamIpv4, ingressIpv4, providerIpv4,
      upstreamPort, ingressPort, endpointDigest,
    };
    controlServer = await startControlServerFn();
    await runTransactionFn('register', tls, runtime);
    await runTransactionFn('unregister', tls, runtime);
    process.exitCode = 0;
  } catch (_) {
    process.exitCode = 64;
  } finally {
    if (controlServer) controlServer.close();
    for (const operation of ['register', 'unregister']) {
      try { fs.unlinkSync(readyPath(operation)); } catch (_) {}
    }
  }
}

if (require.main === module) main();
module.exports = {
  awaitControlHandoff, consumeBinding, consumeBody, exactObject, main, readyPath,
  startControlServer, verifyHandoff,
};
