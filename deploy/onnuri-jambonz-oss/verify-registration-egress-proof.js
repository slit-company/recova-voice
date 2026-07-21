'use strict';

const crypto = require('crypto');
const fs = require('fs');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const DOMAIN = 'recova.onnuri.smoke.registration.v1';
const MAX_LIFETIME_SECONDS = 60;
const MAX_CLOCK_SKEW_SECONDS = 5;
const CLAIM_KEYS = [
  'candidate_digest', 'concurrency_count', 'envelope_digest', 'expires_at',
  'gate_envelope_digest', 'issued_at', 'max_elapsed_seconds', 'nonce_digest',
  'operation_kind', 'operation_uuid', 'organization_id', 'prior_register_gate_id',
  'prior_register_operation_uuid', 'registration_gate_id', 'request_digest',
  'retry_count', 'transaction_count', 'verification_domain',
];

function fail() {
  const error = new Error('registration_authority_rejected');
  error.code = 'REGISTRATION_AUTHORITY_REJECTED';
  throw error;
}

function required(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) fail();
  return value;
}

function canonicalDecode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) fail();
  const text = decoded.toString('utf8');
  const parsed = JSON.parse(text);
  if (JSON.stringify(parsed) !== text) fail();
  return parsed;
}

function exactInteger(name, value, minimum = 1) {
  const expected = required(name);
  if (!/^[1-9][0-9]*$/.test(expected) || !Number.isSafeInteger(value) || value < minimum) fail();
  if (String(value) !== expected) fail();
}

function exactClaim(claims, key, environment) {
  const expected = required(environment);
  if (claims[key] !== expected) fail();
}

function parseDbTime(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value)) fail();
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) fail();
  return milliseconds;
}

function verifyAuthorization() {
  try {
    const proofPath = required('G009_REGISTRATION_EGRESS_PROOF_PATH');
    const publicKeyPath = required('G009_DISPATCH_PUBLIC_KEY_PATH');
    const raw = fs.readFileSync(proofPath, 'utf8');
    const authorization = raw.endsWith('\n') ? raw.slice(0, -1) : raw;
    if (!authorization || authorization.includes('\n') || authorization.trim() !== authorization) fail();
    const envelope = canonicalDecode(authorization);
    if (
      !envelope || typeof envelope !== 'object' || Array.isArray(envelope) ||
      Object.keys(envelope).join(',') !== 'algorithm,claims,key_id,signature,verification_domain' ||
      envelope.algorithm !== 'ES256' || envelope.verification_domain !== DOMAIN ||
      typeof envelope.signature !== 'string' ||
      !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature) ||
      typeof envelope.key_id !== 'string' ||
      !/^[A-Za-z0-9._-]{1,64}$/.test(envelope.key_id) ||
      envelope.key_id !== required('G009_DISPATCH_KEY_ID')
    ) fail();
    const claims = envelope.claims;
    if (
      !claims || typeof claims !== 'object' || Array.isArray(claims) ||
      Object.keys(claims).join(',') !== CLAIM_KEYS.join(',') ||
      claims.verification_domain !== DOMAIN || claims.envelope_digest !== claims.gate_envelope_digest ||
      claims.transaction_count !== 1 || claims.retry_count !== 0 ||
      claims.concurrency_count !== 1 || claims.max_elapsed_seconds !== MAX_LIFETIME_SECONDS ||
      !UUID.test(claims.operation_uuid) || !DIGEST.test(claims.request_digest) ||
      !DIGEST.test(claims.candidate_digest) || !DIGEST.test(claims.gate_envelope_digest) ||
      !DIGEST.test(claims.nonce_digest) || !Number.isSafeInteger(claims.organization_id) ||
      claims.organization_id < 1 || !Number.isSafeInteger(claims.registration_gate_id) ||
      claims.registration_gate_id < 1 || !['register', 'unregister'].includes(claims.operation_kind)
    ) fail();
    exactInteger('RECOVA_ONE_SHOT_ORGANIZATION_ID', claims.organization_id);
    exactInteger('RECOVA_ONE_SHOT_REGISTRATION_GATE_ID', claims.registration_gate_id);
    exactClaim(claims, 'operation_uuid', 'RECOVA_ONE_SHOT_OPERATION_UUID');
    exactClaim(claims, 'operation_kind', 'RECOVA_ONE_SHOT_OPERATION_KIND');
    exactClaim(claims, 'request_digest', 'RECOVA_ONE_SHOT_REQUEST_DIGEST');
    exactClaim(claims, 'candidate_digest', 'RECOVA_ONE_SHOT_CANDIDATE_DIGEST');
    exactClaim(claims, 'gate_envelope_digest', 'RECOVA_ONE_SHOT_GATE_ENVELOPE_DIGEST');
    exactClaim(claims, 'nonce_digest', 'RECOVA_ONE_SHOT_AUTHORIZATION_NONCE_DIGEST');
    if (claims.operation_kind === 'register') {
      if (claims.prior_register_gate_id !== null || claims.prior_register_operation_uuid !== null) fail();
      if (
        (process.env.RECOVA_ONE_SHOT_PRIOR_REGISTER_GATE_ID || '') !== '' ||
        (process.env.RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID || '') !== ''
      ) fail();
    } else {
      if (
        !Number.isSafeInteger(claims.prior_register_gate_id) || claims.prior_register_gate_id < 1 ||
        typeof claims.prior_register_operation_uuid !== 'string' ||
        !UUID.test(claims.prior_register_operation_uuid)
      ) fail();
      exactInteger('RECOVA_ONE_SHOT_PRIOR_REGISTER_GATE_ID', claims.prior_register_gate_id);
      exactClaim(
        claims, 'prior_register_operation_uuid',
        'RECOVA_ONE_SHOT_PRIOR_REGISTER_OPERATION_UUID',
      );
    }
    const issuedAtMs = parseDbTime(claims.issued_at);
    const expiresAtMs = parseDbTime(claims.expires_at);
    const now = Date.now();
    if (
      issuedAtMs > now + MAX_CLOCK_SKEW_SECONDS * 1000 || expiresAtMs <= now ||
      expiresAtMs <= issuedAtMs ||
      expiresAtMs - issuedAtMs > MAX_LIFETIME_SECONDS * 1000 ||
      expiresAtMs - now > MAX_LIFETIME_SECONDS * 1000 ||
      now - issuedAtMs > MAX_LIFETIME_SECONDS * 1000
    ) fail();
    const unsigned = {
      algorithm: envelope.algorithm,
      claims,
      key_id: envelope.key_id,
      verification_domain: envelope.verification_domain,
    };
    const signature = Buffer.from(envelope.signature, 'base64url');
    if (signature.length !== 64 || signature.toString('base64url') !== envelope.signature) fail();
    const valid = crypto.verify(
      'sha256', Buffer.from(JSON.stringify(unsigned)),
      {key: fs.readFileSync(publicKeyPath), dsaEncoding: 'ieee-p1363'}, signature,
    );
    if (!valid) fail();
    return {authorization, claims, expiresAtMs};
  } catch (error) {
    if (error && error.code === 'REGISTRATION_AUTHORITY_REJECTED') throw error;
    fail();
  }
}

if (require.main === module) {
  try {
    verifyAuthorization();
  } catch (_) {
    process.exitCode = 64;
  }
}

module.exports = {verifyAuthorization, fail};
