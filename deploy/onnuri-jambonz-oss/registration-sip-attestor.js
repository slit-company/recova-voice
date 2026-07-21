'use strict';

const crypto = require('crypto');
const dgram = require('dgram');

const DOMAIN = 'recova.onnuri.smoke.registration.execution.v1';
const SHA256 = /^[0-9a-f]{64}$/;
const TOKEN = /^[A-Za-z0-9.!%*_+`'~-]+$/;

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  throw new Error('noncanonical_value');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

function exactUtc(now) {
  return new Date(now).toISOString();
}

function parseSip(packet) {
  if (!Buffer.isBuffer(packet) || packet.length === 0 || packet.length > 65535 || packet.includes(0)) {
    throw new Error('invalid_packet');
  }
  const text = packet.toString('latin1');
  if (!text.endsWith('\r\n\r\n') || text.includes('\n\n') || text.includes('\r\r')) {
    throw new Error('invalid_framing');
  }
  const lines = text.slice(0, -4).split('\r\n');
  if (!lines[0] || lines.some((line) => line.length > 2048)) throw new Error('invalid_lines');
  const headers = new Map();
  for (const line of lines.slice(1)) {
    if (/^[ \t]/.test(line)) throw new Error('folded_header');
    const separator = line.indexOf(':');
    if (separator <= 0) throw new Error('invalid_header');
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!TOKEN.test(name) || !value || headers.has(name)) throw new Error('duplicate_header');
    headers.set(name, value);
  }
  const contentLength = headers.get('content-length') || headers.get('l');
  if (contentLength !== undefined && contentLength !== '0') throw new Error('body_refused');
  const response = /^SIP\/2\.0 ([1-6][0-9]{2}) ([^\r\n]+)$/.exec(lines[0]);
  const request = /^REGISTER (sip:[^ \r\n]+) SIP\/2\.0$/.exec(lines[0]);
  if (!response && !request) throw new Error('method_refused');
  return {
    kind: response ? 'response' : 'request',
    status: response ? Number(response[1]) : null,
    requestUri: request ? request[1] : null,
    headers,
  };
}

function uriFromHeader(value) {
  const match = /<([^>]+)>/.exec(value) || /^(sip:[^;\s]+)/.exec(value);
  if (!match || !match[1].startsWith('sip:')) throw new Error('invalid_uri');
  return match[1];
}

function branch(message) {
  const via = message.headers.get('via') || message.headers.get('v');
  const match = via && /(?:^|;)branch=(z9hG4bK[A-Za-z0-9.!%*_+`'~-]+)(?:;|$)/i.exec(via);
  if (!match) throw new Error('invalid_branch');
  return match[1];
}

function cseq(message) {
  const value = message.headers.get('cseq');
  const match = value && /^([1-9][0-9]{0,9}) REGISTER$/.exec(value);
  if (!match) throw new Error('invalid_cseq');
  return Number(match[1]);
}

function requestExpiry(message) {
  const contact = message.headers.get('contact') || message.headers.get('m');
  if (!contact || contact.includes(',')) throw new Error('ambiguous_contact');
  const parameter = /(?:^|;)expires=([0-9]+)(?:;|$)/i.exec(contact);
  const header = message.headers.get('expires');
  if (parameter && header !== undefined && Number(parameter[1]) !== Number(header)) {
    throw new Error('ambiguous_expiry');
  }
  const raw = parameter ? parameter[1] : header;
  if (raw === undefined || !/^[0-9]+$/.test(raw)) throw new Error('missing_expiry');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > 86400) throw new Error('invalid_expiry');
  return {contactUri: uriFromHeader(contact), value};
}

function acceptedExpiry(message, contactUri) {
  const contact = message.headers.get('contact') || message.headers.get('m');
  if (!contact || contact.includes(',') || uriFromHeader(contact) !== contactUri) {
    throw new Error('ambiguous_contact');
  }
  const parameter = /(?:^|;)expires=([0-9]+)(?:;|$)/i.exec(contact);
  const header = message.headers.get('expires');
  if (parameter && header !== undefined && Number(parameter[1]) !== Number(header)) {
    throw new Error('ambiguous_expiry');
  }
  const raw = parameter ? parameter[1] : header;
  if (raw === undefined || !/^[0-9]+$/.test(raw)) throw new Error('missing_expiry');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value > 86400) throw new Error('invalid_expiry');
  return value;
}

class RegistrationSipAttestor {
  constructor(options) {
    this.claims = options.claims;
    this.startedAt = options.startedAt;
    this.deadlineMs = options.deadlineMs;
    this.endpointDigest = options.endpointDigest;
    this.providerIpv4 = options.providerIpv4;
    this.sendUpstream = options.sendUpstream;
    this.sendProvider = options.sendProvider;
    this.onTerminal = options.onTerminal;
    this.now = options.now || Date.now;
    this.state = 'initial';
    this.providerPeer = null;
    this.initial = null;
    this.retry = null;
    this.challengeStatus = null;
    this.challengeDigest = null;
    this.finalDigest = null;
    this.responseCount = 0;
    this.closed = false;
  }

  observeProvider(packet, peer) {
    if (this.closed) return;
    try {
      if (!peer || peer.address !== this.providerIpv4 ||
          (this.providerPeer && (
            peer.address !== this.providerPeer.address || peer.port !== this.providerPeer.port
          ))) {
        throw new Error('provider_peer_refused');
      }
      if (this.now() >= this.deadlineMs || this.state === 'upstream' || this.state === 'final') {
        throw new Error('extra_request');
      }
      const message = parseSip(packet);
      if (message.kind !== 'request') throw new Error('internal_response_refused');
      const identity = {
        callId: message.headers.get('call-id') || message.headers.get('i'),
        aor: uriFromHeader(message.headers.get('to') || message.headers.get('t') || ''),
        from: uriFromHeader(message.headers.get('from') || message.headers.get('f') || ''),
        requestUri: message.requestUri,
        cseq: cseq(message),
        branch: branch(message),
        expiry: requestExpiry(message),
      };
      if (!identity.callId || identity.aor !== identity.from) throw new Error('identity_refused');
      if (this.claims.operation_kind === 'register' ? identity.expiry.value <= 0 : identity.expiry.value !== 0) {
        throw new Error('operation_expiry_refused');
      }
      if (this.state === 'initial') {
        this.providerPeer = peer;
        this.initial = {...identity, digest: sha256(packet)};
        this.state = 'upstream';
      } else if (this.state === 'authenticated') {
        const authorization = this.challengeStatus === 401 ? 'authorization' : 'proxy-authorization';
        if (!message.headers.has(authorization) || identity.callId !== this.initial.callId ||
            identity.aor !== this.initial.aor || identity.from !== this.initial.from ||
            identity.requestUri !== this.initial.requestUri ||
            identity.expiry.contactUri !== this.initial.expiry.contactUri ||
            identity.expiry.value !== this.initial.expiry.value ||
            identity.cseq !== this.initial.cseq + 1 || identity.branch === this.initial.branch) {
          throw new Error('followup_binding_refused');
        }
        this.retry = {...identity, digest: sha256(packet)};
        this.state = 'upstream';
      } else {
        throw new Error('extra_request');
      }
      this.sendUpstream(packet);
    } catch (_) {
      this.contain();
    }
  }

  observeSupplier(packet) {
    if (this.closed) return;
    try {
      if (this.now() >= this.deadlineMs || this.state !== 'upstream') throw new Error('unexpected_response');
      const message = parseSip(packet);
      if (message.kind !== 'response') throw new Error('upstream_request_refused');
      const active = this.retry || this.initial;
      if ((message.headers.get('call-id') || message.headers.get('i')) !== active.callId ||
          cseq(message) !== active.cseq || branch(message) !== active.branch) {
        throw new Error('response_binding_refused');
      }
      if (message.status < 200) throw new Error('provisional_refused');
      this.responseCount += 1;
      if (this.responseCount > 2) throw new Error('extra_response');
      if (message.status === 401 || message.status === 407) {
        const challengeName = message.status === 401 ? 'www-authenticate' : 'proxy-authenticate';
        const challenge = message.headers.get(challengeName);
        if (this.retry || this.challengeStatus !== null || !challenge || /(?:^|,)\s*stale\s*=\s*true\b/i.test(challenge)) {
          throw new Error('challenge_refused');
        }
        this.challengeStatus = message.status;
        this.challengeDigest = sha256(packet);
        this.state = 'authenticated';
        this.sendProvider(packet, this.providerPeer);
        return;
      }
      if (message.status >= 300 && message.status < 400) throw new Error('redirect_refused');
      this.finalDigest = sha256(packet);
      let accepted = null;
      let outcome = 'failed';
      let deregistered = false;
      if (message.status === 200) {
        accepted = acceptedExpiry(message, active.expiry.contactUri);
        if (this.claims.operation_kind === 'register') {
          if (accepted <= 0 || accepted > active.expiry.value) throw new Error('accepted_expiry_refused');
        } else {
          if (accepted !== 0) throw new Error('accepted_expiry_refused');
          deregistered = true;
        }
        outcome = 'succeeded';
      }
      this.sendProvider(packet, this.providerPeer);
      this.finish(outcome, message.status, accepted, deregistered);
    } catch (_) {
      this.contain();
    }
  }

  bindingDigest() {
    if (!this.initial) return null;
    const binding = {
      aor_digest: sha256(this.initial.aor),
      call_id_digest: sha256(this.initial.callId),
      initial_cseq: this.initial.cseq,
      initial_via_branch_digest: sha256(this.initial.branch),
      request_uri_digest: sha256(this.initial.requestUri),
      retry_cseq: this.retry ? this.retry.cseq : null,
      retry_via_branch_digest: this.retry ? sha256(this.retry.branch) : null,
    };
    return sha256(Buffer.from(canonical(binding)));
  }

  contain() {
    this.finish('contained', null, null, false);
  }

  finish(outcome, finalStatus, acceptedExpires, deregistered) {
    if (this.closed) return;
    this.closed = true;
    this.state = 'final';
    this.onTerminal({
      accepted_expires_seconds: acceptedExpires,
      challenge_response_wire_digest: this.challengeDigest,
      challenge_status: this.challengeStatus,
      completed_at: exactUtc(this.now()),
      deregistered,
      final_response_wire_digest: this.finalDigest,
      final_status: finalStatus,
      initial_request_wire_digest: this.initial ? this.initial.digest : null,
      outcome,
      response_count: this.responseCount,
      retry_request_wire_digest: this.retry ? this.retry.digest : null,
      sip_transaction_binding_digest: this.bindingDigest(),
      started_at: exactUtc(this.startedAt),
      upstream_endpoint_digest: this.endpointDigest,
      wire_request_count: (this.initial ? 1 : 0) + (this.retry ? 1 : 0),
    });
  }
}

function signExecutionAttestation(claims, observation, keyId, privateKey) {
  if (!SHA256.test(observation.upstream_endpoint_digest) || !keyId) throw new Error('invalid_attestation_input');
  const attestedClaims = {
    accepted_expires_seconds: observation.accepted_expires_seconds,
    authorization_nonce_digest: claims.nonce_digest,
    candidate_digest: claims.candidate_digest,
    challenge_response_wire_digest: observation.challenge_response_wire_digest,
    challenge_status: observation.challenge_status,
    completed_at: observation.completed_at,
    deregistered: observation.deregistered,
    final_response_wire_digest: observation.final_response_wire_digest,
    final_status: observation.final_status,
    gate_envelope_digest: claims.gate_envelope_digest,
    initial_request_wire_digest: observation.initial_request_wire_digest,
    operation_kind: claims.operation_kind,
    operation_uuid: claims.operation_uuid,
    organization_id: claims.organization_id,
    outcome: observation.outcome,
    prior_register_gate_id: claims.prior_register_gate_id,
    prior_register_operation_uuid: claims.prior_register_operation_uuid,
    registration_gate_id: claims.registration_gate_id,
    request_digest: claims.request_digest,
    response_count: observation.response_count,
    retry_count: 0,
    retry_request_wire_digest: observation.retry_request_wire_digest,
    sip_transaction_binding_digest: observation.sip_transaction_binding_digest,
    started_at: observation.started_at,
    transaction_count: 1,
    transport: 'udp',
    upstream_endpoint_digest: observation.upstream_endpoint_digest,
    verification_domain: DOMAIN,
    wire_request_count: observation.wire_request_count,
  };
  const unsigned = {algorithm: 'ES256', claims: attestedClaims, key_id: keyId, verification_domain: DOMAIN};
  const signature = crypto.sign('sha256', Buffer.from(canonical(unsigned)), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  if (signature.length !== 64) throw new Error('invalid_signature');
  return base64url(Buffer.from(canonical({...unsigned, signature: base64url(signature)})));
}

function startRegistrationProxy(options) {
  const upstream = dgram.createSocket('udp4');
  const ingress = dgram.createSocket('udp4');
  let timer;
  let settle;
  const terminal = new Promise((resolve) => { settle = resolve; });
  const safeClose = (socket) => {
    try { socket.close(); } catch (_) {}
  };
  const attestor = new RegistrationSipAttestor({
    ...options,
    sendUpstream: (packet) => upstream.send(packet),
    sendProvider: (packet, peer) => {
      if (peer) ingress.send(packet, peer.port, peer.address);
    },
    onTerminal: (observation) => {
      clearTimeout(timer);
      safeClose(ingress);
      safeClose(upstream);
      settle(observation);
    },
  });
  upstream.on('message', (packet) => attestor.observeSupplier(packet));
  upstream.on('error', () => attestor.contain());
  ingress.on('message', (packet, peer) => attestor.observeProvider(packet, peer));
  ingress.on('error', () => attestor.contain());
  upstream.connect(options.upstreamPort, options.upstreamIpv4, () => {
    ingress.bind(options.ingressPort, options.ingressIpv4, () => {
      try { options.onReady(); } catch (_) { attestor.contain(); }
    });
  });
  timer = setTimeout(() => attestor.contain(), Math.max(1, options.deadlineMs - Date.now()));
  return terminal;
}

module.exports = {
  DOMAIN,
  RegistrationSipAttestor,
  canonical,
  parseSip,
  sha256,
  signExecutionAttestation,
  startRegistrationProxy,
};
