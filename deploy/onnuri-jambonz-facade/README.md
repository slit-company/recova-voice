# Onnuri Jambonz facade

This image is an offline, disabled deployment foundation. It grants no SIP, RTP,
REGISTER, call, stock-management, cloud, or database authority. Phase A/B remain
Waiting/no-traffic.

## ASGI factory

The single deployment and programmatic factory is exactly:

```text
api.services.telephony.providers.jambonz.facade.app:create_facade_app
```

`FACADE_APP_FACTORY` must equal that value. `FACADE_ASGI_COMMAND_JSON` must be a
JSON argv array containing exactly one `{app_factory}` placeholder, and the ASGI
runtime must invoke it as a factory. For example, the shape is:

```text
["uvicorn", "{app_factory}", "--factory", "--host", "127.0.0.1"]
```

The entrypoint rejects shells, missing placeholders, and alternate factories.
It does not load credentials or select an adapter.

A zero-argument `create_facade_app()` invocation enters strict deployment
composition. No G-1 stock Jambonz candidate has been approved or pinned, so it
fails startup with `jambonz_stock_candidate_unavailable_g1_required` before
loading F12 configuration or constructing a network-active client. Do not
replace this with a guessed candidate API or fake success.

Tests may call the same factory with all five explicit dependencies: stock
client, F12 authority adapter, signature verifier, verification policy, and WSS
URL. Any partial dependency set fails with the non-sensitive reason
`facade_partial_dependency_injection_rejected`; dependencies are never ambiently
discovered.

## F12 boundary

`StrictF12Transport` is a lower-level primitive for a separately reviewed F12
authority adapter. It uses HTTPS with a caller-supplied mTLS certificate/key and
CA, a timeout of at most ten seconds, redirects and environment proxy trust
disabled, and transport retries set to zero. Its trusted-proxy authentication
set is exactly:

- `x-recova-verified-mtls-identity`
- `x-recova-verified-mtls-issuer`
- `x-recova-onnuri-endpoint-credential`

It never sends `Authorization`, `Cookie`, or `X-API-Key`. It requires the adapter
to provide a typed response model and rejects non-200 or invalid responses.
Endpoint credentials remain opaque and must not be printed, logged, included in
image configuration, or committed.

The F12 authority contract is being reconciled independently. This foundation
does not freeze caller-supplied authority outputs into transport models or guess
operation paths. Activation remains blocked until that strict adapter is landed
and reviewed while preserving backend-only persistence and tenant isolation.
