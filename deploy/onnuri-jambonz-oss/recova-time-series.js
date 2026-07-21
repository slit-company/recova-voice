'use strict';

if (process.env.RECOVA_EPHEMERAL_NO_STORAGE !== '1') {
  module.exports = require('@jambonz/time-series');
} else {
  const noop = async() => {};
  const empty = async() => [];
  const AlertType = Object.freeze({
    WEBHOOK_STATUS_FAILURE: 'webhook-failure',
    WEBHOOK_CONNECTION_FAILURE: 'webhook-connection-failure',
    WEBHOOK_URL_NOTFOUND: 'webhook-url-notfound',
    WEBHOOK_AUTH_FAILURE: 'webhook-auth-failure',
    INVALID_APP_PAYLOAD: 'invalid-app-payload',
    TTS_NOT_PROVISIONED: 'no-tts',
    STT_NOT_PROVISIONED: 'no-stt',
    TTS_FAILURE: 'tts-failure',
    STT_FAILURE: 'stt-failure',
    CARRIER_NOT_PROVISIONED: 'no-carrier',
    ACCOUNT_CALL_LIMIT: 'account-call-limit',
    ACCOUNT_DEVICE_LIMIT: 'account-device-limit',
    ACCOUNT_API_LIMIT: 'account-api-limit',
    SP_CALL_LIMIT: 'service-provider-call-limit',
    SP_DEVICE_LIMIT: 'service-provider-device-limit',
    SP_API_LIMIT: 'service-provider-api-limit',
    ACCOUNT_INACTIVE: 'account is inactive or suspended',
    PLAY_FILENOTFOUND: 'play-url-notfound',
    TTS_STREAMING_CONNECTION_FAILURE: 'tts-streaming-connection-failure',
    APPLICATION: 'alert-from-application'
  });
  module.exports = () => ({
    writeCallCount: noop,
    writeCallCountSP: noop,
    writeCallCountApp: noop,
    queryCdrs: empty,
    writeCdrs: noop,
    writeAlerts: noop,
    writeSystemAlerts: noop,
    AlertType
  });
}
