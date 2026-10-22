// This runs in the page's world. It has no authority and sees no wallet secrets.
import {encode, decode} from './encoding.mjs';
const native = {create: navigator.credentials.create.bind(navigator.credentials), get: navigator.credentials.get.bind(navigator.credentials)};
const pending = new Map();
function pack(input) {
  const pk = input.publicKey;
  return {...pk, challenge: encode(pk.challenge),
    ...(pk.user ? {user: {...pk.user, id: encode(pk.user.id)}} : {}),
    ...(pk.allowCredentials ? {allowCredentials: pk.allowCredentials.map(v => ({...v, id: encode(v.id)}))} : {}),
    ...(pk.excludeCredentials ? {excludeCredentials: pk.excludeCredentials.map(v => ({...v, id: encode(v.id)}))} : {})};
}
function unpack(value) {
  const response = {};
  for (const key of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
    if (key in value.response) response[key] = value.response[key] === null ? null : decode(value.response[key]).buffer;
  }
  if (value.response.attestationObject) {
    response.getTransports = () => ['internal'];
    response.getPublicKeyAlgorithm = () => -7;
    response.getPublicKey = () => decode(value.response.publicKey).buffer;
    response.getAuthenticatorData = () => decode(value.response.authenticatorData).buffer;
    Object.setPrototypeOf(response, AuthenticatorAttestationResponse.prototype);
  } else Object.setPrototypeOf(response, AuthenticatorAssertionResponse.prototype);
  const credential = {id: value.id, rawId: decode(value.id).buffer, type: 'public-key', authenticatorAttachment: 'cross-platform', response,
    getClientExtensionResults: () => value.extensions ?? {}, toJSON: () => ({id:value.id,rawId:value.id,type:'public-key',authenticatorAttachment:'cross-platform',response:{...value.response,...(value.response.attestationObject?{transports:['internal'],publicKeyAlgorithm:-7}:{})},clientExtensionResults:value.extensions??{}})};
  Object.setPrototypeOf(credential, PublicKeyCredential.prototype);
  return credential;
}
window.addEventListener('message', event => {
  if (event.source !== window || event.origin !== location.origin || event.data?.channel !== 'kagitaba-response') return;
  const callback = pending.get(event.data.id);
  if (callback) callback(event.data);
});
for (const kind of ['create', 'get']) {
  navigator.credentials[kind] = function(options) {
    if (!options?.publicKey || window !== window.top || options.mediation === 'conditional') return native[kind](options);
    if (options.signal?.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const clean = () => {pending.delete(id); clearTimeout(timer); options.signal?.removeEventListener('abort', abort);};
      const abort = () => {clean(); window.postMessage({channel: 'kagitaba-cancel', id}, location.origin); reject(new DOMException('Aborted', 'AbortError'));};
      const timer = setTimeout(abort, Math.min(Math.max(Number(options.publicKey.timeout) || 60000, 1000), 120000) + 1000);
      options.signal?.addEventListener('abort', abort, {once: true});
      pending.set(id, async value => {
        clean();
        try {
          // Adopt Firefox's promise directly, preserving its AbortError and other
          // native errors instead of converting them to our NotAllowedError.
          if (value.fallback) resolve(native[kind](options));
          else if (value.error) reject(new DOMException(value.error, 'NotAllowedError'));
          else resolve(unpack(value.credential));
        } catch { reject(new DOMException('Credential request failed', 'NotAllowedError')); }
      });
      try { window.postMessage({channel: 'kagitaba-request', id, kind, input: pack(options)}, location.origin); }
      catch { clean(); reject(new DOMException('Invalid credential request', 'TypeError')); }
    });
  };
}
