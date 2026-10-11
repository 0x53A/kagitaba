import {getDomain} from 'tldts';
import {decode} from './encoding.mjs';

export function originForSender(sender) {
  if (!Number.isInteger(sender?.tab?.id) || sender.frameId !== 0 || !sender.url) throw new Error('Only top-level website requests are supported');
  const url = new URL(sender.url);
  if (url.protocol !== 'https:' || url.username || url.password) throw new Error('A secure website is required');
  return url.origin;
}

export function validateRequest(kind, input, sender) {
  const origin = originForSender(sender);
  if (!input || !['create', 'get'].includes(kind)) throw new Error('Invalid request');
  const host = new URL(origin).hostname;
  const rpId = kind === 'create' ? (input.rp?.id ?? host) : (input.rpId ?? host);
  if (typeof rpId !== 'string' || rpId !== rpId.toLowerCase() || rpId.endsWith('.') || !getDomain(rpId, {allowPrivateDomains: true}) || !(host === rpId || host.endsWith(`.${rpId}`))) throw new Error('Invalid relying party');
  const challenge = decode(input.challenge);
  if (challenge.length < 16 || challenge.length > 1024) throw new Error('Unsupported challenge');
  const list = kind === 'create' ? input.excludeCredentials : input.allowCredentials;
  if (list !== undefined && (!Array.isArray(list) || list.length > 128 || list.some(c => c.type !== 'public-key' || decode(c.id).length < 1 || decode(c.id).length > 1024))) throw new Error('Invalid credential list');
  const uv = kind === 'create' ? input.authenticatorSelection?.userVerification : input.userVerification;
  if (uv !== undefined && !['required', 'preferred', 'discouraged'].includes(uv)) throw new Error('Invalid verification policy');
  if (kind === 'create') {
    if (!input.pubKeyCredParams?.some(p => p.type === 'public-key' && p.alg === -7)) throw new Error('Only ES256 passkeys are supported');
    if (!input.user || decode(input.user.id).length < 1 || decode(input.user.id).length > 64 || typeof input.user.name !== 'string' || input.user.name.length > 256) throw new Error('Invalid account');
    if(typeof input.user.displayName !== 'string' || input.user.displayName.length > 256 || typeof input.rp?.name !== 'string' || input.rp.name.length > 256)throw new Error('Invalid display names');
    if (input.authenticatorSelection?.authenticatorAttachment === 'platform' || input.attestation === 'enterprise') throw new Error('Requested authenticator is unsupported');
  }
  const extensions = input.extensions ?? {};
  if (Object.keys(extensions).some(key => !['credProps'].includes(key))) throw new Error('Requested WebAuthn extension is unsupported');
  return {kind, input, origin, rpId, uv: uv ?? 'preferred', timeout: Math.min(Math.max(Number(input.timeout) || 60000, 1000), 120000)};
}

export function matchesOrigin(payload, origin) {
  const urls = payload?.entity?.scope?.urls;
  if (!Array.isArray(urls)) return false;
  return urls.some(value => {
    try { return new URL(value).origin === origin && new URL(value).protocol === 'https:'; } catch { return false; }
  });
}

export class Epoch {
  value = 0;
  invalidate() { this.value++; }
  capture() { return this.value; }
  check(value) { if (value !== this.value) throw new Error('Operation cancelled by locking or navigation'); }
}
