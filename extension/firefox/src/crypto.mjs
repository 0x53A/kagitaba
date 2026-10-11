import init, {command} from '../pkg/kagitaba_browser.js';
import {random} from './encoding.mjs';
let ready;
export async function cryptoCall(op, args = {}) {
  ready ??= init({module_or_path: browser.runtime.getURL('kagitaba_browser_bg.wasm')});
  await ready;
  const entropy = random(['identity_generate','identity_wrap','local_encrypt','entry_encrypt','metadata_encrypt','passkey_create'].includes(op) ? 65536 : 0);
  try { return JSON.parse(await command(JSON.stringify({op, ...args}), entropy)); }
  finally { entropy.fill(0); }
}
