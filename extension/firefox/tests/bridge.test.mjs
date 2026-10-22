import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {encode, decode} from '../src/encoding.mjs';

test('Firefox fallback receives original options and preserves cancellation errors', async () => {
  let receive, posted, forwarded;
  const origin = 'https://example.com';
  const window = {addEventListener(type, callback) {receive = callback;}, postMessage(value) {posted = value;}};
  window.top = window;
  const navigator = {credentials: {create() {}, get(options) {forwarded = options; return Promise.reject(new DOMException('Aborted', 'AbortError'));}}};
  const source = (await readFile(new URL('../src/bridge.mjs', import.meta.url), 'utf8')).replace("import {encode, decode} from './encoding.mjs';", '');
  vm.runInNewContext(source, {window, navigator, location: {origin}, crypto: {randomUUID: () => 'id'}, encode, decode, setTimeout, clearTimeout, DOMException});
  const options = {publicKey: {challenge: new Uint8Array(32)}, signal: new AbortController().signal};
  const result = navigator.credentials.get(options);
  receive({source: window, origin, data: {channel: 'kagitaba-response', id: posted.id, fallback: true}});
  await assert.rejects(result, {name: 'AbortError'});
  assert.equal(forwarded, options);
});
