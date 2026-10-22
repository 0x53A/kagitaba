import test from 'node:test';
import assert from 'node:assert/strict';
import {PasskeyRouter} from '../src/passkey-router.mjs';

function fixture(backends = ['native', 'browser']) {
  const requests = new Map(), shown = [], closed = [];
  let calls = 0, cancellations = 0, response, valid = true;
  const native = {cancelPage() {cancellations++;}, async passkey() {calls++; return response();}};
  const api = {tabs: {async sendMessage(id, message) {shown.push(message);}},
    runtime: {getURL: path => `moz-extension://test/${path}`},
    windows: {async create() {return {id: 42};}, async remove(id) {closed.push(id);}}};
  const router = new PasskeyRouter({api, native, requests, currentDocument: async () => {if (!valid) throw Error('changed');}});
  const request = {id: 'request', pageId: 'page', tabId: 7, documentToken: 'document', origin: 'https://example.com', kind: 'get', timeout: 60000};
  const sender = {frameId: 0, tab: {id: 7}, url: 'https://example.com/login'};
  const result = router.start(request, backends);
  const choose = (backend, override = {}, source = sender) => router.choose({requestId: request.id, documentToken: request.documentToken, backend, ...override}, source);
  return {router, requests, result, request, choose, shown, closed, sender,
    respond(fn) {response = fn;}, navigate() {valid = false;},
    get calls() {return calls;}, get cancellations() {return cancellations;}};
}

test('a passkey request shows choices without contacting native or opening approval', async () => {
  const f = fixture();
  assert.equal(f.calls, 0);
  assert.deepEqual(f.shown[0].backends, ['native', 'browser']);
  assert.equal(f.request.windowId, undefined);
  await f.choose('cancel');
  assert.deepEqual(await f.result, {error: 'Request cancelled'});
});

test('native failure stays pending for retry and a successful reply dismisses the chooser', async () => {
  const f = fixture();
  f.respond(() => {throw Error('private library details');});
  await f.choose('native');
  assert.equal(f.requests.size, 1);
  assert.equal(f.request.phase, 'choose');
  assert.match(f.shown.at(-1).error, /Open and unlock/);
  assert.equal(JSON.stringify(f.shown).includes('private library details'), false);
  f.respond(() => ({credential: {id: 'public'}}));
  await f.choose('native');
  assert.deepEqual(await f.result, {credential: {id: 'public'}});
  assert.equal(f.shown.at(-1).type, 'passkey-dismiss');
  assert.equal(f.requests.size, 0);
});

test('Firefox can take over after a failure or during an outstanding native request', async () => {
  const f = fixture();
  let reply;
  f.respond(() => new Promise(resolve => {reply = resolve;}));
  const choosing = f.choose('native');
  // Let context checking and chooser rendering complete.
  while (!reply) await Promise.resolve();
  await f.choose('native');
  assert.equal(f.calls, 1);
  await f.choose('firefox');
  assert.deepEqual(await f.result, {fallback: true});
  reply({credential: {id: 'late'}});
  await choosing;
  assert.equal(f.requests.size, 0);
  assert.equal(f.shown.at(-1).type, 'passkey-dismiss');
});

test('choices are bound to the requesting tab, origin, document and available backends', async () => {
  const f = fixture(['browser']);
  for (const sender of [{...f.sender, frameId: 1}, {...f.sender, tab: {id: 8}}, {...f.sender, url: 'https://evil.test'}])
    assert.equal(await f.choose('firefox', {}, sender), false);
  assert.equal(await f.choose('firefox', {documentToken: 'old'}), false);
  assert.equal(await f.choose('native'), false);
  assert.equal(await f.choose('invented'), false);
  assert.equal(f.requests.size, 1);
  await f.choose('browser');
  assert.equal(f.request.windowId, 42);
  await f.choose('firefox');
  await f.result;
  assert.deepEqual(f.closed, [42]);
});

test('navigation detected during choice cannot invoke a backend', async () => {
  const f = fixture();
  f.navigate();
  await assert.rejects(f.choose('native'));
  assert.equal(f.calls, 0);
  f.request.finish({error: 'Website navigated'});
  await f.result;
});

test('cancellation while rechecking context cannot open approval', async () => {
  const f = fixture();
  let release;
  f.router.currentDocument = () => new Promise(resolve => {release = resolve;});
  const choosing = f.choose('browser');
  f.request.finish({error: 'Request cancelled'});
  release();
  await choosing;
  await f.result;
  assert.equal(f.request.windowId, undefined);
});
