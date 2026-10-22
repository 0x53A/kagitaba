import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import git from 'isomorphic-git';
import { GitReplica, b64, unb64 } from '../src/git.mjs';
import {mergeFiles, mergeBase} from '../src/merge-policy.mjs';
import 'fake-indexeddb/auto';
import LightningFS from '@isomorphic-git/lightning-fs';

test('metadata merges retain clean revisions, combine additive grants and reject real edits', () => {
  const participant='a'.repeat(64), id='b'.repeat(32), pointer=`participants/${participant}/meta.entry`;
  const primary=`entries/${id}/primary`, own=`entries/${id}/grants/${participant}`, added=`entries/${id}/grants/${'c'.repeat(64)}`, other=`entries/${id}/grants/${'d'.repeat(64)}`;
  const base={[pointer]:b64(Buffer.from(`${id}\n`)),[primary]:'base',[own]:'grant'};
  const left={...base,[added]:'new grant'}, right={...base,[other]:'other grant'};
  assert.deepEqual({...mergeFiles(base,left,right)},{...left,...right});
  const edited={...base,[primary]:'new revision',[own]:'new matching grant'};
  assert.deepEqual({...mergeFiles(base,left,edited)},edited);
  assert.deepEqual({...mergeFiles(base,edited,left)},edited);
  assert.throws(()=>mergeFiles(base,edited,{...base,[primary]:'competing revision',[own]:'competing grant'}),/Conflicting/);
  assert.deepEqual({...mergeFiles(base,left,{...base,[added]:'different grant'})},base);
  assert.throws(()=>mergeFiles(base,{},edited),/Conflicting/);
});
// Use the IndexedDB mutex in Node: LightningFS's Web Locks backend leaves an
// uncancelled ten-minute timer after acquiring a contended lock (upstream).
Object.defineProperty(globalThis, 'navigator', {value: {}, configurable: true});

// Deterministic boundary double. Actual SSHSIG interoperability is covered by
// Rust/native tests; these tests exercise transport, ancestry and persistence.
const crypto = async (op, a) => {
  if (op === 'hash') return { hex: createHash(a.algorithm).update(unb64(a.data)).digest('hex') };
  if (op === 'validate_snapshot') return { signers: ['ROOT'] };
  const signature = `TEST-${createHash('sha256').update(unb64(a.message)).digest('hex')}\n`;
  if (op === 'ssh_sign') return { signature };
  if (op === 'ssh_verify' && a.publicKey === 'ROOT' && a.signature === signature) return { valid: true };
  throw Error('Invalid signature');
};
async function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kagitaba-browser-git-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // Redirect only this replica's absolute paths into its disposable test root.
  const promises = {};
  for (const name of ['mkdir','readFile','writeFile','stat','lstat','readdir','unlink','rmdir','readlink']) promises[name] = (p, ...args) => fs.promises[name](dir + p, ...args);
  promises.rename = (a,b) => fs.promises.rename(dir+a,dir+b);
  promises.symlink = (target,p) => fs.promises.symlink(target,dir+p);
  const replica = new GitReplica({ crypto, fs: { promises } }); await replica.init();
  const blob = await git.writeBlob({ ...replica.opts, blob: new TextEncoder().encode('1\n') });
  const tree = await git.writeTree({ ...replica.opts, tree: [{ mode:'100644',path:'kagitaba-format',oid:blob,type:'blob' }] });
  const actor = 'Test <test@localhost> 1 +0000';
  const unsigned = `tree ${tree}\nauthor ${actor}\ncommitter ${actor}\n\nCreate\n`;
  const { signature } = await crypto('ssh_sign', { message:b64(new TextEncoder().encode(unsigned)) });
  const signed = unsigned.replace('\n\n', '\ngpgsig '+signature.trimEnd()+'\n\n');
  const head = await git.writeObject({...replica.opts,type:'commit',format:'content',object:new TextEncoder().encode(signed)});
  await replica.accept(head,'ROOT'); return replica;
}
test('signed replica survives restart, exports complete graph and rejects rollback', async t => {
  const r = await fixture(t), initial = await r.exportTransfer();
  const files = await r.snapshot();
  await r.commit(files, {}, 'Update');
  assert.notEqual(r.state.head, initial.head);
  await assert.rejects(r.importTransfer(initial), /Rollback/);
  const reopened = new GitReplica({ crypto, fs:r.fs }); await reopened.init();
  assert.equal(reopened.state.head,r.state.head);
  assert.deepEqual(await reopened.snapshot(),files);
  const exported = await reopened.exportTransfer();
  assert.equal(exported.objects.filter(x=>x.type==='commit').length,2);
});
test('URL-only connection bootstraps a verified root and pins subsequent history', async t => {
  const r = await fixture(t), genesis = r.state.head;
  await r.commit(await r.snapshot(), {}, 'Enrol browser');
  const head = r.state.head;
  r.state = {};
  r.fetch = async () => head;
  await r.connect({url:'https://example.test/wallet.git',username:'test',password:'secret'});
  assert.equal(r.state.root, 'ROOT');
  assert.equal(r.state.head, head);
  assert.equal(r.state.remote, 'https://example.test/wallet.git');
  assert.ok(!JSON.stringify(r.state).includes('secret'));
  await assert.rejects(r.accept(genesis,r.state.root,r.state.head), /Rollback/);
  assert.equal(r.state.head,head);
});
test('connect persists a complete state once and never reads again after acceptance',async t=>{
  const replica=await fixture(t),head=replica.state.head;replica.state={};replica.fetch=async()=>head;
  let writes=0;const persist=replica.persist.bind(replica);replica.persist=async next=>{writes++;assert.equal(next.head,head);assert.equal(next.remote,'https://example.test/wallet.git');assert.equal(next.synced,head);assert.ok(next.syncedAt);await persist(next);};
  replica.snapshot=async()=>{throw Error('A post-acceptance reread would falsely fail');};
  const files=await replica.connect({url:'https://example.test/wallet.git'});
  assert.ok(files['kagitaba-format']);assert.equal(writes,1);
});
test('up-to-date synchronization returns a durable explicit outcome',async t=>{
  const replica=await fixture(t);await replica.setRemote('https://example.test/wallet.git');replica.fetch=async()=>replica.state.head;
  const result=await replica.sync();assert.equal(result.outcome,'up-to-date');assert.ok(result.syncedAt);assert.equal(replica.state.lastSync.outcome,'up-to-date');
});
test('transfer tampering and independently pinned wrong root fail closed', async t => {
  const r = await fixture(t), bundle = await r.exportTransfer();
  await assert.rejects(r.verify(r.state.head,'ATTACKER'), /Unauthorized/);
  bundle.objects[0].data = b64(new TextEncoder().encode('altered'));
  await assert.rejects(r.importTransfer(bundle), /digest mismatch/);
  await assert.rejects(r.connect({url:'http://example.test/repo',root:'ROOT'}));
  assert.throws(()=>r.remote('https://secret@example.test/repo'), /without credentials/);
});
test('a lock guard is checked immediately before signing a pending write',async t=>{
  const replica=await fixture(t),before=replica.state.head,files=await replica.snapshot();let signatures=0;
  const original=replica.crypto;replica.crypto=async(op,args)=>{if(op==='ssh_sign')signatures++;return original(op,args);};
  await assert.rejects(replica.commit(files,()=>{throw Error('locked');},'Pending edit'),/locked/);
  assert.equal(signatures,0);assert.equal(replica.state.head,before);
});

test('IndexedDB flush persists accepted state and objects across filesystem instances', async t => {
  const source = await fixture(t), bundle = await source.exportTransfer();
  const name = `kagitaba-test-${Date.now()}-${Math.random()}`;
  const first = new GitReplica({crypto,fs:new LightningFS(name)}); await first.init();
  await first.importTransfer(bundle,{root:'ROOT'});
  await first.setRemote('https://example.test/wallet.git');
  // Wait for the first filesystem's lock to be released, as on background idle.
  await new Promise(resolve => setTimeout(resolve,600));
  const reopened = new GitReplica({crypto,fs:new LightningFS(name)}); await reopened.init();
  assert.equal(reopened.state.head,bundle.head);
  assert.equal(reopened.state.remote,'https://example.test/wallet.git');
  assert.deepEqual(await reopened.snapshot(),await source.snapshot());
});

test('sync refuses divergent remote history without discarding local edits', async t => {
  const local = await fixture(t), peer = await fixture(t);
  // Both synthetic genesis commits have identical content and signatures.
  assert.equal(local.state.head,peer.state.head);
  await local.commit(await local.snapshot(),{},'Local edit');
  await peer.commit(await peer.snapshot(),{},'Concurrent remote edit');
  const accepted = local.state.head, incoming = await peer.exportTransfer();
  await assert.rejects(local.importTransfer(incoming), /divergent/);
  await local.setRemote('https://example.test/wallet.git');
  local.fetch = async () => incoming.head;
  await assert.rejects(local.sync(), /divergent/);
  assert.equal(local.state.head,accepted);
});

async function signedMerge(replica, parents, tree, message = 'Synthetic merge') {
  const actor = 'Test <test@localhost> 1 +0000';
  const unsigned = `tree ${tree}\n${parents.map(p => `parent ${p}\n`).join('')}author ${actor}\ncommitter ${actor}\n\n${message}\n`;
  const {signature} = await crypto('ssh_sign', {message:b64(new TextEncoder().encode(unsigned))});
  return git.writeObject({...replica.opts, type:'commit', format:'content', object:new TextEncoder().encode(unsigned.replace('\n\n', '\ngpgsig '+signature.trimEnd()+'\n\n'))});
}

test('cache conflicts are discarded independently of authoritative participants', () => {
  const base = {'kagitaba-format':'format','participants/p/pub.pem':'public','participants/p/index-key':'key','cache/p/index':'base'};
  const left = {...base,'cache/p/index':'left'};
  const right = {...base,'cache/p/index':'right'};
  const without = {...base}; delete without['cache/p/index'];
  assert.deepEqual({...mergeFiles(base,left,right)},without);
  assert.deepEqual({...mergeFiles(base,left,base)},left);
  assert.deepEqual({...mergeFiles(base,left,left)},left);
  assert.deepEqual({...mergeFiles(base,left,without)},without);
  assert.deepEqual({...mergeFiles(base,left,{'kagitaba-format':'format'})},{'kagitaba-format':'format'});
  assert.throws(()=>mergeFiles(base,{...base,'participants/p/index-key':'new'},{...base,'participants/p/sign.pem':'sign'}),/Conflicting/);
});

test('merge policy treats entries, grants and participant metadata atomically', () => {
  const base = {'kagitaba-format':'format', 'entries/a/primary':'one', 'entries/a/grants/key':'grant'};
  const left = {...base, 'entries/b/primary':'two'}, right = {...base, 'participants/p/pub.pem':'public', 'participants/p/sign.pem':'signing'};
  assert.deepEqual({...mergeFiles(base,left,right)}, {...left,...right});
  assert.throws(() => mergeFiles(base, {...base,'entries/a/primary':'two'}, {...base,'entries/a/grants/other':'new'}), /Conflicting/);
  assert.throws(() => mergeFiles(base, {'kagitaba-format':'format'}, {...base,'entries/a/primary':'two'}), /Conflicting/);
  assert.deepEqual({...mergeFiles(base,left,left)}, left);
  assert.deepEqual({...mergeFiles(base,{'kagitaba-format':'format'},base)}, {'kagitaba-format':'format'});
  const participant = {'participants/p/pub.pem':'public','participants/p/sign.pem':'one'};
  assert.throws(() => mergeFiles(participant, {...participant,'participants/p/sign.pem':'two'}, {...participant,'participants/p/device.json':'device'}), /Conflicting/);
});

test('signed two-parent graph preserves either checkpoint, export and root discovery', async t => {
  const r = await fixture(t), root = r.state.head, files = await r.snapshot();
  await r.commit(files, {}, 'Left'); const left = r.state.head;
  const tree = (await git.readCommit({...r.opts, oid:left})).commit.tree;
  const right = await signedMerge(r, [root], tree, 'Right');
  const merged = await signedMerge(r, [left,right], tree);
  await r.accept(merged, 'ROOT', left);
  await r.verify(merged, 'ROOT', right);
  assert.equal(await r.discoverRoot(merged), 'ROOT');
  assert.equal((await r.exportTransfer()).objects.filter(o => o.type === 'commit').length, 4);
  const reopened = new GitReplica({crypto,fs:r.fs}); await reopened.init();
  assert.equal(reopened.state.head, merged);
  await assert.rejects(r.accept(right, 'ROOT', merged), /Rollback/);
  for (const parents of [[left,left], [left,root], [left,right,root]]) {
    await assert.rejects(r.verify(await signedMerge(r,parents,tree), 'ROOT'), /Unsupported/);
  }
  const reverse = await signedMerge(r,[right,left],tree);
  const ambiguous = await signedMerge(r,[merged,reverse],tree);
  await assert.rejects(r.verify(ambiguous,'ROOT'), /Unsupported/);
  const graph = await r.history(ambiguous);
  assert.throws(() => mergeBase(graph, merged, reverse), /Unsupported/);
});

test('valid signature cannot authorize dropping an independent merge change', async t => {
  const r = await fixture(t), root = r.state.head, files = await r.snapshot();
  await r.commit({...files,'entries/a/primary':b64(new Uint8Array([1]))}, {}, 'Left');
  const left = r.state.head, leftTree = (await git.readCommit({...r.opts, oid:left})).commit.tree;
  // Construct a second signed branch without moving the accepted checkpoint.
  const blob = await git.writeBlob({...r.opts, blob:new Uint8Array([2])});
  const entryTree = await git.writeTree({...r.opts,tree:[{mode:'100644',path:'primary',oid:blob,type:'blob'}]});
  const entriesTree = await git.writeTree({...r.opts,tree:[{mode:'040000',path:'b',oid:entryTree,type:'tree'}]});
  const format = await git.writeBlob({...r.opts,blob:unb64(files['kagitaba-format'])});
  const rightTree = await git.writeTree({...r.opts,tree:[{mode:'100644',path:'kagitaba-format',oid:format,type:'blob'},{mode:'040000',path:'entries',oid:entriesTree,type:'tree'}]});
  const right = await signedMerge(r,[root],rightTree,'Right');
  await assert.rejects(r.accept(await signedMerge(r,[left,right],leftTree),'ROOT',left), /Conflicting/);
  assert.equal(r.state.head,left);
});

test('merge signer must be authorized by the second parent as well as the first', async t => {
  const r = await fixture(t), root = r.state.head, files = await r.snapshot();
  await r.commit(files, {}, 'Left still authorizes ROOT'); const left = r.state.head;
  const blob = await git.writeBlob({...r.opts,blob:new TextEncoder().encode('OTHER')});
  const keyTree = await git.writeTree({...r.opts,tree:[{mode:'100644',path:'sign.pem',oid:blob,type:'blob'}]});
  const peopleTree = await git.writeTree({...r.opts,tree:[{mode:'040000',path:'p',oid:keyTree,type:'tree'}]});
  const format = await git.writeBlob({...r.opts,blob:unb64(files['kagitaba-format'])});
  const tree = await git.writeTree({...r.opts,tree:[{mode:'100644',path:'kagitaba-format',oid:format,type:'blob'},{mode:'040000',path:'participants',oid:peopleTree,type:'tree'}]});
  const right = await signedMerge(r,[root],tree,'Remove ROOT on right');
  const original = r.crypto;
  r.crypto = (op,args) => op === 'validate_snapshot' ? Promise.resolve({signers:args.files['participants/p/sign.pem'] ? ['OTHER'] : ['ROOT']}) : original(op,args);
  // The right-hand removal was authorized by its own parent.
  await r.verify(right,'ROOT',root);
  await assert.rejects(r.accept(await signedMerge(r,[left,right],tree),'ROOT',left), /Unauthorized/);
  assert.equal(r.state.head,left);
});

test('attachment blobs belong to their owner entry atomic merge unit',()=>{
  const base={'kagitaba-format':'1','entries/a/primary':'old','entries/a/attachments/blob':'file'};
  const left={...base,'entries/a/primary':'new'};
  const right={...base,'entries/a/attachments/blob':'other'};
  assert.throws(()=>mergeFiles(base,left,right),/Conflicting/);
  assert.deepEqual({...mergeFiles(base,left,base)},left);
  assert.deepEqual({...mergeFiles(base,{'kagitaba-format':'1'},base)},{'kagitaba-format':'1'});
});
