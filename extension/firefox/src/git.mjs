import git from 'isomorphic-git';
import LightningFS from '@isomorphic-git/lightning-fs';
import http from 'isomorphic-git/http/web';
import {connectionStep} from './errors.mjs';
import {mergeBase, mergeFiles, equalFiles} from './merge-policy.mjs';

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: true });
export function b64(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, ''); }
export function unb64(s) { if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw Error('Invalid binary encoding'); return Uint8Array.from(atob(s.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)); }
const oidOK = s => typeof s === 'string' && /^[a-f0-9]{40}$/.test(s);
const MAX = 256 * 1024 * 1024;
function parseCommit(bytes) {
  if (bytes.length > 16384) throw Error('Oversized commit');
  const text = dec.decode(bytes), split = text.indexOf('\n\n');
  if (split < 0) throw Error('Invalid commit');
  const headers = text.slice(0, split).split('\n'), unsigned = [], parents = [];
  let signature, tree, last; const names = [];
  for (const line of headers) {
    if (line.startsWith(' ')) { if (last !== 'gpgsig') throw Error('Invalid header'); signature += '\n' + line.slice(1); continue; }
    const i = line.indexOf(' '), name = line.slice(0, i), value = line.slice(i + 1); last = name; names.push(name);
    if (name === 'gpgsig') { if (signature !== undefined) throw Error('Duplicate signature'); signature = value; }
    else {
      if (!['tree', 'parent', 'author', 'committer'].includes(name)) throw Error('Unsupported commit header');
      unsigned.push(line);
      if (name === 'tree') { if (tree || !oidOK(value)) throw Error('Invalid tree'); tree = value; }
      if (name === 'parent') { if (!oidOK(value)) throw Error('Invalid parent'); parents.push(value); }
    }
  }
  if (!tree || !signature || parents.length > 2 || new Set(parents).size !== parents.length || unsigned.filter(x => x.startsWith('author ')).length !== 1 || unsigned.filter(x => x.startsWith('committer ')).length !== 1) throw Error('Unsupported wallet history');
  const expected = ['tree', ...parents.map(() => 'parent'), 'author', 'committer', 'gpgsig'];
  if (names.join(',') !== expected.join(',')) throw Error('Noncanonical commit headers');
  return { tree, parents, signature: signature + '\n', unsigned: enc.encode(unsigned.join('\n') + text.slice(split)) };
}

/** Owns one encrypted replica. Calls must be serialized by the privileged caller. */
export class GitReplica {
  constructor({ crypto, fs, http: transport, progress = () => {} } = {}) { this.crypto = crypto; this.fs = fs || new LightningFS('kagitaba-git'); this.http = transport || http; this.progress=progress; this.dir = '/wallet'; this.state = {}; }
  get opts() { return { fs: this.fs, dir: this.dir }; }
  async init() {
    try { await this.fs.promises.mkdir(this.dir); } catch (e) { if (e.code !== 'EEXIST') throw e; }
    try { this.state = JSON.parse(await this.fs.promises.readFile('/accepted.json', 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    await git.init({ ...this.opts, defaultBranch: 'wallet' });
    if (this.state.head) { await this.verify(this.state.head, this.state.root, this.state.head); await git.writeRef({ ...this.opts, ref: 'refs/heads/wallet', value: this.state.head, force: true }); }
    return this;
  }
  async persist(next) {
    // LightningFS batches its directory metadata; flush objects before the
    // checkpoint and the checkpoint before reporting a durable local save.
    await this.fs.promises.flush?.();
    await this.fs.promises.writeFile('/accepted.next', JSON.stringify(next));
    await this.fs.promises.rename('/accepted.next', '/accepted.json');
    await this.fs.promises.flush?.();
    this.state = next;
  }
  async object(oid) {
    if (!oidOK(oid)) throw Error('Invalid object ID');
    const o = await git.readObject({ ...this.opts, oid, format: 'content' });
    const bytes = new Uint8Array(o.object);
    if (bytes.length > 16 * 1024 * 1024 || !['commit', 'tree', 'blob'].includes(o.type)) throw Error('Invalid object');
    const header = enc.encode(`${o.type} ${bytes.length}\0`), raw = new Uint8Array(header.length + bytes.length); raw.set(header); raw.set(bytes, header.length);
    if ((await this.crypto('hash', { algorithm: 'sha1', data: b64(raw) })).hex !== oid) throw Error('Object digest mismatch');
    return { type: o.type, bytes };
  }
  async files(tree) {
    const files = Object.create(null); let budget = MAX, count = 0;
    const visit = async (oid, prefix, depth) => {
      if (depth > 5) throw Error('Tree nesting limit');
      const o = await this.object(oid); if (o.type !== 'tree') throw Error('Expected tree');
      const { tree: entries } = await git.readTree({ ...this.opts, oid });
      for (const e of entries) {
        if (!e.path || /[/\\\0]/.test(e.path) || ['.', '..'].includes(e.path)) throw Error('Unsafe tree path');
        const path = prefix + e.path;
        if (e.mode === '040000') await visit(e.oid, path + '/', depth + 1);
        else if (e.mode === '100644') {
          const blob = await this.object(e.oid); budget -= blob.bytes.length;
          if (blob.type !== 'blob' || blob.bytes.length > 2 * 1024 * 1024 + 100 || budget < 0 || ++count > 100000 || Object.hasOwn(files, path)) throw Error('Snapshot limit');
          files[path] = b64(blob.bytes);
        } else throw Error('Unsupported tree mode');
      }
    };
    await visit(tree, '', 0); return files;
  }
  async history(head) {
    const graph = new Map(), visiting = new Map(), pending = [[head, false]];
    let roots = 0;
    while (pending.length) {
      const [id, expanded] = pending.pop();
      if (graph.has(id)) continue;
      if (expanded) {
        const c = visiting.get(id); visiting.delete(id);
        if (!c.parents.length) roots++;
        graph.set(id, c); continue;
      }
      if (visiting.has(id)) throw Error('Unsupported wallet history');
      if (graph.size + visiting.size >= 10000) throw Error('History limit');
      const o = await this.object(id); if (o.type !== 'commit') throw Error('Expected commit');
      const c = parseCommit(o.bytes); visiting.set(id, c);
      pending.push([id, true], ...[...c.parents].reverse().map(p => [p, false]));
    }
    if (roots !== 1) throw Error('Unsupported wallet history');
    return graph;
  }
  async verify(head, root, checkpoint) {
    const graph = await this.history(head);
    if (checkpoint && !graph.has(checkpoint)) throw Error('Rollback or divergent history');
    for (const c of graph.values()) {
      let keys = [root];
      const parents = [];
      for (const id of c.parents) {
        const files = await this.files(graph.get(id).tree);
        const checked = await this.crypto('validate_snapshot', {files});
        keys = parents.length ? keys.filter(key => checked.signers.includes(key)) : checked.signers;
        parents.push(files);
      }
      let valid = false;
      for (const publicKey of keys) { try { const checked = await this.crypto('ssh_verify', { publicKey, message: b64(c.unsigned), signature: c.signature }); if (checked.valid === true) { valid = true; break; } } catch { /* Try the other authorized signers. */ } }
      if (!valid) throw Error('Unauthorized or invalid commit signature');
      const files = await this.files(c.tree), checked = await this.crypto('validate_snapshot', { files });
      if (!parents.length && !checked.signers.includes(root)) throw Error('Root is not enrolled');
      for (const previous of parents) await this.crypto('validate_snapshot', {files, previous});
      if (parents.length === 2) {
        const base = mergeBase(graph, ...c.parents);
        const expected = mergeFiles(await this.files(graph.get(base).tree), ...parents);
        if (!equalFiles(expected, files)) throw Error('Conflicting wallet changes');
      }
    }
    return this.files(graph.get(head).tree);
  }
  async snapshot() { if (!this.state.head) throw Error('Connect a wallet first'); return this.verify(this.state.head, this.state.root, this.state.head); }
  async discoverRoot(head) {
      const graph = await this.history(head), commit = graph.values().next().value;
      const files = await this.files(commit.tree);
      const {signers} = await this.crypto('validate_snapshot', {files});
      for (const publicKey of signers) {
        try {
          const result = await this.crypto('ssh_verify', {publicKey, message:b64(commit.unsigned), signature:commit.signature});
          if (result.valid === true) return publicKey;
        } catch { /* A registered signer need not have signed genesis. */ }
      }
      throw Error('Unauthorized or invalid commit signature');
  }
  async accept(head, root, checkpoint) {
    const files = await this.verify(head, root, checkpoint);
    await git.writeRef({ ...this.opts, ref: 'refs/heads/wallet', value: head, force: true });
    await this.persist({ ...this.state, head, root });
    return files;
  }
  remote(url) { const u = new URL(url); if (u.protocol !== 'https:' || u.username || u.password || u.hash || u.search) throw Error('Use an HTTPS remote URL without credentials or query parameters'); return u.href; }
  async setRemote(url) {const remote=this.remote(url);if(remote===this.state.remote)return;await this.persist({ ...this.state,remote,synced:undefined,syncedAt:undefined,lastSync:null });}
  async fetch(url, auth = {}) {
    // A fresh IndexedDB repository has no remote fetch mapping. Passing a URL
    // alone still makes isomorphic-git require remote.origin.fetch after receiving
    // the pack. Track only wallet; this untrusted remote ref is never our accepted
    // checkpoint or local branch until accept() verifies its signed history.
    const remoteUrl = this.remote(url);
    await git.setConfig({ ...this.opts, path: 'remote.origin.fetch', value: '+refs/heads/wallet:refs/remotes/origin/wallet' });
    const result = await git.fetch({ ...this.opts, http: this.http, url: remoteUrl, remote: 'origin', ref: 'wallet', remoteRef: 'wallet', singleBranch: true, tags: false, onAuth: () => ({ username: auth.username || '', password: auth.password || '' }) });
    if (!result.fetchHead) throw Error('Remote wallet branch is missing'); return result.fetchHead;
  }
  async connect({ url, root, checkpoint, ...auth }) {
    if (this.state.head) throw Error('This installation already has a connected wallet');
    this.progress('fetching');
    const head = await connectionStep('fetch', () => this.fetch(url, auth));
    this.progress('verifying');
    // The selected HTTPS remote bootstraps trust once; later updates remain pinned.
    root ??= await connectionStep('verify', () => this.discoverRoot(head));
    checkpoint ??= head;
    const files=await connectionStep('verify',()=>this.verify(head,root,checkpoint));
    const syncedAt=Date.now();
    // Build the complete accepted state once. No fallible re-read happens after
    // persisting it, so a connected wallet is never reported as a failed fetch.
    await connectionStep('save connection',async()=>{
      await git.writeRef({...this.opts,ref:'refs/heads/wallet',value:head,force:true});
      await this.persist({...this.state,head,root,remote:this.remote(url),synced:head,syncedAt,lastSync:{outcome:'up-to-date',at:syncedAt}});
    });
    this.progress('complete');return files;
  }
  async importTransfer(bundle, { root, checkpoint } = {}) {
    if (bundle.format !== 'kagitaba-git-transfer' || bundle.version !== 1 || !oidOK(bundle.head) || !Array.isArray(bundle.objects) || bundle.objects.length > 200000) throw Error('Invalid transfer');
    let budget = 512 * 1024 * 1024;
    for (const o of bundle.objects) {
      const bytes = unb64(o.data); budget -= bytes.length;
      if (budget < 0 || bytes.length > 16 * 1024 * 1024 || !['blob', 'tree', 'commit'].includes(o.type)) throw Error('Transfer limit');
      const id = await git.writeObject({ ...this.opts, type: o.type, object: bytes, format: 'content' }); if (id !== o.oid) throw Error('Transfer digest mismatch');
    }
    if (!this.state.head && !root) throw Error('Explicit root trust is required');
    return this.accept(bundle.head, this.state.root || root, this.state.head || checkpoint);
  }
  async exportTransfer() {
    await this.snapshot(); const objects = [], seen = new Set(), pending = [this.state.head]; let budget = 512 * 1024 * 1024;
    while (pending.length) {
      const oid = pending.pop(); if (seen.has(oid)) continue; seen.add(oid);
      const o = await this.object(oid); budget -= o.bytes.length; if (budget < 0 || seen.size > 200000) throw Error('Transfer limit');
      objects.push({ oid, type: o.type, data: b64(o.bytes) });
      if (o.type === 'commit') { const c = parseCommit(o.bytes); pending.push(c.tree, ...c.parents); }
      if (o.type === 'tree') pending.push(...(await git.readTree({ ...this.opts, oid })).tree.map(e => e.oid));
    }
    return { format: 'kagitaba-git-transfer', version: 1, head: this.state.head, root: this.state.root, objects };
  }
  async commit(files, identity, message = 'Update wallet') {
    const previous = await this.snapshot(); await this.crypto('validate_snapshot', { files, previous });
    const tree = async subset => {
      const entries = [], dirs = new Map();
      for (const [path, value] of Object.entries(subset)) {
        const slash = path.indexOf('/');
        if (slash < 0) entries.push({ mode: '100644', path, oid: await git.writeBlob({ ...this.opts, blob: unb64(value) }), type: 'blob' });
        else { const dir = path.slice(0, slash); if (!dirs.has(dir)) dirs.set(dir, Object.create(null)); dirs.get(dir)[path.slice(slash + 1)] = value; }
      }
      for (const [path, subset] of dirs) entries.push({ mode: '040000', path, oid: await tree(subset), type: 'tree' });
      return git.writeTree({ ...this.opts, tree: entries });
    };
    const treeId = await tree(files), now = Math.floor(Date.now() / 1000), actor = `Kagitaba <wallet@localhost> ${now} +0000`;
    if (!/^[\x20-\x7e]{1,120}$/.test(message)) throw Error('Invalid commit message');
    const unsigned = `tree ${treeId}\nparent ${this.state.head}\nauthor ${actor}\ncommitter ${actor}\n\n${message}\n`;
    const signingIdentity = typeof identity === 'function' ? identity() : identity;
    const { signature } = await this.crypto('ssh_sign', { identity: signingIdentity, message: b64(enc.encode(unsigned)) });
    const signed = unsigned.replace('\n\n', '\ngpgsig ' + signature.trimEnd().replaceAll('\n', '\n ') + '\n\n');
    const head = await git.writeObject({ ...this.opts, type: 'commit', object: enc.encode(signed), format: 'content' });
    await this.accept(head, this.state.root, this.state.head); return head;
  }
  async sync(auth = {}) {
    if (!this.state.remote) throw Error('No remote configured');
    this.progress('fetching');
    const remoteHead = await this.fetch(this.state.remote, auth);
    let outcome='up-to-date';
    if (remoteHead !== this.state.head) {
      const ahead = await git.isDescendent({ ...this.opts, oid: this.state.head, ancestor: remoteHead });
      if (ahead) {
        this.progress('verifying');
        await this.verify(this.state.head, this.state.root, remoteHead);
        // A prior storage failure can leave the convenience ref ahead of the
        // accepted checkpoint. Never let Git choose that ref as our push source.
        await git.writeRef({...this.opts,ref:'refs/heads/wallet',value:this.state.head,force:true});
        this.progress('pushing');
        const result = await git.push({ ...this.opts, http: this.http, url: this.state.remote, ref: 'wallet', remoteRef: 'wallet', force: false, onAuth: () => ({ username: auth.username || '', password: auth.password || '' }) });
        if (!result.ok) throw Error('Remote refused update');
        outcome='pushed';
      } else {this.progress('verifying');await this.accept(remoteHead, this.state.root, this.state.head);outcome='pulled';}
    }
    const syncedAt=Date.now();await this.persist({ ...this.state, synced: this.state.head,syncedAt,lastSync:{outcome,at:syncedAt} });this.progress('complete');return {outcome,syncedAt,head:this.state.head};
  }
  async recordSyncError(error){await this.persist({...this.state,lastSync:{error,at:Date.now()}});}
}
