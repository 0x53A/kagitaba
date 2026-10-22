// Build Rust/WASM and install JS dependencies before running:
// nix-shell --run 'node --test extension/firefox/tests/wasm.integration.mjs'
// These tests use synthetic keys only and exercise the real bundled WASM.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFileSync} from 'node:child_process';
import git from 'isomorphic-git';
import {randomBytes, createHash, createPublicKey, verify} from 'node:crypto';
import init, {command} from '../pkg/kagitaba_browser.js';
import {GitReplica, b64, unb64} from '../src/git.mjs';
import {RemoteAuth} from '../src/remote-auth.mjs';

const root = fileURLToPath(new URL('../../..', import.meta.url));
const ready = init({module_or_path:fs.readFileSync(new URL('../pkg/kagitaba_browser_bg.wasm', import.meta.url))});
const text = s => new TextEncoder().encode(s);

test('WASM accepts a clean metadata merge and its grant-repair child from either parent', async t => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'kagitaba-metadata-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const fixturePath=path.join(dir,'fixture.json'), wallet=path.join(dir,'wallet');
  const quote=s=>`'${s.replaceAll("'", "'\\''")}'`;
  execFileSync('nix-shell',['--run',`cargo run -q -p kagitaba-store --example browser_fixture -- ${quote(fixturePath)} ${quote(wallet)} --metadata-merge`],{cwd:root});
  const fixture=JSON.parse(fs.readFileSync(fixturePath));
  const replicaDir=path.join(dir,'replica');fs.mkdirSync(replicaDir);
  const promises={};
  for(const name of ['mkdir','readFile','writeFile','stat','lstat','readdir','unlink','rmdir','readlink'])promises[name]=(p,...args)=>fs.promises[name](replicaDir+p,...args);
  promises.rename=(a,b)=>fs.promises.rename(replicaDir+a,replicaDir+b);
  promises.symlink=(target,p)=>fs.promises.symlink(target,replicaDir+p);
  const replica=new GitReplica({crypto,fs:{promises}});await replica.init();
  await replica.importTransfer(fixture,{root:fixture.root,checkpoint:fixture.head});
  const child=(await git.readCommit({...replica.opts,oid:fixture.head})).commit;
  assert.equal(child.parent.length,1);
  const merge=(await git.readCommit({...replica.opts,oid:child.parent[0]})).commit;
  assert.equal(merge.parent.length,2);
  for(const parent of merge.parent)await replica.verify(fixture.head,fixture.root,parent);
  const files=await replica.snapshot();
  const validated=await crypto('validate_snapshot',{files});
  const [participant,id]=Object.entries(validated.participantMetadata)[0];
  const identity=b64(Buffer.concat([Buffer.from('KBI1'),Buffer.alloc(32,9),Buffer.alloc(32,9)]));
  const own=await crypto('identity_wrap',{identity,prf:b64(Buffer.alloc(32,7)),context:'test'});
  const reopened=await crypto('identity_unwrap',{envelope:own.envelope,prf:b64(Buffer.alloc(32,7)),context:'test'});
  const result=await crypto('metadata_decrypt',{identity,participantId:participant,primary:files[`entries/${id}/primary`],grant:files[`entries/${id}/grants/${reopened.participantId}`]});
  assert.equal(result.name,'Synthetic encrypted name');
  const broken={...files};delete broken[`entries/${id}/primary`];
  await assert.rejects(crypto('validate_snapshot',{files:broken}));
});
async function crypto(op, fields = {}) {
  await ready;
  const entropy = randomBytes(65536);
  try { return JSON.parse(await command(JSON.stringify({op, ...fields}), entropy)); }
  catch { throw Error(`WASM operation failed: ${op}`); }
  finally { entropy.fill(0); }
}

test('bundled WASM wraps identities and produces independently verified WebAuthn signatures', async () => {
  const identity = await crypto('identity_generate');
  const prf = b64(randomBytes(32)), context = 'synthetic-integration-installation';
  const sealed = await crypto('identity_wrap', {identity:identity.identity, prf, context});
  assert.deepEqual(await crypto('identity_unwrap', {...sealed, prf, context}), identity);
  await assert.rejects(crypto('identity_unwrap', {...sealed, prf, context:context+'-wrong'}));
  const clientDataJSON = b64(text(JSON.stringify({type:'webauthn.create', challenge:b64(randomBytes(32)), origin:'https://example.test', crossOrigin:false})));
  const registration = await crypto('passkey_create', {rpId:'example.test', userHandle:b64(randomBytes(16)), clientDataJSON, uv:true});
  const client = b64(text(JSON.stringify({type:'webauthn.get', challenge:b64(randomBytes(32)), origin:'https://example.test', crossOrigin:false})));
  const assertion = await crypto('passkey_assert', {privateKey:registration.privateKey, rpId:'example.test', clientDataJSON:client, uv:true});
  const auth = unb64(assertion.authenticatorData);
  assert.deepEqual(Buffer.from(auth.slice(0,32)), createHash('sha256').update('example.test').digest());
  assert.deepEqual([...auth.slice(33)], [0,0,0,0]);
  const message = Buffer.concat([auth,createHash('sha256').update(unb64(client)).digest()]);
  const publicKey = createPublicKey({key:Buffer.from(unb64(registration.publicKey)), format:'der', type:'spki'});
  assert.equal(verify('sha256', message, publicKey, unb64(assertion.signature)), true);
  message[0] ^= 1;
  assert.equal(verify('sha256', message, publicKey, unb64(assertion.signature)), false);
});

test('remote token persistence is encrypted, scoped, lock-gated and survives reopening',async()=>{
  const values=new Map(),store={get:async key=>values.get(key),set:async(key,value)=>values.set(key,structuredClone(value))};
  const identity=(await crypto('identity_generate')).identity,auth=new RemoteAuth({store,crypto});
  const url='https://example.test/wallet.git',password='synthetic-private-remote-token';
  await auth.save(url,{username:'synthetic',password,remember:true,autoSync:true},identity);
  assert.equal(JSON.stringify([...values]).includes(password),false);
  assert.equal(JSON.stringify([...values]).includes(identity),false);
  const reopened=new RemoteAuth({store,crypto});await reopened.load();
  assert.deepEqual(reopened.public(url),{username:'synthetic',hasToken:true,hasSessionToken:false,remember:true,autoSync:true});
  assert.deepEqual(await reopened.resolve(url,undefined,identity),{username:'synthetic',password});
  await assert.rejects(reopened.resolve(url,undefined,null),/Unlock/);
  assert.equal(reopened.public('https://other.test/wallet.git').hasToken,false);
  assert.equal((await reopened.resolve('https://other.test/wallet.git',undefined,null)).password,'');
  await reopened.save(url,{username:'synthetic',password:'',remember:true,autoSync:false},identity);
  assert.equal((await reopened.resolve(url,undefined,identity)).password,password);
  await reopened.save(url,{username:'synthetic',remember:false},identity);
  assert.equal(reopened.public(url).hasToken,false);
  assert.equal(reopened.public(url).hasSessionToken,true);
  assert.equal((await reopened.resolve(url,undefined,identity)).password,password);
  assert.equal(JSON.stringify([...values]).includes(password),false);
  reopened.clearSession();
  await assert.rejects(reopened.resolve(url,undefined,identity),/No saved remote token/);
});

test('bundled WASM verifies a native merge from either checkpoint and signs a durable browser revision', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kagitaba-wasm-integration-'));
  t.after(() => fs.rmSync(dir, {recursive:true, force:true}));
  const fixturePath = path.join(dir, 'native.json');
  const nativeWallet = path.join(dir, 'native-wallet');
  const quote = s => `'${s.replaceAll("'", "'\\''")}'`;
  execFileSync('nix-shell', ['--run', `cargo run -q -p kagitaba-store --example browser_fixture -- ${quote(fixturePath)} ${quote(nativeWallet)} --merge`], {cwd:root});
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const replicaDir = path.join(dir, 'replica'); fs.mkdirSync(replicaDir);
  const promises = {};
  for (const name of ['mkdir','readFile','writeFile','stat','lstat','readdir','unlink','rmdir','readlink']) promises[name] = (p, ...args) => fs.promises[name](replicaDir+p, ...args);
  promises.rename = (a,b) => fs.promises.rename(replicaDir+a,replicaDir+b);
  promises.symlink = (target,p) => fs.promises.symlink(target,replicaDir+p);
  const replica = new GitReplica({crypto,fs:{promises}}); await replica.init();
  await replica.importTransfer(fixture, {root:fixture.root, checkpoint:fixture.head});
  assert.equal(await replica.discoverRoot(fixture.head), fixture.root);
  assert.equal(replica.state.head, fixture.head);
  const parents = (await git.readCommit({...replica.opts, oid:fixture.head})).commit.parent;
  assert.equal(parents.length, 2);
  for (const parent of parents) await replica.verify(fixture.head, fixture.root, parent);
  let files = await replica.snapshot();
  const identity = b64(Buffer.concat([Buffer.from('KBI1'), Buffer.alloc(32,8), Buffer.alloc(32,12)]));
  const participantId = Object.keys(files).find(path => /^participants\/[^/]+\/pub.pem$/.test(path)).split('/')[1];
  const {renameParticipant, decryptMetadata, metadataPointers} = await import('../src/participant-metadata.mjs');
  files = await renameParticipant(files, participantId, 'Firefox · synthetic', participantId, identity, crypto);
  const metaId = metadataPointers(files)[participantId];
  assert.equal((await crypto('validate_snapshot', {files})).participantMetadata[participantId], metaId);
  assert.equal((await decryptMetadata(files,participantId,participantId,identity,crypto)).name,'Firefox · synthetic');
  assert.equal(Object.keys(files).some(path=>path.endsWith('/name.json')||path.endsWith('/browser.json')),false);
  for(const data of Object.values(files))assert.equal(Buffer.from(data,'base64url').includes(Buffer.from('Firefox · synthetic')),false);
  for (const name of ['bad\nname', ' '.repeat(2), 'x'.repeat(129), '\u202ehidden']) {
    await assert.rejects(renameParticipant(files,participantId,name,participantId,identity,crypto));
  }
  await replica.commit(files, identity, 'Synthetic browser interoperability update');
  assert.notEqual(replica.state.head, fixture.head);
  const reopened = new GitReplica({crypto,fs:{promises}}); await reopened.init();
  assert.equal(reopened.state.head, replica.state.head);
  const bundle = await reopened.exportTransfer();
  assert.equal(bundle.objects.filter(o => o.type === 'commit').length, 5);
  const returnPath = path.join(dir, 'browser.json'), rootPath = path.join(dir, 'root.pem');
  fs.writeFileSync(returnPath, JSON.stringify(bundle)); fs.writeFileSync(rootPath, fixture.root);
  execFileSync('nix-shell', ['--run', `cargo run -q -p kagitaba-store --example browser_transfer -- import ${quote(nativeWallet)} ${quote(rootPath)} ${quote(parents[1])} ${quote(returnPath)} --confirmed-trust`], {cwd:root});
  await assert.rejects(reopened.importTransfer(fixture), /Rollback|divergent/);
});

test('shared credential tools preserve unrestricted fields and generate matching TOTP codes', async()=>{
  await ready;
  const call=async(op,args={})=>JSON.parse(await command(JSON.stringify({op,...args}),randomBytes(65536)));
  const generated=await call('password_generate',{rules:{}});
  assert.match(generated.password,/^[acdefhjkmnprtuvwxy347]{12}$/);
  assert.match(generated.password,/[347]/);
  const {credential}=await call('totp_parse',{uri:'otpauth://totp/Example:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&period=300&digits=8'});
  assert.equal(credential.period,300);
  assert.equal((await call('totp_code',{credential:{...credential,period:30},now:59})).code,'94287082');
  const id='01010101010101010101010101010101';
  const payload=JSON.stringify({format:'kagitaba-cxf',version:1,cxfVersion:{major:1,minor:0},kind:'item',entity:{id:'AQEBAQEBAQEBAQEBAQEBAQ',title:'Test',credentials:[{type:'basic-auth',password:{fieldType:'concealed-string',value:'old',vendor:'kept'}},{type:'basic-auth',password:{fieldType:'concealed-string',value:'second'}},credential],scope:{urls:['http://localhost/path?q=1#f','ssh://host','bare host',''],androidApps:[]}}});
  const result=await call('payload_edit',{entryId:id,payload,changes:{logins:[{index:1,password:'\n unicode 密码 \t'}]}});
  const edited=JSON.parse(result.payload);
  assert.deepEqual(edited.entity.scope,JSON.parse(payload).entity.scope);
  assert.deepEqual(edited.entity.credentials[0],JSON.parse(payload).entity.credentials[0]);
  assert.equal(edited.entity.credentials[1].password.value,'\n unicode 密码 \t');
  assert.equal(edited.entity.credentials[2].period,300);
});

test('generator rank-zero vector matches native and Android',async()=>{
  await ready;
  const result=JSON.parse(await command(JSON.stringify({op:'password_generate',rules:{}}),new Uint8Array(65536)));
  assert.equal(result.password,'aaaaaaaaaaa3');
  await assert.rejects(command(JSON.stringify({op:'password_generate',rules:{}}),new Uint8Array()));
});

test('native attachment above 16 MiB survives WASM validation, browser edit and native reimport', async t => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'kagitaba-attachments-'));
  t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const quote=s=>`'${s.replaceAll("'", "'\\''")}'`;
  const fixturePath=path.join(dir,'fixture.json'),nativeWallet=path.join(dir,'wallet');
  execFileSync('nix-shell',['--run',`cargo run -q -p kagitaba-store --example browser_fixture -- ${quote(fixturePath)} ${quote(nativeWallet)} --attachment`],{cwd:root});
  const fixture=JSON.parse(fs.readFileSync(fixturePath));
  const replicaDir=path.join(dir,'replica');fs.mkdirSync(replicaDir);
  const promises={};
  for(const name of ['mkdir','readFile','writeFile','stat','lstat','readdir','unlink','rmdir','readlink'])promises[name]=(p,...args)=>fs.promises[name](replicaDir+p,...args);
  promises.rename=(a,b)=>fs.promises.rename(replicaDir+a,replicaDir+b);
  promises.symlink=(target,p)=>fs.promises.symlink(target,replicaDir+p);
  const replica=new GitReplica({crypto,fs:{promises}});await replica.init();
  await replica.importTransfer(fixture,{root:fixture.root,checkpoint:fixture.head});
  const files=await replica.snapshot(), blob=Object.keys(files).find(p=>p.includes('/attachments/'));
  assert.ok(blob);assert.ok(unb64(files[blob]).length>16*1024*1024);
  const id='07'.repeat(16),identity=b64(Buffer.concat([Buffer.from('KBI1'),Buffer.alloc(32,8),Buffer.alloc(32,12)]));
  const grant=Object.keys(files).find(p=>p.startsWith(`entries/${id}/grants/`));
  const {payload}=await crypto('entry_decrypt',{identity,primary:files[`entries/${id}/primary`],grant:files[grant]});
  const edited=await crypto('payload_edit',{entryId:id,payload,changes:{title:'Browser edit keeps file'}});
  await crypto('validate_attachment_edit',{entryId:id,payload:edited.payload,previousPayload:payload});
  const recipient=textDecoder(files[Object.keys(files).find(p=>/^participants\/[^/]+\/pub.pem$/.test(p))]);
  const encrypted=await crypto('entry_encrypt',{entryId:id,payload:edited.payload,recipients:[recipient]});
  const {replaceEntry}=await import('../src/drafts.mjs');
  const next=replaceEntry(files,id,encrypted);assert.equal(next[blob],files[blob]);
  await replica.commit(next,identity,'Synthetic attachment-preserving edit');
  const exported=await replica.exportTransfer(),returnPath=path.join(dir,'returned.json'),rootPath=path.join(dir,'root.pem');
  fs.writeFileSync(returnPath,JSON.stringify(exported));fs.writeFileSync(rootPath,fixture.root);
  execFileSync('nix-shell',['--run',`cargo run -q -p kagitaba-store --example browser_transfer -- import ${quote(nativeWallet)} ${quote(rootPath)} ${quote(fixture.head)} ${quote(returnPath)} --confirmed-trust`],{cwd:root});
  assert.equal((await replica.snapshot())[blob],files[blob]);
});
function textDecoder(encoded){return new TextDecoder().decode(unb64(encoded));}

test('bundled WASM signs stored backup flags and rejects malformed backup state',async()=>{
 const data=type=>b64(text(JSON.stringify({type,challenge:b64(randomBytes(32)),origin:'https://example.test'})));
 const created=await crypto('passkey_create',{rpId:'example.test',userHandle:b64(randomBytes(16)),clientDataJSON:data('webauthn.create'),uv:true});
 const publicKey=createPublicKey({key:Buffer.from(unb64(created.publicKey)),format:'der',type:'spki'});
 const client=data('webauthn.get');
 for(const [eligible,state,expected] of [[false,false,0x05],[true,false,0x0d],[true,true,0x1d]]){
  const signed=await crypto('passkey_assert',{privateKey:created.privateKey,rpId:'example.test',clientDataJSON:client,uv:true,kagitabaBackupFlags:{eligible,state}});
  const auth=unb64(signed.authenticatorData);assert.equal(auth[32],expected);
  const message=Buffer.concat([auth,createHash('sha256').update(unb64(client)).digest()]);
  assert.equal(verify('sha256',message,publicKey,unb64(signed.signature)),true);
 }
 await assert.rejects(crypto('passkey_assert',{privateKey:created.privateKey,rpId:'example.test',clientDataJSON:client,uv:true,kagitabaBackupFlags:{eligible:false,state:true}}));
 await assert.rejects(crypto('passkey_validate',{privateKey:created.privateKey,kagitabaBackupFlags:null}));
});
