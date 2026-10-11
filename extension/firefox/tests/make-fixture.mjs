// Synthetic browser integration fixture. No user wallet or hardware is read.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import git from 'isomorphic-git';
import init, { command } from '../pkg/kagitaba_browser.js';
import { GitReplica, b64 } from '../src/git.mjs';

await init({module_or_path:fs.readFileSync(new URL('../pkg/kagitaba_browser_bg.wasm',import.meta.url))});
const crypto = async (op,args={}) => {
  try { return JSON.parse(await command(JSON.stringify({op,...args}),randomBytes(65536))); }
  catch { throw Error(`Synthetic fixture operation failed: ${op}`); }
};
const tmp = fs.mkdtempSync(path.join(os.tmpdir(),'kagitaba-fixture-'));
const promises = {};
for (const name of ['mkdir','readFile','writeFile','stat','lstat','readdir','unlink','rmdir','readlink']) promises[name] = (p,...args) => fs.promises[name](tmp+p,...args);
promises.rename = (a,b) => fs.promises.rename(tmp+a,tmp+b);
promises.symlink = (target,p) => fs.promises.symlink(target,tmp+p);
const bytes = text => new TextEncoder().encode(text);
try {
  const replica = new GitReplica({crypto,fs:{promises}}); await replica.init();
  const generated = await crypto('identity_generate'), {identity,...publicKeys} = generated;
  const installationId = randomBytes(16).toString('hex'), prf = b64(randomBytes(32));
  const wrapped = await crypto('identity_wrap',{identity,prf,context:installationId});
  const installation = {format:'kagitaba-browser-installation',version:1,...publicKeys,installationId,
    unlock:{rpId:'kagitaba.local',prfInput:b64(randomBytes(32)),credentialId:b64(randomBytes(32))},envelope:wrapped.envelope};
  const participantId = generated.participantId, entryId = randomBytes(16).toString('hex');
  const payload = JSON.stringify({format:'kagitaba-cxf',version:1,cxfVersion:{major:1,minor:0},kind:'item',entity:{id:b64(Buffer.from(entryId,'hex')),title:'Synthetic browser login',credentials:[{type:'basic-auth',username:{fieldType:'string',value:'synthetic-user'},password:{fieldType:'concealed-string',value:'synthetic-password'}}],scope:{urls:['https://example.test'],androidApps:[]}}});
  const encrypted = await crypto('entry_encrypt',{entryId,payload,recipients:[generated.participantPem]});
  const files = {'kagitaba-format':b64(bytes('1\n')),
    [`participants/${participantId}/pub.pem`]:b64(bytes(generated.participantPem)),
    [`participants/${participantId}/sign.pem`]:b64(bytes(generated.signingPem)),
    [`participants/${participantId}/browser.json`]:b64(bytes(JSON.stringify(installation))),
    [`entries/${entryId}/primary`]:encrypted.primary,
    [`entries/${entryId}/grants/${participantId}`]:encrypted.grants[participantId]};
  await crypto('validate_snapshot',{files});
  async function tree(subset) {
    const entries=[],dirs=new Map();
    for(const [p,v] of Object.entries(subset)) {const n=p.indexOf('/'); if(n<0) entries.push({mode:'100644',path:p,oid:await git.writeBlob({...replica.opts,blob:Buffer.from(v,'base64url')}),type:'blob'});
      else {const dir=p.slice(0,n);if(!dirs.has(dir))dirs.set(dir,{});dirs.get(dir)[p.slice(n+1)]=v;}}
    for(const [p,v] of dirs)entries.push({mode:'040000',path:p,oid:await tree(v),type:'tree'});
    return git.writeTree({...replica.opts,tree:entries});
  }
  const treeId=await tree(files), actor='Synthetic <fixture@localhost> 1 +0000';
  const unsigned=`tree ${treeId}\nauthor ${actor}\ncommitter ${actor}\n\nSynthetic fixture\n`;
  const {signature}=await crypto('ssh_sign',{identity,message:b64(bytes(unsigned))});
  const signed=unsigned.replace('\n\n','\ngpgsig '+signature.trimEnd().replaceAll('\n','\n ')+'\n\n');
  const head=await git.writeObject({...replica.opts,type:'commit',format:'content',object:bytes(signed)});
  await replica.accept(head,generated.signingPem);
  // This second commit exercises the production signing/save path too.
  await replica.commit(files,identity,'Verify browser writer');
  const wallet=await replica.exportTransfer();
  const result={installation,prf,wallet,root:generated.signingPem,checkpoint:wallet.head,entryId};
  const output=process.argv[2]; if(!output)throw Error('Provide a new output JSON path');
  fs.writeFileSync(output,JSON.stringify(result),{flag:'wx',mode:0o600});
} finally {fs.rmSync(tmp,{recursive:true,force:true});}
