import {cryptoCall} from './crypto.mjs';
import {uiDiagnostic} from './errors.mjs';
import {GitReplica} from './git.mjs';
import {InstallationStore} from './storage.mjs';
import {RemoteAuth} from './remote-auth.mjs';
import {metadataPointers, isMetadata, decryptMetadata, pruneLegacy, renameParticipant} from './participant-metadata.mjs';
import {encode, decode, random, hex, text, textBytes} from './encoding.mjs';
import {validateRequest, matchesOrigin, originForSender, Epoch} from './policy.mjs';
import {checkDraft} from './drafts.mjs';

const epoch = new Epoch();
const requests = new Map();
let walletWindow;
async function openWallet(tab) {
  if (walletWindow !== undefined) {
    try {await browser.windows.update(walletWindow,{focused:true});browser.runtime.sendMessage({type:'active-site',tabId:tab.id}).catch(()=>{});return;}
    catch {walletWindow=undefined;}
  }
  const window=await browser.windows.create({url:browser.runtime.getURL(`app.html?tab=${tab.id}`),type:'popup',width:520,height:760});
  walletWindow=window.id;
}
const participantNames = new Map();
const rawEntries = new Map();
let identity = null, installation, files = {}, entries = new Map(), touched = 0;
const supportedPasskeys=new Set();
const db = new InstallationStore();
const progress=phase=>browser.runtime.sendMessage({type:'sync-progress',phase}).catch(()=>{});
const replica = new GitReplica({crypto: cryptoCall,progress});
const remoteAuth=new RemoteAuth({store:db,crypto:cryptoCall});
const ready = Promise.all([db.open(), replica.init()]).then(async () => {installation = await db.get('installation');await remoteAuth.load(); if (replica.state.head) files = await replica.snapshot();});
let mutation = Promise.resolve();
const serialize = callback => {const result = mutation.then(callback); mutation = result.catch(() => {}); return result;};
let automaticSyncQueued=false;
function autoSync(){
  if(automaticSyncQueued||!identity||!replica.state.head||!replica.state.remote||!remoteAuth.public(replica.state.remote).autoSync)return;
  automaticSyncQueued=true;
  setTimeout(()=>{serialize(async()=>{automaticSyncQueued=false;if(identity&&remoteAuth.public(replica.state.remote).autoSync)await synchronize();}).catch(()=>{});},0);
}
function publicStatus(){return {installation:publicInstallation(),unlocked:!!identity,replica:replica.state,lastSync:replica.state.lastSync??null,remoteAuth:remoteAuth.public(replica.state.remote),entries:metadata(),participants:publicParticipants()};}
function publicParticipants() {
  return Object.keys(files).flatMap(path => {
    const match = /^participants\/([0-9a-f]{64})\/pub.pem$/.exec(path);
    if (!match) return [];
    return [{id:match[1], name:identity ? participantNames.get(match[1]) ?? '' : ''}];
  });
}
function locked() { if (!identity) throw new Error('Unlock Kagitaba first'); touched = Date.now(); }
function lock(reason = 'lock') { identity = null;remoteAuth.clearSession(); entries.clear(); rawEntries.clear(); participantNames.clear(); supportedPasskeys.clear();epoch.invalidate(); for (const request of requests.values()) request.finish({error: 'Wallet locked'}); requests.clear(); browser.runtime.sendMessage({type: 'locked', reason}).catch(() => {}); }
function own(sender) {return sender.id === browser.runtime.id && sender.url?.split('?')[0] === browser.runtime.getURL('app.html');}
function publicInstallation() {if (!installation) return null; const {envelope, ...publicData} = installation; return publicData;}
function metadata() {return [...entries].map(([id, payload]) => ({id, title: payload.entity.title || id, kind: payload.kind}));}
async function indexPasskeys(id,payload,current){
  for(const key of supportedPasskeys)if(key.startsWith(`${id}:`))supportedPasskeys.delete(key);
  for(const credential of payload.entity.credentials??[]){if(credential.type!=='passkey')continue;try{await cryptoCall('passkey_validate',{privateKey:credential.key});}catch{continue;}epoch.check(current);supportedPasskeys.add(`${id}:${credential.credentialId}`);}
}
async function refresh(acceptedSnapshot) {
  const current = epoch.capture();
  const snapshot = acceptedSnapshot??await replica.snapshot();
  epoch.check(current); files = snapshot; entries.clear();rawEntries.clear();participantNames.clear();supportedPasskeys.clear();
  if (!identity) return;
  for (const [participant, id] of Object.entries(metadataPointers(files))) {
    if (!files[`entries/${id}/grants/${installation.participantId}`]) continue;
    const result = await decryptMetadata(files, participant, installation.participantId, identity, cryptoCall);
    epoch.check(current); participantNames.set(participant, result.name);
  }
  for (const [path, primary] of Object.entries(files)) {
    const match = /^entries\/([0-9a-f]{32})\/primary$/.exec(path);
    if (!match) continue;
    if (isMetadata(files, match[1])) continue;
    const grant = files[`entries/${match[1]}/grants/${installation.participantId}`];
    if (!grant) continue;
    let result;
    try{result=await cryptoCall('entry_decrypt', {identity, primary, grant});}catch{epoch.check(current);continue;}
    epoch.check(current); const payload=JSON.parse(result.payload);rawEntries.set(match[1],result.payload);entries.set(match[1],payload);await indexPasskeys(match[1],payload,current);
  }
}
async function synchronize(explicitAuth){
  const current=epoch.capture();let auth;
  try{
    auth=await remoteAuth.resolve(replica.state.remote,explicitAuth,identity,()=>epoch.check(current));
    epoch.check(current);
    const result=await replica.sync(auth);
    // Accepted encrypted state remains useful after lock. Only populate secret
    // caches if this is still the same unlocked session.
    try{files=await replica.snapshot();if(identity&&epoch.capture()===current)await refresh(files);}
    catch{if(identity&&epoch.capture()===current)lock();result.warning='Synchronized. Unlock again to reload wallet entries.';}
    browser.runtime.sendMessage({type:'sync-result',...result}).catch(()=>{});
    return result;
  }catch(error){
    const detail=uiDiagnostic(error);
    try{await replica.recordSyncError(detail);}catch{/* Keep the original actionable error. */}
    browser.runtime.sendMessage({type:'sync-result',error:detail}).catch(()=>{});
    browser.runtime.sendMessage({type:'sync-progress',phase:'error',error:detail}).catch(()=>{});
    throw error;
  }finally{if(auth)auth.password='';}
}
async function savePayload(id, payload, permitted = () => {}, expectedPrimary = null, changes) {
  locked(); const current = epoch.capture();
  checkDraft(files, id, expectedPrimary);
  if (isMetadata(files, id)) throw Error('Invalid entry');
  const oldPrefix = `entries/${id}/grants/`;
  const recipients = Object.keys(files).filter(path => path.startsWith(oldPrefix)).map(path => path.slice(oldPrefix.length));
  if (!recipients.length) recipients.push(installation.participantId);
  const pems = recipients.map(recipient => {
    const value = files[`participants/${recipient}/pub.pem`];
    if (!value) throw new Error('Recipient is not enrolled');
    return text(decode(value));
  });
  let raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
  if (changes) raw = (await cryptoCall('payload_edit', {entryId:id, payload:raw, changes})).payload;
  epoch.check(current);
  const encrypted = await cryptoCall('entry_encrypt', {entryId: id, payload: raw, recipients: pems});
  epoch.check(current);
  const next = await pruneLegacy(files, cryptoCall); epoch.check(current);
  for (const path of Object.keys(next)) if (path.startsWith(`entries/${id}/`)) delete next[path];
  next[`entries/${id}/primary`] = encrypted.primary;
  for (const [recipient, grant] of Object.entries(encrypted.grants)) next[`${oldPrefix}${recipient}`] = grant;
  await replica.commit(next, () => {epoch.check(current);permitted();return identity;}, 'Update encrypted wallet entry');
  files = next;
  epoch.check(current); await refresh(next);
  autoSync();
  return id;
}
async function currentDocument(request) {
  const tab = await browser.tabs.get(request.tabId);
  if (new URL(tab.url).origin !== request.origin) throw new Error('The website navigated');
  const probe = await browser.tabs.sendMessage(request.tabId, {type: 'probe'}, {frameId: 0});
  if (probe.documentToken !== request.documentToken || probe.origin !== request.origin) throw new Error('The website document changed');
}
function passkeys(request) {
  const result = [];
  for (const [id, payload] of entries) for (const credential of payload.entity.credentials ?? []) {
    if (credential.type !== 'passkey' || credential.rpId !== request.rpId || !supportedPasskeys.has(`${id}:${credential.credentialId}`)) continue;
    const allowed = request.input.allowCredentials;
    if (allowed?.length && !allowed.some(c => c.id === credential.credentialId)) continue;
    result.push({entryId: id, title: payload.entity.title, credential});
  }
  return result;
}
async function verifyHardware(prf) {
  const result = await cryptoCall('identity_unwrap', {envelope: installation.envelope, prf, context: installation.installationId});
  if (result.participantId !== installation.participantId || result.signingId !== installation.signingId) throw new Error('Wrong installation identity');
  return result.identity;
}
async function approve(message) {
  const request = requests.get(message.requestId);
  if (!request) throw new Error('Request expired');
  if (message.fallback) {request.finish({fallback: true}); return true;}
  locked(); const current = epoch.capture();
  await currentDocument(request);
  // A fresh PRF assertion with authenticator UV is required for every passkey use.
  if (!message.prf || message.uv !== true) throw new Error('Security key user verification is required');
  await verifyHardware(message.prf); epoch.check(current);
  const clientDataJSON = encode(textBytes(JSON.stringify({type: request.kind === 'create' ? 'webauthn.create' : 'webauthn.get', challenge: request.input.challenge, origin: request.origin, crossOrigin: false})));
  let credential;
  if (request.kind === 'create') {
    const excluded = request.input.excludeCredentials ?? [];
    if (passkeys({...request, input: {}}).some(item => excluded.some(ex => ex.id === item.credential.credentialId))) throw new Error('A matching passkey already exists');
    const created = await cryptoCall('passkey_create', {rpId: request.rpId, userHandle: request.input.user.id, clientDataJSON, uv: true});
    epoch.check(current);
    const id = hex(random(16));
    const payload = {format: 'kagitaba-cxf', version: 1, cxfVersion: {major: 1, minor: 0}, kind: 'item', entity: {id: encode(Uint8Array.from(id.match(/../g), byte => parseInt(byte,16))), title: `${request.rpId} — ${request.input.user.name}`, credentials: [{type: 'passkey', credentialId: created.credentialId, rpId: request.rpId, userHandle: request.input.user.id, username: request.input.user.name, userDisplayName: request.input.user.displayName ?? request.input.user.name, key: created.privateKey}], scope: {urls: [request.origin],androidApps:[]}}};
    await currentDocument(request); epoch.check(current);
    if(!requests.has(request.id))throw new Error('Request cancelled');
    await savePayload(id, payload, () => {if(!requests.has(request.id))throw new Error('Request cancelled');});
    credential = {id: created.credentialId, response: {clientDataJSON, authenticatorData: created.authenticatorData, attestationObject: created.attestationObject, publicKey: created.publicKey}, extensions: request.input.extensions?.credProps ? {credProps: {rk: true}} : {}};
  } else {
    const selected = passkeys(request).find(item => item.entryId === message.entryId && item.credential.credentialId === message.credentialId);
    if (!selected) throw new Error('Selected passkey is not permitted');
    const signed = await cryptoCall('passkey_assert', {privateKey: selected.credential.key, rpId: request.rpId, clientDataJSON, uv: true});
    credential = {id: selected.credential.credentialId, response: {clientDataJSON, ...signed, userHandle: selected.credential.userHandle}, extensions: {}};
  }
  epoch.check(current); await currentDocument(request);
  if (!requests.has(request.id)) throw new Error('Request cancelled');
  request.finish({credential}); return true;
}
async function handleUI(message) {
  await ready;
  if (message.type === 'status') return publicStatus();
  if (message.type === 'lock') {lock(); return true;}
  if (message.type === 'setup') {
    if (installation) throw new Error('This installation is already enrolled');
    const current = epoch.capture();
    const generated = await cryptoCall('identity_generate');
    const installationId = hex(random(16));
    const wrapped = await cryptoCall('identity_wrap', {identity: generated.identity, prf: message.prf, context: installationId});
    const {identity: secret, ...publicKeys} = generated;
    epoch.check(current);
    installation = {format:'kagitaba-browser-installation',version:1,...publicKeys, installationId, unlock: message.unlock, envelope: wrapped.envelope};
    await db.set('installation', installation); epoch.check(current); identity = secret; touched = Date.now();
    return publicInstallation();
  }
  if (message.type === 'unlock') {const current = epoch.capture(); const secret = await verifyHardware(message.prf); epoch.check(current); identity = secret; touched = Date.now(); if (replica.state.head) await refresh();autoSync(); return true;}
  if (message.type === 'connect') {
    const current=epoch.capture();
    const snapshot=await replica.connect(message.options);files=snapshot;
    let warning;
    // Connection acceptance is complete now. Optional credential persistence or
    // decrypting titles cannot retroactively turn that success into a failure.
    try{
      const options=message.options;
      await remoteAuth.save(replica.state.remote,{username:options.username??'',password:options.password??'',remember:options.remember??true,autoSync:options.autoSync??false},identity,()=>epoch.check(current));
    }catch{
      warning='Connected. Unlock the wallet and save remote credentials to remember the token.';
      try{await remoteAuth.save(replica.state.remote,{username:message.options.username??'',remember:message.options.remember??true,autoSync:message.options.autoSync??false},null);}catch{/* Connection remains accepted even if optional preferences cannot be saved. */}
    }
    if(identity&&epoch.capture()===current){try{await refresh(snapshot);}catch{warning??='Connected. Unlock again to load wallet entries.';}}
    return {connected:true,head:replica.state.head,syncedAt:replica.state.syncedAt,...(warning?{warning}:{})};
  }
  if (message.type === 'import') {lock(); await replica.importTransfer(message.bundle, message.trust); files = await replica.snapshot(); return true;}
  if (message.type === 'export') return {wallet: await replica.exportTransfer()};
  if (message.type === 'participant') return {format:'kagitaba-participant-1',encryption:installation.participantPem,signing:installation.signingPem};
  if (message.type === 'sync') return synchronize(message.auth);
  if (message.type === 'remote-auth') {
    if(!replica.state.remote)throw Error('No remote configured');const current=epoch.capture();
    const result=await remoteAuth.save(replica.state.remote,message,identity,()=>epoch.check(current));autoSync();return result;
  }
  if (message.type === 'remote') {await replica.setRemote(message.url);return true;}
  if (message.type === 'entry') {locked(); const payload = entries.get(message.id); if (!payload) throw new Error('Entry inaccessible'); return payload;}
  if (message.type === 'entry-draft') {locked(); const payload = rawEntries.get(message.id); if (!payload) throw new Error('Entry inaccessible'); return {payload, primary:files[`entries/${message.id}/primary`]};}
  if (message.type === 'name-participant') {
    locked();
    if (!/^[0-9a-f]{64}$/.test(message.id) || !files[`participants/${message.id}/pub.pem`]) throw Error('Unknown wallet participant');
    const name = message.name;
    if (typeof name !== 'string' || name.trim() !== name || [...name].length > 128 || textBytes(name).length > 512 || /[\p{Cc}\u202a-\u202e\u2066-\u2069]/u.test(name)) throw Error('Invalid participant name');
    const current = epoch.capture();
    const next = await renameParticipant(files, message.id, name, installation.participantId, identity, cryptoCall);
    epoch.check(current);
    await replica.commit(next, () => {epoch.check(current); return identity;}, 'Name participant');
    files = next; epoch.check(current); await refresh(next); autoSync(); return true;
  }
  if (message.type === 'save') {locked(); return savePayload(message.id ?? hex(random(16)), message.payload, () => {}, message.expectedPrimary, message.changes);}
  if (message.type === 'delete') {
    locked();if(!/^[0-9a-f]{32}$/.test(message.id)||isMetadata(files,message.id))throw new Error('Invalid entry');const current=epoch.capture(),next=await pruneLegacy(files,cryptoCall);epoch.check(current);
    for(const path of Object.keys(next))if(path.startsWith(`entries/${message.id}/`))delete next[path];
    await replica.commit(next,()=>{epoch.check(current);return identity;},'Delete encrypted wallet entry');files=next;epoch.check(current);await refresh(next);autoSync();return true;
  }
  if (message.type === 'request') {
    const request = requests.get(message.requestId);
    if (!request) throw new Error('Request expired');
    return {id: request.id, kind: request.kind, origin: request.origin, rpId: request.rpId, username: request.input.user?.name, accounts: identity ? passkeys(request).map(item => ({entryId: item.entryId, credentialId: item.credential.credentialId, title: item.title})) : []};
  }
  if (message.type === 'approve') return approve(message);
  if (['matches', 'fill', 'capture'].includes(message.type)) {
    locked(); const current = epoch.capture(); const tab = await browser.tabs.get(message.tabId);
    const origin = originForSender({tab, frameId: 0, url: tab.url});
    const probe = await browser.tabs.sendMessage(tab.id, {type: 'probe'}, {frameId: 0});
    if (probe.origin !== origin) throw new Error('Website navigated');
    epoch.check(current);
    if (message.type === 'matches') return {origin, entries: [...entries].filter(([,payload]) => matchesOrigin(payload, origin) && payload.entity.credentials.some(c => c.type === 'basic-auth')).map(([id,payload]) => ({id, title: payload.entity.title}))};
    if (message.type === 'capture') {const captured=await browser.tabs.sendMessage(tab.id, {type: 'capture', origin, documentToken: probe.documentToken}, {frameId: 0});epoch.check(current);return {origin,...captured};}
    const payload = entries.get(message.id);
    if (!matchesOrigin(payload, origin)) throw new Error('Credential does not match this website');
    const credential = payload.entity.credentials.find(c => c.type === 'basic-auth');
    await browser.tabs.sendMessage(tab.id, {type: 'fill', origin, documentToken: probe.documentToken, username: credential.username?.value ?? '', password: credential.password?.value ?? ''}, {frameId: 0});
    return true;
  }
  throw new Error('Unknown operation');
}
browser.runtime.onMessage.addListener((message, sender) => {
  if (own(sender)) return (['lock', 'status', 'request'].includes(message.type) ? handleUI(message) : serialize(() => handleUI(message))).catch(error => {const detail = uiDiagnostic(error); console.warn(`[Kagitaba] ${detail}`); throw new Error(detail);});
  if (message.type === 'cancel') {
    for (const request of requests.values()) if (request.pageId === message.id && request.tabId === sender.tab?.id && request.documentToken === message.documentToken) request.finish({error: 'Request cancelled'});
    return Promise.resolve(true);
  }
  if (message.type !== 'webauthn') return undefined;
  return ready.then(() => {
    let request;
    try {if(JSON.stringify(message.input).length>65536)throw new Error('Request too large');request = validateRequest(message.kind, message.input, sender);} catch {return {fallback: true};}
    if (!installation || !replica.state.head || requests.size >= 8 || [...requests.values()].some(r=>r.tabId===sender.tab.id) || typeof message.documentToken !== 'string') return {fallback: true};
    const id = hex(random(16));
    return new Promise(resolve => {
      const timer = setTimeout(() => finish({error: 'Request expired'}), request.timeout);
      const finish = result => {clearTimeout(timer); requests.delete(id); resolve(result);};
      requests.set(id, {...request, id, pageId: message.id, documentToken: message.documentToken, tabId: sender.tab.id, finish});
      browser.windows.create({url: browser.runtime.getURL(`app.html?request=${id}`),type:'popup',width:480,height:640}).then(window=>{const pending=requests.get(id);if(pending)pending.windowId=window.id;else browser.windows.remove(window.id).catch(()=>{});}).catch(() => finish({error: 'Unable to open approval'}));
    });
  });
});
browser.browserAction.onClicked.addListener(tab => openWallet(tab).catch(()=>{}));
browser.windows.onRemoved.addListener(windowId=>{if(walletWindow===windowId)walletWindow=undefined;for(const request of requests.values())if(request.windowId===windowId)request.finish({error:'Request cancelled'});});
browser.webNavigation.onCommitted.addListener(details => {if (details.frameId === 0) for (const request of requests.values()) if (request.tabId === details.tabId) request.finish({error: 'Website navigated'});});
browser.tabs.onRemoved.addListener(tabId => {for (const request of requests.values()) if (request.tabId === tabId) request.finish({error: 'Website closed'});});
browser.alarms.create('lock', {periodInMinutes: 1});
browser.alarms.onAlarm.addListener(() => {if (identity && Date.now() - touched >= 5 * 60 * 1000) lock();});
