import {encode, decode, random, hex} from './encoding.mjs';
const app = document.querySelector('#app'), notice = document.querySelector('#notice');
const params = new URLSearchParams(location.search), requestId = params.get('request');
let tabId = Number(params.get('tab'));
async function openEntry(id, parent) {const draft=await send({type:'entry-draft',id});showEntry(JSON.parse(draft.payload),id,parent,draft);}
let state, uiEpoch=0;
let connectionDraft = {}, settingsDraft = {}, view = 'wallet', selectedId = null, search = '', dirty = false, busy = false, renderVersion = 0, fieldNumber = 0, requestFinished = false;
const send = async message => {const captured=uiEpoch;const value=await browser.runtime.sendMessage(message);if(captured!==uiEpoch && !['lock','connect','status','sync'].includes(message.type))throw new Error('Wallet locked. Unlock to continue.');return value;};
function el(tag, content, className) {const node = document.createElement(tag); if (content !== undefined) node.textContent = content; if(className) node.className = className; return node;}
function button(label, action, primary = false) {const node = el('button', label, primary ? 'primary' : ''); node.type='button';node.onclick = () => run(action, node); return node;}
function field(parent, label, value = '', type = 'text') {const caption=el('label',label),input = el(type === 'textarea' ? 'textarea' : 'input');input.id=`field-${++fieldNumber}`;caption.htmlFor=input.id; if(type !== 'textarea') input.type = type; input.value = value; parent.append(caption,input); return input;}
function check(parent,label,value){const row=el('label',undefined,'check'),input=el('input');input.type='checkbox';input.checked=value;row.append(input,el('span',label));parent.append(row);return input;}
function disclosure(parent,title){const node=el('details');node.append(el('summary',title));parent.append(node);return node;}
function feedback(text='',kind='info'){notice.textContent=text;notice.dataset.kind=kind;notice.hidden=!text;}
function controls(){app.setAttribute('aria-busy',String(busy));for(const b of app.querySelectorAll('button'))b.disabled=busy;}
function canLeave(){if(dirty&&!confirm('Discard your unsaved changes?'))return false;dirty=false;return true;}
async function navigate(next){if(!canLeave())return;view=next;selectedId=null;await render();feedback();}
function section(title) {const node = el('section'); node.append(el('h2', title)); app.append(node); return node;}
async function run(action, control) {if(busy)return;busy=true;controls();feedback(`${control?.textContent??'Working'}…`,'progress');try{await action();if(notice.dataset.kind==='progress')feedback('Done.','success');}catch(error){feedback(error.message||'Operation failed. Please retry.','error');}finally{busy=false;controls();}}
function download(name, value) {const url = URL.createObjectURL(new Blob([JSON.stringify(value)],{type:'application/json'})); const link = el('a'); link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function assertion(unlock) {
  feedback('Follow Firefox’s prompt: enter your security-key PIN and touch the key when requested.','progress');
  const credential = await navigator.credentials.get({publicKey: {rpId: unlock.rpId, challenge: random(32), allowCredentials: [{type:'public-key',id:decode(unlock.credentialId)}], userVerification:'required', timeout:120000, extensions:{prf:{eval:{first:decode(unlock.prfInput)}}}}});
  const output = credential?.getClientExtensionResults()?.prf?.results?.first;
  if (!output || !(new Uint8Array(credential.response.authenticatorData)[32] & 4)) throw new Error('This browser/key did not provide PRF with user verification. No alternative unlock is used.');
  return {prf: encode(output), uv:true};
}
async function setup() {
  const rpId = 'kagitaba.local', prfInput = encode(random(32));
  const credential = await navigator.credentials.create({publicKey:{rp:{id:rpId,name:'Kagitaba wallet unlock'},user:{id:random(32),name:`Firefox ${new Date().toISOString().slice(0,10)}`,displayName:'Kagitaba installation'},challenge:random(32),pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'discouraged',requireResidentKey:false,userVerification:'required',authenticatorAttachment:'cross-platform'},attestation:'none',timeout:120000,extensions:{prf:{eval:{first:decode(prfInput)}}}}});
  if (!credential) throw new Error('Security key enrollment cancelled');
  const unlock = {rpId,prfInput,credentialId:encode(credential.rawId)};
  const proof = await assertion(unlock);
  await send({type:'setup',unlock,...proof}); await render();
}
async function unlock() {const proof=await assertion(state.installation.unlock);await send({type:'unlock',...proof});await render();feedback('Wallet unlocked.','success');}
async function render() {
  if(requestFinished)return;
  const version=++renderVersion,next=await send({type:'status'});if(version!==renderVersion)return;state=next;app.replaceChildren();
  document.querySelector('#lock').hidden=!state.unlocked;
  document.querySelector('#header-state').textContent=state.unlocked?'Unlocked':'Locked';
  if(!state.installation){const node=section('1 · Protect this installation');node.append(el('p','Connect your security key. Firefox will ask for its PIN and a touch.'),button('Enroll security key',setup,true),el('p','Reinstalling requires new enrollment in your wallet.','muted'));controls();return;}
  if(requestId){await renderRequest();return;}
  if(!state.replica.head){renderConnect();return;}
  const nav=el('nav',undefined,'tabs');nav.setAttribute('aria-label','Wallet navigation');for(const [key,label] of [['wallet','Wallet'],['settings','Settings']]){const b=button(label,()=>navigate(key));b.setAttribute('aria-current',String(key==='wallet'?view==='wallet':view!=='wallet'));nav.append(b);}app.append(nav);
  if(view!=='wallet'){renderSync();controls();return;}
  renderSyncBar();
  if(!state.unlocked){const top=section('Unlock wallet');top.append(button('Unlock with security key',unlock,true));controls();return;}
  if(state.unlocked){
    if(tabId)await renderWebsite();
    const workspace=section('Entries'),toolbar=el('div',undefined,'toolbar'),filter=el('input');filter.type='search';filter.placeholder='Search entries';filter.setAttribute('aria-label','Search entries');filter.value=search;
    const layout=el('div',undefined,'layout'),list=el('ul',undefined,'entries'),details=el('div',undefined,'entry-detail');layout.append(list,details);toolbar.append(filter,button('New login',()=>{if(canLeave())edit(newPayload(),null,details);},true));workspace.append(toolbar,layout);
    const draw=()=>{list.replaceChildren();const matches=state.entries.filter(e=>e.title.toLowerCase().includes(search.toLowerCase()));for(const entry of matches){const item=el('li'),b=button(entry.title||'Untitled entry',async()=>{if(!canLeave())return;selectedId=entry.id;draw();await openEntry(entry.id,details);feedback();});b.classList.toggle('selected',selectedId===entry.id);item.append(b);list.append(item);}if(!matches.length)list.append(el('li',state.entries.length?'No matching entries.':'No accessible entries.','muted'));};
    filter.oninput=()=>{search=filter.value;draw();controls();};draw();
    if(selectedId&&state.entries.some(e=>e.id===selectedId))await openEntry(selectedId,details);
  }
  controls();
}
function showEntry(payload,id,parent,draft){parent.replaceChildren();const root=parent;root.classList.add('active');document.querySelector('.entries')?.setAttribute('hidden','');document.querySelector('.toolbar')?.setAttribute('hidden','');root.append(button('Back to entries',()=>{selectedId=null;render();}),el('h3',payload.entity.title||'Untitled entry'));for(const credential of payload.entity.credentials??[]){if(credential.type==='basic-auth'){const username=field(root,'Username',credential.username?.value??'');username.readOnly=true;const password=field(root,'Password',credential.password?.value??'','password');password.readOnly=true;root.append(button('Show / hide',()=>{password.type=password.type==='password'?'text':'password';feedback();}),button('Copy password',async()=>{await navigator.clipboard.writeText(password.value);feedback('Password copied.','success');}));}else if(credential.type==='passkey')root.append(el('p',`Passkey · ${credential.rpId??'website'}`));else root.append(el('p',credential.type,'muted'));}for(const origin of payload.entity.scope?.urls??[])root.append(el('p',origin,'fingerprint'));root.append(button('Edit entry',()=>{edit(payload,id,parent,draft);feedback();},true));}
function newPayload(origin='') {const id=random(16);return {format:'kagitaba-cxf',version:1,cxfVersion:{major:1,minor:0},kind:'item',entity:{id:encode(id),title:'New login',credentials:[{type:'basic-auth',username:{fieldType:'string',value:''},password:{fieldType:'concealed-string',value:''}}],scope:{urls:origin?[origin]:[],androidApps:[]}}};}
function edit(payload,id,parent,draft=null,captured=null) {
  parent.replaceChildren();const root=parent;
  root.classList.add('active');document.querySelector('.entries')?.setAttribute('hidden','');document.querySelector('.toolbar')?.setAttribute('hidden','');
  root.append(el('h3',id?'Edit entry':'New login'));root.addEventListener('input',()=>{dirty=true;});
  const title=field(root,'Title',payload.entity.title ?? '');
  const basic=payload.entity.credentials?.find(c=>c.type==='basic-auth');
  let username,password,urls;
  if(basic){username=field(root,'Username',captured?.username??basic.username?.value??'');password=field(root,'Password',captured?.password??basic.password?.value??'','password');root.append(button('Show / hide password',()=>{password.type=password.type==='password'?'text':'password';}));urls=field(root,'Website URLs (one per line)',(payload.entity.scope?.urls??[]).join('\n'),'textarea');}
  if(captured)dirty=true;
  root.append(el('p',id?'Changes stay in the wallet; they do not change your password at the website.':'Only this installation receives access.','muted'));
  const advanced=el('details');advanced.append(el('summary','Advanced: CXF payload'));const json=field(advanced,'CXF envelope',draft?.payload??JSON.stringify(payload,null,2),'textarea');root.append(advanced);let rawChanged=false;json.oninput=()=>rawChanged=true;
  root.append(button('Save entry',async()=>{
    const entryId=id??hex(decode(payload.entity.id));
    const changes={};
    if(title.value!==payload.entity.title)changes.title=title.value;
    if(basic){const login={};if(username.value!==(basic.username?.value??''))login.username=username.value;if(password.value!==(basic.password?.value??''))login.password=password.value;if(urls.value!==(payload.entity.scope?.urls??[]).join('\n'))login.urls=urls.value.split('\n').map(s=>s.trim()).filter(Boolean).map(value=>{const u=new URL(value);if(u.protocol!=='https:')throw Error('Use HTTPS website URLs');return value;});changes.login=login;}
    await send({type:'save',id:entryId,payload:json.value,expectedPrimary:draft?.primary??null,...(!rawChanged?{changes}:{})});
    dirty=false;selectedId=entryId;await render();feedback('Entry saved.','success');
  },true));
  root.append(button('Cancel',async()=>{if(!canLeave())return;await render();feedback();}));
  if(id)root.append(button('Delete entry',async()=>{if(!confirm('Delete this entry? Signed history retains old revisions.'))return;await send({type:'delete',id});dirty=false;selectedId=null;await render();feedback('Entry deleted.','success');}));
}
function renderConnect() {
  const enrollment=section('2 · Enroll in your wallet');enrollment.append(el('p','Import this request on your computer, grant entry access, then push.'),button('Export participant request',async()=>{download('kagitaba-participant.json',await send({type:'participant'}));feedback('Request exported.','success');}));
  const node=section('3 · Connect repository');
  const url=field(node,'HTTPS Git remote URL',connectionDraft.url??''),username=field(node,'Remote username',connectionDraft.username??''),password=field(node,'Remote token / password',connectionDraft.password??'','password');
  url.placeholder='https://github.com/you/wallet.git';username.autocomplete='username';password.autocomplete='off';
  const remember=check(node,'Remember credentials, encrypted on this installation',connectionDraft.remember??true),auto=check(node,'Automatically synchronize after unlocking and saving',connectionDraft.autoSync??true);
  for(const [key,input] of Object.entries({url,username,password}))input.oninput=()=>{connectionDraft[key]=input.value;};
  remember.onchange=()=>{connectionDraft.remember=remember.checked;};auto.onchange=()=>{connectionDraft.autoSync=auto.checked;};
  node.append(button('Connect remote',async()=>{connectionDraft={url:url.value,username:username.value,password:password.value,remember:remember.checked,autoSync:auto.checked};if(!state.unlocked&&connectionDraft.remember)await unlock();feedback('Connecting and verifying wallet history…','progress');const result=await send({type:'connect',options:{...connectionDraft,url:connectionDraft.url.trim()}});connectionDraft={};password.value='';await render();feedback(result?.warning??'Wallet connected. Your connection settings are ready.',result?.warning?'info':'success');},true));
  node.append(el('p','The first connection trusts this repository. Later updates are checked against its saved signing key and history.','muted'));
  const offline=el('details');offline.append(el('summary','Import a signed transfer instead'));node.append(offline);
  const root=field(offline,'Trusted root signing public key (PEM)','','textarea'),checkpoint=field(offline,'Trusted commit checkpoint (40 hexadecimal characters)');
  const file=field(offline,'Signed transfer','','file');file.accept='.json';offline.append(button('Import transfer',async()=>{if(!file.files[0]||file.files[0].size>512*1024*1024)throw new Error('Select a bounded transfer file');const bundle=JSON.parse(await file.files[0].text());if(!/^[0-9a-f]{40}$/.test(checkpoint.value))throw new Error('Enter the independently verified checkpoint');await send({type:'import',bundle:bundle.wallet??bundle,trust:{root:root.value,checkpoint:checkpoint.value}});await render();}));
}
async function synchronize(){if(!canLeave())return;if(!state.unlocked)await unlock();feedback('Fetching and verifying wallet updates…','progress');const result=await send({type:'sync'});await render();feedback(result.warning??(result.outcome==='pulled'?'Downloaded and verified wallet updates.':result.outcome==='pushed'?'Your saved changes are synchronized.':'Wallet is up to date.'),result.warning?'info':'success');}
function renderSyncBar(){const bar=el('div',undefined,'syncbar'),summary=el('div'),status=state.replica.lastSync,pending=state.replica.synced!==state.replica.head;summary.append(el('strong',status?.error?'Synchronization needs attention':pending?'Changes saved on this device':'Wallet synchronized'));summary.append(el('div',status?.error??(state.replica.syncedAt?`Last sync: ${new Date(state.replica.syncedAt).toLocaleString()}`:pending?'Synchronize to back up your changes.':'Ready to use.'),'muted'));bar.append(summary);if(state.replica.remote)bar.append(button(state.unlocked?'Synchronize':'Unlock & synchronize',synchronize,true));else bar.append(button('Set up synchronization',()=>navigate('settings')));app.append(bar);}
function renderSync() {
  if(view==='settings'){
    const node=section('Settings'),actions=el('div',undefined,'workflow-actions');
    for(const [key,label] of [['connection','Repository connection'],['participants','Participant names'],['backups','Backups & identity']])actions.append(button(label,()=>navigate(key)));
    node.append(actions);return;
  }
  app.append(button('← Back to settings',()=>navigate('settings')));
  if(view==='participants'){
  const people = section('Participant names');
  people.append(el('p', 'Encrypted names are shared with all participants.', 'muted'));
  for (const participant of state.participants ?? []) {
    const row = el('div'); people.append(row);
    row.append(el('strong', `${participant.name || 'Unnamed participant'} · ${participant.id.slice(0,16)}…`), el('p', participant.id, 'fingerprint'));
    const name = field(row, 'Friendly name · leave empty to remove', participant.name); name.maxLength = 128;
    name.oninput=()=>{dirty=true;};
    row.append(button('Save name', async () => {if (!state.unlocked) await unlock(); await send({type:'name-participant',id:participant.id,name:name.value.trim()});dirty=false; await render(); feedback('Name saved.', 'success');}));
  }
  return;
  }
  if(view==='connection'){
  const saved=state.remoteAuth??{},node=section('Repository connection');
  const url=field(node,'HTTPS Git remote URL',settingsDraft.url??state.replica.remote??''),username=field(node,'Remote username',settingsDraft.username??saved.username??''),password=field(node,'Remote token / password',settingsDraft.password??'','password');password.autocomplete='off';password.placeholder=saved.hasToken?'Saved securely · leave blank to keep':'Enter your access token';
  const remember=check(node,'Remember credentials, encrypted on this installation',settingsDraft.remember??(saved.username?saved.remember:true)),auto=check(node,'Automatically synchronize after unlocking and saving',settingsDraft.autoSync??saved.autoSync??false);
  const capture=()=>{dirty=true;settingsDraft={url:url.value,username:username.value,password:password.value,remember:remember.checked,autoSync:auto.checked};};for(const input of [url,username,password])input.oninput=capture;remember.onchange=capture;auto.onchange=capture;
  node.append(button('Save connection settings',async()=>{capture();if(!state.unlocked)await unlock();if(settingsDraft.url.trim()!==state.replica.remote)await send({type:'remote',url:settingsDraft.url.trim()});await send({type:'remote-auth',username:settingsDraft.username,password:settingsDraft.password,remember:settingsDraft.remember,autoSync:settingsDraft.autoSync});settingsDraft={};dirty=false;await render();feedback('Connection settings saved.','success');},true));
  return;
  }
  const backups=section('Wallet backups');backups.append(el('p','Backups contain signed encrypted wallet history. Browser identity stays on this installation; reinstalling requires new enrollment.','muted'),button('Export encrypted backup',async()=>{download('kagitaba-wallet-backup.json',await send({type:'export'}));feedback('Encrypted backup exported.','success');}));
  const offline=disclosure(backups,'Import a newer signed transfer'),file=field(offline,'Signed transfer','','file');offline.append(button('Accept verified update',async()=>{if(!file.files[0]||file.files[0].size>512*1024*1024)throw new Error('Select a bounded transfer file');const bundle=JSON.parse(await file.files[0].text());await send({type:'import',bundle:bundle.wallet??bundle,trust:{}});await render();feedback('Verified wallet update imported. Unlock to see your entries.','success');}));
  const installation=section('This installation');installation.append(button('Export participant request',async()=>{download('kagitaba-participant.json',await send({type:'participant'}));feedback('Participant request exported.','success');}));const technical=disclosure(installation,'Public fingerprints & trusted history');technical.append(el('p',`Participant: ${state.installation.participantId}`,'fingerprint'),el('p',`Signing key: ${state.installation.signingId}`,'fingerprint'),el('p',`Accepted commit: ${state.replica.head}`,'fingerprint'));
}
async function renderWebsite() {
  let matches;try{matches=await send({type:'matches',tabId});}catch{return;}
  const node=section(`Website: ${matches.origin}`);
  for(const entry of matches.entries)node.append(button(`Fill ${entry.title}`,async()=>{await send({type:'fill',tabId,id:entry.id});feedback('Filled the selected website. The form was not submitted.','success');},true));
  node.append(button('Save login from this page',async()=>{const captured=await send({type:'capture',tabId});const area=el('div');node.append(area);if(matches.entries.length){const select=el('select');select.append(new Option('New entry',''));for(const entry of matches.entries)select.append(new Option(`Update ${entry.title}`,entry.id));area.append(select,button('Continue',async()=>{const id=select.value||null;const draft=id?await send({type:'entry-draft',id}):null;edit(draft?JSON.parse(draft.payload):newPayload(captured.origin),id,area,draft,captured);}));}else edit(newPayload(captured.origin),null,area,null,captured);}));
}
async function renderRequest() {
  const request=await send({type:'request',requestId});const node=section(request.kind==='create'?'Create a passkey':'Use a passkey');
  node.append(el('p',request.origin),el('p',`Relying party: ${request.rpId}`,'fingerprint'));
  if(!state.unlocked)node.append(button('Unlock wallet',unlock,true));
  else if(request.kind==='create'){node.append(el('p',`Account: ${request.username}`));node.append(button('Verify with security key and create',async()=>{const proof=await assertion(state.installation.unlock);await send({type:'approve',requestId,...proof});requestFinished=true;app.replaceChildren(el('h2','Passkey created'),el('p','Return to the website to continue.'));feedback('Passkey created successfully.','success');},true));}
  else {if(!request.accounts.length)node.append(el('p','No accessible passkey matches this request. Use Firefox or another authenticator below.'));for(const account of request.accounts)node.append(button(`Verify and use ${account.title}`,async()=>{const proof=await assertion(state.installation.unlock);await send({type:'approve',requestId,entryId:account.entryId,credentialId:account.credentialId,...proof});requestFinished=true;app.replaceChildren(el('h2','Response sent'),el('p','Return to the website to continue.'));feedback('Signed response sent to the website.','success');},true));}
  node.append(button('Use Firefox / another authenticator',async()=>{await send({type:'approve',requestId,fallback:true});window.close();}));
}
document.querySelector('#lock').onclick=async()=>{try{await send({type:'lock'});}catch{feedback('Unable to lock wallet.','error');}};
browser.runtime.onMessage.addListener(message=>{
  if(message.type==='active-site'&&!requestId&&!dirty&&!busy){tabId=message.tabId;selectedId=null;render().catch(()=>{});}
  if(message.type==='locked'){if(message.reason!=='connect'){connectionDraft.password='';settingsDraft.password='';}uiEpoch++;renderVersion++;dirty=false;selectedId=null;app.replaceChildren();document.querySelectorAll('dialog').forEach(dialog=>dialog.remove());render().catch(()=>{});if(!busy)feedback('Wallet locked.');}
  if(message.type==='sync-progress'){const phases={fetching:'Fetching wallet updates…',verifying:'Verifying signed wallet history…',pushing:'Uploading encrypted changes…'};if(phases[message.phase]&&!busy)feedback(phases[message.phase],'progress');}
  if(message.type==='sync-result'&&!busy){feedback(message.error??message.warning??(message.outcome==='pulled'?'Downloaded and verified wallet updates.':message.outcome==='pushed'?'Your saved changes are synchronized.':'Wallet is up to date.'),message.error?'error':message.warning?'info':'success');if(!dirty)render().catch(()=>{});}
});
window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
render().catch(error=>feedback(error.message,'error'));
