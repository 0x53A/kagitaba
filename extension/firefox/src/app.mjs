import {collectionNodes} from './wallet-navigation.mjs';
import {cryptoCall} from './crypto.mjs';
import {generator,importTotp,closeTools,copySecret,totpCode} from './credential-tools.mjs';
import {encode, decode, random, hex} from './encoding.mjs';
const app = document.querySelector('#app'), notice = document.querySelector('#notice');
const params = new URLSearchParams(location.search), requestId = params.get('request');
let tabId = Number(params.get('tab'));
async function openEntry(id, parent) {const draft=await send({type:'entry-draft',id});showEntry(JSON.parse(draft.payload),id,parent,draft);}
let state, uiEpoch=0, selectedCollection=null;
let fidoPending;
class FidoLockedError extends Error {constructor(){super('Wallet locked. Unlock to continue.');}}
let connectionDraft = {}, settingsDraft = {}, view = 'wallet', selectedId = null, search = '', dirty = false, busy = false, renderVersion = 0, fieldNumber = 0, requestFinished = false;
const send = async message => {const captured=uiEpoch;const value=await browser.runtime.sendMessage(message);if(captured!==uiEpoch && !['lock','connect','status','sync','backend-mode'].includes(message.type))throw new Error('Wallet locked. Unlock to continue.');return value;};
function el(tag, content, className) {const node = document.createElement(tag); if (content !== undefined) node.textContent = content; if(className) node.className = className; return node;}
function button(label, action, primary = false) {const node = el('button', label, primary ? 'primary' : ''); node.type='button';node.onclick = () => run(action, node); return node;}
function field(parent, label, value = '', type = 'text') {const caption=el('label',label),input = el(type === 'textarea' ? 'textarea' : 'input');input.id=`field-${++fieldNumber}`;caption.htmlFor=input.id; if(type !== 'textarea') input.type = type; input.value = value; parent.append(caption,input); return input;}
function check(parent,label,value){const row=el('label',undefined,'check'),input=el('input');input.type='checkbox';input.checked=value;row.append(input,el('span',label));parent.append(row);return input;}
function disclosure(parent,title){const node=el('details');node.append(el('summary',title));parent.append(node);return node;}
function feedback(text='',kind='info'){notice.textContent=text;notice.dataset.kind=kind;notice.hidden=!text;}
function fidoPrompt(){feedback('','progress');notice.hidden=false;notice.append('Waiting for security-key confirmation. Follow Firefox’s prompt: enter your ',el('strong','FIDO PIN'),' and touch the key when requested. Firefox controls the PIN and touch prompts.');}
function fidoInstructions(){const node=el('p');node.append('Connect your security key. Firefox will ask for its ',el('strong','FIDO PIN'),' and a touch.');return node;}
async function fidoRequest(method, options){
  const epoch=uiEpoch, controller=new AbortController();fidoPending=controller;fidoPrompt();
  try{const credential=await navigator.credentials[method]({...options,signal:controller.signal});if(epoch!==uiEpoch)throw new FidoLockedError();return credential;}
  catch(error){if(epoch!==uiEpoch)throw new FidoLockedError();throw error;}
  finally{if(fidoPending===controller)fidoPending=undefined;}
}
function controls(){app.setAttribute('aria-busy',String(busy));for(const b of document.querySelectorAll('#app button, #header-refresh button, #header-tools button'))b.disabled=busy&&!b.dataset.cancelNative;}
function canLeave(){if(dirty&&!confirm('Discard your unsaved changes?'))return false;dirty=false;return true;}
async function navigate(next){if(!canLeave())return;view=next;selectedId=null;await render();feedback();}
function section(title) {const node = el('section'); node.append(el('h2', title)); app.append(node); return node;}
async function run(action, control) {if(busy)return;busy=true;controls();feedback(`${control?.textContent??'Working'}…`,'progress');try{await action();if(notice.dataset.kind==='progress')feedback('Done.','success');}catch(error){if(!(error instanceof FidoLockedError))feedback(error.message||'Operation failed. Please retry.','error');}finally{busy=false;controls();}}
function download(name, value) {const url = URL.createObjectURL(new Blob([JSON.stringify(value)],{type:'application/json'})); const link = el('a'); link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
async function assertion(unlock) {
  const credential = await fidoRequest('get',{publicKey: {rpId: unlock.rpId, challenge: random(32), allowCredentials: [{type:'public-key',id:decode(unlock.credentialId)}], userVerification:'required', timeout:120000, extensions:{prf:{eval:{first:decode(unlock.prfInput)}}}}});
  const output = credential?.getClientExtensionResults()?.prf?.results?.first;
  if (!output || !(new Uint8Array(credential.response.authenticatorData)[32] & 4)) throw new Error('This browser/key did not provide PRF with user verification. No alternative unlock is used.');
  return {prf: encode(output), uv:true};
}
async function setup() {
  const rpId = 'kagitaba.local', prfInput = encode(random(32));
  const credential = await fidoRequest('create',{publicKey:{rp:{id:rpId,name:'Kagitaba wallet unlock'},user:{id:random(32),name:`Firefox ${new Date().toISOString().slice(0,10)}`,displayName:'Kagitaba installation'},challenge:random(32),pubKeyCredParams:[{type:'public-key',alg:-7}],authenticatorSelection:{residentKey:'discouraged',requireResidentKey:false,userVerification:'required',authenticatorAttachment:'cross-platform'},attestation:'none',timeout:120000,extensions:{prf:{eval:{first:decode(prfInput)}}}}});
  if (!credential) throw new Error('Security key enrollment cancelled');
  const unlock = {rpId,prfInput,credentialId:encode(credential.rawId)};
  const proof = await assertion(unlock);
  await send({type:'setup',unlock,...proof}); await render();
}
async function unlock() {const proof=await assertion(state.installation.unlock);await send({type:'unlock',...proof});await render();feedback('Wallet unlocked.','success');}
async function render() {
  if(requestFinished)return;
  const version=++renderVersion,next=await send({type:'status'});if(version!==renderVersion)return;state=next;closeTools();app.replaceChildren();
  document.querySelector('#lock').hidden=!state.unlocked;
  document.querySelector('#header-name').textContent=state.backendMode==='native'?'Native app':state.replica.head?'Browser wallet':'';
  const status=document.querySelector('#header-state'), refresh=document.querySelector('#header-refresh'), tools=document.querySelector('#header-tools');
  status.textContent=state.unlocked?'Unlocked':'Locked';refresh.replaceChildren();tools.replaceChildren();
  if(state.replica.head&&state.backendMode!=='native'){
    status.textContent=state.replica.lastSync?.error?'Sync failed':state.replica.synced!==state.replica.head?'Pending changes':'Synchronized';
    status.title=state.replica.lastSync?.error??(state.replica.syncedAt?new Date(state.replica.syncedAt).toLocaleString():'');
    if(state.replica.remote){const sync=button('↻',synchronize);sync.classList.add('icon');sync.title=state.unlocked?'Synchronize':'Unlock & synchronize';sync.setAttribute('aria-label',sync.title);refresh.append(sync);}
  }
  if(!requestId){
    const menu=disclosure(tools,'Tools');
    menu.append(button('Password generator',()=>generator()));
    menu.append(button(state.backendMode==='native'?'Use standalone wallet':'Use native client',async()=>{if(!canLeave())return;await send({type:'backend-mode',mode:state.backendMode==='native'?'standalone':'native'});await render();}));
  }
  if(state.backendMode==='native'&&!requestId){
    document.querySelector('#header-state').textContent='Native client';
    const node=section('Use your native wallet');
    node.append(el('p','Open and unlock the native app.','muted'));
    if(tabId)node.append(button('Choose login in native client',async()=>{feedback('Waiting for approval in the native client…','progress');await send({type:'native-fill',tabId});feedback('Login filled. The form was not submitted.','success');},true));
    else node.append(el('p','Open this window from the toolbar on an HTTPS website.','muted'));
    const cancel=el('button','Cancel request');cancel.type='button';cancel.dataset.cancelNative='true';cancel.onclick=()=>browser.runtime.sendMessage({type:'native-cancel'});node.append(cancel);
    controls();return;
  }
  if(!state.installation){
    if(view==='enrollment'){
      app.append(button('← Back',()=>navigate('wallet')));
      const node=section('Create enrollment request');node.append(fidoInstructions(),button('Enroll security key',setup,true));
    }else{
      const node=section('Open wallet');
      node.append(button('Use native client',async()=>{await send({type:'backend-mode',mode:'native'});await render();},true),button('Create enrollment request',()=>navigate('enrollment')));
    }
    controls();return;
  }
  if(requestId){await renderRequest();return;}
  if(!state.replica.head){renderConnect();return;}
  const nav=el('nav',undefined,'tabs');nav.setAttribute('aria-label','Wallet navigation');for(const [key,label] of [['wallet','Wallet'],['settings','Settings']]){const b=button(label,()=>navigate(key));b.setAttribute('aria-current',String(key==='wallet'?view==='wallet':view!=='wallet'));nav.append(b);}app.append(nav);
  if(view!=='wallet'){renderSync();controls();return;}
  if(!state.unlocked){const top=section('Unlock wallet');top.append(button('Unlock with security key',unlock,true));controls();return;}
  if(state.unlocked){
    if(tabId)await renderWebsite();
    const workspace=section('Entries'),toolbar=el('div',undefined,'toolbar'),filter=el('input');filter.type='search';filter.placeholder='Search entries';filter.setAttribute('aria-label','Search entries');filter.value=search;
    const layout=el('div',undefined,'layout'),list=el('ul',undefined,'entries'),details=el('div',undefined,'entry-detail'),tree=el('nav',undefined,'collection-tree'),content=el('div',undefined,'collection-content'),columns=el('div',undefined,'collection-columns');
    tree.setAttribute('aria-label','Collections');layout.append(list,details);content.append(toolbar,layout);columns.append(tree,content);toolbar.append(filter,button('New login',()=>{if(canLeave())edit(newPayload(),null,details);},true));workspace.append(columns);
    const nodes=collectionNodes(state.entries);if(selectedCollection&&selectedCollection!=='unfiled'&&!nodes.some(n=>n.key===selectedCollection))selectedCollection=null;
    const choose=key=>{if(!canLeave())return;selectedCollection=key;selectedId=null;render();};
    tree.append(el('h3','Collections'));const all=button('All entries',()=>choose(null));all.setAttribute('aria-current',String(selectedCollection===null));tree.append(all);const unfiled=button('Entries not in a collection',()=>choose('unfiled'));unfiled.setAttribute('aria-current',String(selectedCollection==='unfiled'));tree.append(unfiled);
    for(const node of nodes){const row=button(node.title,()=>choose(node.key));row.style.paddingInlineStart=`${12+node.depth*14}px`;row.setAttribute('aria-current',String(selectedCollection===node.key));tree.append(row);}
    keepCollectionVisible();
    const draw=()=>{list.replaceChildren();const node=nodes.find(n=>n.key===selectedCollection),items=state.entries.filter(e=>e.kind==='item'),matches=items.filter(e=>(selectedCollection==='unfiled'?!nodes.some(n=>n.items.includes(e.id)):!node||node.items.includes(e.id))&&[e.title,...(e.usernames??[]),e.id].some(v=>v.toLowerCase().includes(search.toLowerCase())));
      if(node?.unavailable)list.append(el('li',`${node.unavailable} unavailable or external links`,'muted collection-status'));
      for(const entry of matches){const item=el('li'),b=button('',async()=>{if(!canLeave())return;selectedId=entry.id;draw();await openEntry(entry.id,details);feedback();});b.append(el('strong',entry.title||'Untitled entry'),el('span',(entry.usernames??[]).join(' · '),'entry-usernames'),Object.assign(el('span',entry.id.slice(0,8),'entry-id'),{title:entry.id}));b.classList.toggle('selected',selectedId===entry.id);item.append(b);list.append(item);}
      if(!matches.length)list.append(el('li',search?'No matching entries.':node?'No accessible entries in this collection.':'No accessible entries.','muted'));};
    filter.oninput=()=>{search=filter.value;draw();controls();};draw();
    if(selectedId&&state.entries.some(e=>e.id===selectedId))await openEntry(selectedId,details);
  }
  controls();
}
function showEntry(payload,id,parent,draft){
 parent.replaceChildren();const root=parent;root.classList.add('active');document.querySelector('.entries')?.setAttribute('hidden','');document.querySelector('.toolbar')?.setAttribute('hidden','');
 root.append(button('Back to entries',()=>{selectedId=null;render();}),el('h3',payload.entity.title||'Untitled entry'));
 for(const c of payload.entity.credentials??[]){
  const group=el('div',undefined,'credential-group');root.append(group);
  if(c.type==='basic-auth'){
   const username=field(group,'Username',c.username?.value??'','textarea');username.readOnly=true;
   const password=field(group,'Password',c.password?.value??'','textarea');password.readOnly=true;password.hidden=true;
   group.append(button('Show / hide',()=>{password.hidden=!password.hidden;}),button('Copy password',()=>copySecret(c.password?.value??'')));
  }else if(c.type==='totp'){group.append(el('p',`TOTP · ${c.issuer??''} · ${c.username??''}`),button('Show TOTP code',()=>totpCode(c)));}
  else if(c.type==='note'){const value=field(group,'Note',c.content?.value??'','textarea');value.readOnly=true;value.hidden=true;group.append(button('Show / hide note',()=>{value.hidden=!value.hidden;}));}
  else if(c.type==='passkey'){
   group.append(el('h3','Passkey'));
   for(const [label,key,secret] of [['Relying party','rpId'],['Username','username'],['Display name','userDisplayName'],['Credential ID','credentialId'],['User handle','userHandle',true]]){
    if(typeof c[key]!=='string'||!c[key])continue;
    const value=field(group,label,secret?'••••••••':c[key],'textarea');value.readOnly=true;
    if(secret){let visible=false;group.append(button('Show / hide',()=>{visible=!visible;value.value=visible?c[key]:'••••••••';}));}
    group.append(button(`Copy ${label.toLowerCase()}`,()=>copySecret(c[key])));
   }
   for(const [label,key] of [['Backup eligible','eligible'],['Backed up','state']]){
    const flag=c.kagitabaBackupFlags?.[key];group.append(el('p',label,'muted'),el('p',flag===undefined?'Not recorded':flag===true?'Yes':flag===false?'No':'Invalid'));
   }
  }else group.append(el('p',c.type,'muted'));
 }
 for(const url of payload.entity.scope?.urls??[])root.append(el('p',url,'fingerprint'));
 root.append(button('Edit entry',()=>{edit(payload,id,parent,draft);feedback();},true));
}
function newPayload(origin='') {const id=random(16);return {format:'kagitaba-cxf',version:1,cxfVersion:{major:1,minor:0},kind:'item',entity:{id:encode(id),title:'New login',credentials:[{type:'basic-auth',username:{fieldType:'string',value:''},password:{fieldType:'concealed-string',value:''}}],scope:{urls:origin?[origin]:[],androidApps:[]}}};}
function edit(payload,id,parent,draft=null,captured=null) {
  parent.replaceChildren();const root=parent;
  root.classList.add('active');document.querySelector('.entries')?.setAttribute('hidden','');document.querySelector('.toolbar')?.setAttribute('hidden','');
  root.append(el('h3',id?'Edit entry':'New login'));root.addEventListener('input',()=>{dirty=true;});
  const title=field(root,'Title',payload.entity.title ?? '');
  const logins=[];
  for(const [index,basic] of (payload.entity.credentials??[]).entries()){
    if(basic.type!=='basic-auth')continue;
    const username=field(root,'Username',captured?.username??basic.username?.value??'','textarea');
    const password=field(root,'Password',captured?.password??basic.password?.value??'','textarea');password.hidden=true;
    root.append(button('Show / hide password',()=>{password.hidden=!password.hidden;}),button('Generate…',()=>generator(value=>{password.value=value;dirty=true;})));
    logins.push({index,basic,username,password});
  }
  const urlRows=[];const urlsRoot=el('section',undefined,'url-table');urlsRoot.append(el('h4','URLs'));const urlBody=el('div');urlsRoot.append(urlBody);root.append(urlsRoot);
  const addUrl=value=>{
    const row=el('div',undefined,'url-row'),input=el('input');input.type='text';input.value=value;input.setAttribute('aria-label','URL');
    const record={input,removed:false};urlRows.push(record);
    const copy=button('Copy',()=>copySecret(input.value));copy.setAttribute('aria-label','Copy URL');
    const remove=button('×',()=>{record.removed=true;row.remove();dirty=true;});remove.setAttribute('aria-label','Remove URL');
    row.append(input,copy,remove);urlBody.append(row);
  };
  for(const value of payload.entity.scope?.urls??[])addUrl(value);
  const addUrlButton=button('+ URL',()=>{addUrl('');dirty=true;});addUrlButton.classList.add('url-add');urlsRoot.append(addUrlButton);
  const appended=[];
  root.append(button('Add login',()=>{const c={type:'basic-auth',username:{fieldType:'string',value:''},password:{fieldType:'concealed-string',value:''}};appended.push(c);const username=field(root,'New username','','textarea'),password=field(root,'New password','','textarea');password.hidden=true;username.oninput=()=>c.username.value=username.value;password.oninput=()=>c.password.value=password.value;root.append(button('Show / hide password',()=>{password.hidden=!password.hidden;}),button('Generate…',()=>generator(v=>{password.value=v;c.password.value=v;dirty=true;})));dirty=true;}));
  const notes=[];
  for(const [index,c] of (payload.entity.credentials??[]).entries())if(c.type==='note'){
    const input=field(root,'Note',c.content?.value??'','textarea');input.hidden=true;root.append(button('Show / hide note',()=>{input.hidden=!input.hidden;}));notes.push({index,c,input});
  }
  root.append(button('Add note',()=>{const c={type:'note',content:{fieldType:'string',value:''}};appended.push(c);const input=field(root,'New note','','textarea');input.oninput=()=>{c.content.value=input.value;dirty=true;};dirty=true;}));
  const customFields=[];
  for(const [index,c] of (payload.entity.credentials??[]).entries())if(c.type==='custom-fields'){
    root.append(el('h4','Custom fields'));
    for(const [fieldIndex,f] of (c.fields??[]).entries()){
      const label=typeof f.label==='string'?f.label:'Unnamed field';
      if(typeof f.value!=='string')continue;
      if(f.fieldType==='boolean' && ['true','false'].includes(f.value)){
        const input=check(root,label,f.value==='true');input.onchange=()=>{dirty=true;};customFields.push({index,fieldIndex,f,input,boolean:true});
      }else if(['string','concealed-string'].includes(f.fieldType)){
        const concealed=f.fieldType==='concealed-string'||label.trim().toLowerCase()==='pin';
        const input=field(root,label,f.value,concealed?'password':'text');
        if(concealed)root.append(button('Show / hide',()=>{input.type=input.type==='password'?'text':'password';}));
        customFields.push({index,fieldIndex,f,input,boolean:false});
      }else root.append(el('p',`${label} · ${f.fieldType??''}`,'muted'));
    }
  }
  const totps=[];
  for(const [index,c] of (payload.entity.credentials??[]).entries())if(c.type==='totp'){
    const fields={};for(const name of ['secret','algorithm','period','digits','issuer','username'])fields[name]=field(root,`TOTP ${name}`,String(c[name]??''),name==='secret'?'password':'text');totps.push({index,c,fields});
    root.append(button('Show current code',()=>totpCode(c)));
  }
  root.append(button('Import TOTP (camera / picture / URI)',()=>importTotp(c=>{appended.push(c);root.append(el('p',`TOTP ready to save · ${c.issuer??''} · ${c.username??''}`));dirty=true;})));
  if(captured)dirty=true;
  root.append(el('p',id?'Changes stay in the wallet; they do not change your password at the website.':'Only this installation receives access.','muted'));
  const advanced=el('details');advanced.append(el('summary','Advanced: CXF payload'));const json=field(advanced,'CXF envelope',draft?.payload??JSON.stringify(payload,null,2),'textarea');root.append(advanced);let rawChanged=false;json.oninput=()=>rawChanged=true;
  root.append(button('Save entry',async()=>{
    const entryId=id??hex(decode(payload.entity.id));
    const changes={};
    if(title.value!==payload.entity.title)changes.title=title.value;
    changes.logins=logins.map(({index,basic,username,password})=>({index,...(username.value!==(basic.username?.value??'')?{username:username.value}:{}),...(password.value!==(basic.password?.value??'')?{password:password.value}:{})}));
    const urls=urlRows.filter(r=>!r.removed).map(r=>r.input.value);if(JSON.stringify(urls)!==JSON.stringify(payload.entity.scope?.urls??[]))changes.urls=urls;
    changes.appendCredentials=appended;
    changes.customFields=customFields.map(({index,fieldIndex,f,input,boolean})=>({index,fieldIndex,value:boolean?String(input.checked):input.value,previous:f.value})).filter(p=>p.value!==p.previous).map(({previous,...patch})=>patch);
    changes.notes=notes.filter(({c,input})=>input.value!==(c.content?.value??'')).map(({index,input})=>({index,value:input.value}));
    changes.totps=totps.map(({index,c,fields})=>({index,...Object.fromEntries(Object.entries(fields).filter(([key,input])=>input.value!==String(c[key]??'')).map(([key,input])=>[key,input.value]))}));
    await send({type:'save',id:entryId,payload:json.value,expectedPrimary:draft?.primary??null,...(!rawChanged?{changes}:{})});
    dirty=false;selectedId=entryId;await render();feedback('Entry saved.','success');
  },true));
  root.append(button('Cancel',async()=>{if(!canLeave())return;await render();feedback();}));
  if(id)root.append(button('Delete entry',async()=>{if(!confirm('Delete this entry? Signed history retains old revisions.'))return;await send({type:'delete',id});dirty=false;selectedId=null;await render();feedback('Entry deleted.','success');}));
}
function renderConnect() {
  if(view==='enrollment'){app.append(button('← Back',()=>navigate('wallet')));const enrollment=section('Create enrollment request');enrollment.append(button('Export participant request',async()=>{download('kagitaba-participant.json',await send({type:'participant'}));feedback('Request exported.','success');},true));return;}
  app.append(button('Create enrollment request',()=>navigate('enrollment')));
  const node=section('Open wallet');
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
  node.append(el('p',request.origin,'request-origin'),el('p',`Relying party: ${request.rpId}`,'fingerprint'));
  if(!state.unlocked)node.append(button('Unlock wallet',unlock,true));
  else if(request.kind==='create'){node.append(el('p','Account','field-caption'),el('p',request.username,'credential-value'));node.append(button('Verify with security key and create',async()=>{const proof=await assertion(state.installation.unlock);await send({type:'approve',requestId,...proof});requestFinished=true;app.replaceChildren(el('h2','Passkey created'),el('p','Return to the website to continue.'));feedback('Passkey created successfully.','success');},true));}
  else {if(!request.accounts.length)node.append(el('p','No accessible passkey matches this request. Use Firefox or another authenticator below.'));for(const account of request.accounts)node.append(button(`Verify and use ${account.title}`,async()=>{const proof=await assertion(state.installation.unlock);await send({type:'approve',requestId,entryId:account.entryId,credentialId:account.credentialId,...proof});requestFinished=true;app.replaceChildren(el('h2','Response sent'),el('p','Return to the website to continue.'));feedback('Signed response sent to the website.','success');},true));}
  node.append(button('Use Firefox / another authenticator',async()=>{await send({type:'approve',requestId,fallback:true});window.close();}));
}
document.querySelector('#close').onclick=async()=>{if(!canLeave())return;try{await send({type:'lock'});window.close();}catch{feedback('Unable to lock wallet.','error');}};
document.querySelector('#lock').onclick=async()=>{try{await send({type:'lock'});}catch{feedback('Unable to lock wallet.','error');}};
browser.runtime.onMessage.addListener(message=>{
  if(message.type==='active-site'&&!requestId&&!dirty&&!busy){tabId=message.tabId;selectedId=null;render().catch(()=>{});}
  if(message.type==='locked'){fidoPending?.abort();if(message.reason!=='connect'){connectionDraft.password='';settingsDraft.password='';}closeTools();selectedCollection=null;uiEpoch++;renderVersion++;dirty=false;selectedId=null;app.replaceChildren();document.querySelectorAll('dialog').forEach(dialog=>dialog.remove());render().catch(()=>{});feedback('Wallet locked.');}
  if(message.type==='sync-progress'){const phases={fetching:'Fetching wallet updates…',verifying:'Verifying signed wallet history…',pushing:'Uploading encrypted changes…'};if(phases[message.phase]&&!busy)feedback(phases[message.phase],'progress');}
  if(message.type==='sync-result'&&!busy){feedback(message.error??message.warning??(message.outcome==='pulled'?'Downloaded and verified wallet updates.':message.outcome==='pushed'?'Your saved changes are synchronized.':'Wallet is up to date.'),message.error?'error':message.warning?'info':'success');if(!dirty)render().catch(()=>{});}
});
window.addEventListener('beforeunload',event=>{if(dirty){event.preventDefault();event.returnValue='';}});
render().catch(error=>feedback(error.message,'error'));

function keepCollectionVisible() {
  const tree=document.querySelector('.collection-tree'),active=tree?.querySelector('[aria-current=true]');
  if(!active)return;
  const container=tree.getBoundingClientRect(),row=active.getBoundingClientRect();
  if(row.bottom>container.bottom)tree.scrollTop+=row.bottom-container.bottom;
  else if(row.top<container.top)tree.scrollTop-=container.top-row.top;
}
window.addEventListener('resize',()=>requestAnimationFrame(keepCollectionVisible));
new ResizeObserver(keepCollectionVisible).observe(document.documentElement);
