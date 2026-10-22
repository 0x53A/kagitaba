import {originForSender} from './policy.mjs';
const failure = () => new Error('Native request denied or unavailable. Open and unlock the native client, then retry.');
export class NativeGateway {
  constructor(api) {this.api=api;this.pending=new Map();this.preflights=new Map();this.epoch=0;}
  cancel(tabId) {this.epoch++;for(const [id,cancel] of this.pending)if(tabId===undefined||tabId===id)cancel();}
  cancelPage(tabId, pageId, documentToken) {
    const cancel=this.pending.get(tabId)??this.preflights.get(tabId);
    if(cancel?.pageId===pageId&&cancel?.documentToken===documentToken)this.cancel(tabId);
  }
  async fill(tabId) {return this.exchange(tabId,null);}
  async passkey(tabId, request, documentToken, pageId) {
    if(this.preflights.size)throw failure();
    this.preflights.set(tabId,{pageId,documentToken});
    try{return await this.exchange(tabId,{request,documentToken,pageId});}
    finally{this.preflights.delete(tabId);}
  }
  async exchange(tabId, passkey) {
    if(this.pending.size)throw failure();
    const epoch=this.epoch;
    const tab=await this.api.tabs.get(tabId);
    const origin=originForSender({tab,frameId:0,url:tab.url});
    const probe=await this.api.tabs.sendMessage(tabId,{type:'probe'},{frameId:0});
    if(epoch!==this.epoch||this.pending.size||probe.origin!==origin||typeof probe.documentToken!=='string')throw failure();
    if(passkey&&(passkey.documentToken!==probe.documentToken||passkey.request.origin!==origin))throw failure();
    const port=this.api.runtime.connectNative('kagitaba');
    let cancelled=false, cancel;
    const response=new Promise((resolve,reject)=>{
      let settled=false;
      const finish=(value,error)=>{if(settled)return;settled=true;clearTimeout(timer);error?reject(failure()):resolve(value);};
      const timer=setTimeout(()=>cancel(),90000);
      cancel=()=>{cancelled=true;finish(null,true);port.disconnect();};
      if(passkey){cancel.pageId=passkey.pageId;cancel.documentToken=passkey.documentToken;}
      this.pending.set(tabId,cancel);
      port.onDisconnect.addListener(()=>{if(!settled){cancelled=true;finish(null,true);}});
      port.onMessage.addListener(value=>finish(value,false));
      try{port.postMessage(passkey?{version:1,operation:'passkey',origin,kind:passkey.request.kind,input:passkey.request.input}:{version:1,operation:'login',origin});}catch{cancel();}
    });
    let value;
    try {
      value=await response;
      if(value?.version!==1||value.error||(!passkey&&(typeof value.username!=='string'||typeof value.password!=='string'||value.username.length+value.password.length>65536)))throw failure();
      const current=await this.api.tabs.get(tabId);
      if(new URL(current.url).origin!==origin)throw failure();
      const now=await this.api.tabs.sendMessage(tabId,{type:'probe'},{frameId:0});
      if(cancelled||now.origin!==origin||now.documentToken!==probe.documentToken)throw failure();
      if(passkey)return publicResponse(value,passkey.request.kind);
      await this.api.tabs.sendMessage(tabId,{type:'fill',origin,documentToken:probe.documentToken,username:value.username,password:value.password},{frameId:0});
      return true;
    } finally {
      if(value&&typeof value==='object'){value.username='';value.password='';}
      this.pending.delete(tabId);port.disconnect();
    }
  }
}

// Only public WebAuthn response fields cross into the page.
function publicResponse(value,kind) {
  if(value.fallback===true)return {fallback:true};
  const source=value.credential, response={};
  const binary=value=>typeof value==='string'&&value.length>0&&value.length<=65536&&/^[A-Za-z0-9_-]+$/.test(value);
  if(!binary(source?.id))throw failure();
  const fields=kind==='create'?['clientDataJSON','authenticatorData','attestationObject','publicKey']:['clientDataJSON','authenticatorData','signature','userHandle'];
  for(const key of fields){if(!binary(source.response?.[key]))throw failure();response[key]=source.response[key];}
  const extensions={};
  if(kind==='create'&&source.extensions?.credProps?.rk===true)extensions.credProps={rk:true};
  return {credential:{id:source.id,response,extensions}};
}
