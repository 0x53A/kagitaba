import {test} from 'node:test';
import assert from 'node:assert/strict';
import {NativeGateway} from '../src/native.mjs';
function fixture() {
  let receive,disconnected,request,fill,token='one',origin='https://example.com';
  let resolvePosted;const posted=new Promise(resolve=>resolvePosted=resolve);
  const api={runtime:{connectNative(name){assert.equal(name,'kagitaba');return {onMessage:{addListener(f){receive=f;}},onDisconnect:{addListener(f){disconnected=f;}},postMessage(value){request=value;resolvePosted();},disconnect(){disconnected?.();}};}},tabs:{async get(id){return {id,url:origin+'/login'};},async sendMessage(id,value){if(value.type==='probe')return {origin,documentToken:token};fill=value;return true;}}};
  return {gateway:new NativeGateway(api),posted,respond(value={version:1,username:'synthetic',password:'test'}){receive(value);disconnected();},navigate(){token='two';},get request(){return request;},get fill(){return fill;}};
}
test('native fill uses trusted tab context and survives normal host exit',async()=>{
  const f=fixture(),result=f.gateway.fill(7);await f.posted;
  assert.deepEqual(f.request,{version:1,operation:'login',origin:'https://example.com'});
  f.respond();assert.equal(await result,true);assert.equal(f.fill.password,'test');assert.equal(f.fill.documentToken,'one');
});
test('document replacement prevents native response delivery',async()=>{
  const f=fixture(),result=f.gateway.fill(7);await f.posted;f.navigate();f.respond();await assert.rejects(result);assert.equal(f.fill,undefined);
});
test('locking or tab cancellation rejects pending native response',async()=>{
  const f=fixture(),result=f.gateway.fill(7);await f.posted;f.gateway.cancel(7);f.respond();await assert.rejects(result);assert.equal(f.fill,undefined);
});
test('cancellation during context lookup cannot open a native request',async()=>{
  const f=fixture(),result=f.gateway.fill(7);f.gateway.cancel();await assert.rejects(result);assert.equal(f.request,undefined);
});
test('denial and malformed responses never fill',async()=>{
  for(const response of [null,7,"invalid",{version:1,error:'denied'},{version:2,username:'a',password:'b'},{version:1,username:'a'}]){
    const f=fixture(),result=f.gateway.fill(7);await f.posted;f.respond(response);await assert.rejects(result);assert.equal(f.fill,undefined);
  }
});
const passkeyRequest={kind:'get',origin:'https://example.com',input:{challenge:'abc',rpId:'example.com'}};
const publicReply={version:1,credential:{id:'AA',response:{clientDataJSON:'AA',authenticatorData:'AA',signature:'AA',userHandle:'AA',privateKey:'secret'},privateKey:'secret',extensions:{}}};
test('native passkey request forwards options and returns only public fields',async()=>{
  const f=fixture(),result=f.gateway.passkey(7,passkeyRequest,'one','page');await f.posted;
  assert.deepEqual(f.request,{version:1,operation:'passkey',origin:passkeyRequest.origin,kind:'get',input:passkeyRequest.input});
  f.respond(publicReply);const response=await result;
  assert.equal(response.credential.id,'AA');assert.equal(JSON.stringify(response).includes('secret'),false);assert.equal(f.fill,undefined);
});
test('page cancellation is bound to the requesting document and request',async()=>{
  const f=fixture(),result=f.gateway.passkey(7,passkeyRequest,'one','page');await f.posted;
  f.gateway.cancelPage(7,'page','other');assert.equal(f.gateway.pending.size,1);
  f.gateway.cancelPage(7,'page','one');await assert.rejects(result);
});
test('native passkeys reject stale documents and allow explicit Firefox fallback',async()=>{
  const stale=fixture();await assert.rejects(stale.gateway.passkey(7,passkeyRequest,'old','page'));assert.equal(stale.request,undefined);
  const f=fixture(),result=f.gateway.passkey(7,passkeyRequest,'one','page');await f.posted;f.respond({version:1,fallback:true});assert.deepEqual(await result,{fallback:true});
});

test('page abort during context lookup prevents opening the native host',async()=>{
  const f=fixture(),result=f.gateway.passkey(7,passkeyRequest,'one','page');
  f.gateway.cancelPage(7,'page','one');await assert.rejects(result);assert.equal(f.request,undefined);
});
