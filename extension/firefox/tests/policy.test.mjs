import test from 'node:test';
import assert from 'node:assert/strict';
import {validateRequest,matchesOrigin,Epoch} from '../src/policy.mjs';
import {encode} from '../src/encoding.mjs';
const sender={tab:{id:3},frameId:0,url:'https://login.example.com/account'};
const request={challenge:encode(new Uint8Array(32)),rpId:'example.com'};
test('uses actual sender origin and bounds RP to registrable parent',()=>{
  assert.equal(validateRequest('get',{...request,origin:'https://evil.com'},sender).origin,'https://login.example.com');
  for(const rpId of ['com','evil.com','ample.com','example.com.','EXAMPLE.COM','github.io'])assert.throws(()=>validateRequest('get',{...request,rpId},sender));
  assert.throws(()=>validateRequest('get',request,{...sender,frameId:1}));
  assert.throws(()=>validateRequest('get',request,{...sender,url:'http://login.example.com'}));
});
test('rejects malformed request lists, extensions, and unsupported algorithms',()=>{
  assert.throws(()=>validateRequest('get',{...request,challenge:'!'},sender));
  assert.throws(()=>validateRequest('get',{...request,extensions:{prf:{}}},sender));
  assert.throws(()=>validateRequest('get',{...request,allowCredentials:[{type:'password',id:'AA'}]},sender));
  assert.throws(()=>validateRequest('create',{...request,rp:{id:'example.com'},user:{id:'AA',name:'test'},pubKeyCredParams:[{type:'public-key',alg:-257}]},sender));
});
test('password matching is exact origin, no URL prefix or subdomain broadening',()=>{
  const payload={entity:{scope:{urls:['https://example.com/login']}}};
  assert.ok(matchesOrigin(payload,'https://example.com'));
  for(const origin of ['https://example.com.evil.test','https://sub.example.com','http://example.com','https://example.com:444'])assert.equal(matchesOrigin(payload,origin),false);
  assert.equal(matchesOrigin({entity:{}},'https://example.com'),false);
});
test('lock epoch rejects an operation which completed after lock',()=>{const epoch=new Epoch(),captured=epoch.capture();epoch.check(captured);epoch.invalidate();assert.throws(()=>epoch.check(captured));});
