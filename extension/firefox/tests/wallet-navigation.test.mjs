import test from 'node:test';
import assert from 'node:assert/strict';
import {entryMetadata,collectionNodes} from '../src/wallet-navigation.mjs';
const a='11'.repeat(16),b='22'.repeat(16),c='33'.repeat(16),id=hex=>Buffer.from(hex,'hex').toString('base64url');
test('collection navigation resolves direct accessible local links only and includes nested membership',()=>{
 const records=new Map([[a,{kind:'item',entity:{title:'A',credentials:[{type:'basic-auth',username:{value:'alice'}},{type:'passkey',username:'alice'},{type:'totp',username:'other'}]}}],[b,{kind:'item',entity:{title:'B',credentials:[]}}],[c,{kind:'collection',entity:{id:id(c),title:'Root',items:[{item:id(a)+'=='},{item:id(b),account:'external'},{item:id('44'.repeat(16))}],subCollections:[{id:id('55'.repeat(16)),title:'Child',items:[{item:id(b)}]}]}}]]);
 const metadata=entryMetadata(records),nodes=collectionNodes(metadata);
 assert.deepEqual(metadata[0].usernames,['alice','other']);assert.equal(nodes.length,2);
 assert.deepEqual(nodes[0].items,[a]);assert.equal(nodes[0].unavailable,2);assert.deepEqual(nodes[1].items,[b]);assert.equal(nodes[1].depth,1);
 assert.equal(new Set(nodes.flatMap(n=>n.items)).size,2);assert.equal(metadata.filter(e=>e.kind==='item').length,2);
});
test('external links do not mark unrelated items filed',()=>{
 const data=entryMetadata(new Map([[a,{kind:'item',entity:{title:'A'}}],[c,{kind:'collection',entity:{id:id(c),items:[{item:id(a),account:''}]}}]]));
 assert.deepEqual(collectionNodes(data)[0].items,[]);assert.equal(collectionNodes(data)[0].unavailable,1);
});
