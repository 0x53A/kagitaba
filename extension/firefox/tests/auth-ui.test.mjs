import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';
import {build} from 'esbuild';

// Exercise the actual app controller with a synthetic DOM and browser prompt.
// Initial status requests remain pending; no wallet or physical key is accessed.
const source = await readFile(new URL('../src/app.mjs', import.meta.url), 'utf8');
const bundled = await build({stdin:{contents:source+'\nexport {fidoRequest,run};',resolveDir:fileURLToPath(new URL('../src/',import.meta.url))},bundle:true,write:false,format:'iife',globalName:'AuthUi'});
function fixture() {
  const nodes = new Map();
  function node(tag='div') {return {tag,children:[],dataset:{},hidden:false,setAttribute(){},querySelectorAll:()=>[],set textContent(value){this.text=value;this.children=[];},append(...items){this.children.push(...items);},replaceChildren(...items){this.children=items;}};}
  let listener, resolve, reject, signal;
  const context = vm.createContext({URLSearchParams,AbortController,location:{search:''},
    document:{querySelector:id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);},querySelectorAll:()=>[],createElement:node},
    window:{addEventListener(){}},
    browser:{runtime:{sendMessage:()=>new Promise(()=>{}),onMessage:{addListener:callback=>{listener=callback;}}}},
    navigator:{credentials:{get:options=>{signal=options.signal;return new Promise((done,fail)=>{resolve=done;reject=fail;});}}},
  });
  vm.runInContext(bundled.outputFiles[0].text,context);
  return {request:()=>context.AuthUi.fidoRequest('get',{publicKey:{}}),run:action=>context.AuthUi.run(action),fail:error=>reject(error),finish:value=>resolve(value),lock:()=>listener({type:'locked'}),signal:()=>signal,notice:()=>nodes.get('#notice')};
}
test('FIDO prompt names the PIN in bold and accepts a completed prompt',async()=>{
  const ui=fixture(), pending=ui.request();
  assert.equal(ui.notice().hidden,false);
  assert(ui.notice().children.some(child=>child.tag==='strong'&&child.text==='FIDO PIN'));
  const proof={synthetic:true};ui.finish(proof);
  assert.equal(await pending,proof);
  assert.equal(ui.signal().aborted,false);
});
test('lock aborts WebAuthn and suppresses even a late result ignoring abort',async()=>{
  const ui=fixture(), pending=ui.request();
  ui.lock();
  assert.equal(ui.signal().aborted,true);
  assert.equal(ui.notice().text,'Wallet locked.');
  ui.finish({synthetic:true});
  await assert.rejects(pending,/Wallet locked/);
  assert.equal(ui.notice().text,'Wallet locked.');
});
test('the action runner preserves lock feedback after a browser abort or late result',async()=>{
  for(const abort of [true,false]){
    const ui=fixture(), pending=ui.run(()=>ui.request());
    ui.lock();
    if(abort)ui.fail(new Error('The operation was aborted.'));
    else ui.finish({synthetic:true});
    await pending;
    assert.equal(ui.notice().text,'Wallet locked.');
    assert.equal(ui.notice().dataset.kind,'info');
    const next=ui.run(()=>ui.request());
    ui.fail(new Error('Security key unavailable'));
    await next;
    assert.equal(ui.notice().text,'Security key unavailable');
    assert.equal(ui.notice().dataset.kind,'error');
  }
});
test('locking does not suppress unrelated operation failures',async()=>{
  const ui=fixture();
  await ui.run(async()=>{ui.lock();throw new Error('Connection failed');});
  assert.equal(ui.notice().text,'Connection failed');
  assert.equal(ui.notice().dataset.kind,'error');
});
