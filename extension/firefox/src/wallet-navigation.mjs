// Organizational navigation only: never follows external/account-qualified links.
function localId(value) {
  if(typeof value!=='string'||!/^[A-Za-z0-9_-]+={0,2}$/.test(value))return null;
  try {const raw=atob(value.replaceAll('-','+').replaceAll('_','/'));return raw.length===16?[...raw].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(''):null;}catch{return null;}
}
export function entryMetadata(records) {
  const accessible=new Set([...records].filter(([,p])=>p.kind==='item').map(([id])=>id));
  function tree(owner,node) {
    const items=new Set();let unavailable=0;
    for(const link of node.items??[]){const id=Object.hasOwn(link,'account')?null:localId(link.item);if(id&&accessible.has(id))items.add(id);else unavailable++;}
    return {key:`${owner}:${node.id}`,title:node.title||'Untitled collection',items:[...items],unavailable,children:(node.subCollections??[]).map(child=>tree(owner,child))};
  }
  return [...records].map(([id,payload])=>({id,title:payload.entity.title||'Untitled entry',kind:payload.kind,
    usernames:[...new Set((payload.entity.credentials??[]).map(c=>c.type==='basic-auth'?c.username?.value:['passkey','totp'].includes(c.type)?c.username:null).filter(v=>typeof v==='string'&&v.length))],
    ...(payload.kind==='collection'?{collection:tree(id,payload.entity)}:{})}));
}
export function collectionNodes(entries) {
  const nodes=[];const visit=(node,depth)=>{nodes.push({...node,depth});for(const child of node.children)visit(child,depth+1);};
  for(const entry of entries)if(entry.collection)visit(entry.collection,0);
  return nodes;
}
