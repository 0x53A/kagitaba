// Application policy shared by graph verification and merge previews. Values
// are encoded committed bytes; no payload is decrypted or edited here.
import {metadataPointers} from './participant-metadata.mjs';
export function ancestors(graph, head) {
  const seen = new Set(), pending = [head];
  while (pending.length) {
    const id = pending.pop();
    if (seen.has(id)) continue;
    const commit = graph.get(id);
    if (!commit) throw Error('Unsupported wallet history');
    seen.add(id); pending.push(...commit.parents);
  }
  return seen;
}

export function mergeBase(graph, left, right) {
  const a = ancestors(graph, left), b = ancestors(graph, right);
  if (a.has(right) || b.has(left)) throw Error('Unsupported wallet history');
  const common = new Set([...a].filter(id => b.has(id))), best = new Set(common);
  for (const id of common) for (const parent of graph.get(id).parents) best.delete(parent);
  if (best.size !== 1) throw Error('Unsupported wallet history');
  return [...best][0];
}

export function equalFiles(left, right) {
  if (left === undefined || right === undefined) return left === right;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length && keys.every(key => Object.hasOwn(right, key) && left[key] === right[key]);
}

function units(files) {
  const groups = new Map();
  for (const [path, bytes] of Object.entries(files)) {
    const parts = path.split('/');
    let unit;
    if (path === 'kagitaba-format') unit = path;
    else if (parts.length >= 3 && ['entries', 'participants'].includes(parts[0])) unit = parts.slice(0, 2).join('/');
    else throw Error('Unsupported wallet history');
    if (!groups.has(unit)) groups.set(unit, Object.create(null));
    groups.get(unit)[path] = bytes;
  }
  return groups;
}

export function mergeFiles(baseFiles, leftFiles, rightFiles) {
  const metadata = new Set([baseFiles,leftFiles,rightFiles].flatMap(files=>Object.values(metadataPointers(files))));
  const base = units(baseFiles), left = units(leftFiles), right = units(rightFiles);
  const merged = Object.create(null);
  for (const key of new Set([...base.keys(), ...left.keys(), ...right.keys()])) {
    const b = base.get(key), l = left.get(key), r = right.get(key);
    let chosen;
    if (equalFiles(l, r) || equalFiles(r, b)) chosen = l;
    else if (equalFiles(l, b)) chosen = r;
    else if (key.startsWith('entries/') && metadata.has(key.slice(8))) chosen = mergeMetadataGrants(b,l,r);
    else throw Error('Conflicting wallet changes');
    if (chosen) Object.assign(merged, chosen);
  }
  const referenced = new Set(Object.values(metadataPointers(merged)));
  for (const id of metadata) if (merged[`entries/${id}/primary`] && !referenced.has(id)) throw Error('Conflicting wallet changes');
  for (const id of referenced) if (!merged[`entries/${id}/primary`]) throw Error('Conflicting wallet changes');
  return merged;
}

function mergeMetadataGrants(base,left,right) {
  if (!base || !left || !right) throw Error('Conflicting wallet changes');
  const onlyAdds=side=>Object.entries(base).every(([path,bytes])=>side[path]===bytes);
  const primary=Object.keys(base).find(path=>path.endsWith('/primary'));
  if(!primary)throw Error('Conflicting wallet changes');
  if(onlyAdds(left)&&right[primary]!==base[primary])return right;
  if(onlyAdds(right)&&left[primary]!==base[primary])return left;
  if (!onlyAdds(left)||!onlyAdds(right)) throw Error('Conflicting wallet changes');
  const merged={...left};
  for(const [path,bytes] of Object.entries(right)) {
    if(Object.hasOwn(merged,path) && merged[path]!==bytes) delete merged[path];
    else merged[path]=bytes;
  }
  return merged;
}
