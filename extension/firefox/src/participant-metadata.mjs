import {decode, encode, text, textBytes, hex, random} from './encoding.mjs';

// Call only with a verified snapshot. Values are encrypted Git file bytes.
export function metadataPointers(files) {
  return Object.fromEntries(Object.entries(files).flatMap(([path, data]) => {
    const match = /^participants\/([0-9a-f]{64})\/meta.entry$/.exec(path);
    return match ? [[match[1], text(decode(data)).trimEnd()]] : [];
  }));
}
export function isMetadata(files, id) { return Object.values(metadataPointers(files)).includes(id); }
function writeEntry(files, id, encrypted) {
  for (const path of Object.keys(files)) if (path.startsWith(`entries/${id}/`)) delete files[path];
  files[`entries/${id}/primary`] = encrypted.primary;
  for (const [recipient, grant] of Object.entries(encrypted.grants)) files[`entries/${id}/grants/${recipient}`] = grant;
}
function recipients(files) {
  return Object.entries(files).filter(([path]) => /^participants\/[0-9a-f]{64}\/pub.pem$/.test(path)).map(([, data]) => text(decode(data)));
}
export async function decryptMetadata(files, participant, ownId, identity, crypto) {
  const id = metadataPointers(files)[participant];
  if (!id) return null;
  const grant = files[`entries/${id}/grants/${ownId}`];
  if (!grant) throw Error('Participant metadata is inaccessible');
  return crypto('metadata_decrypt', {identity, participantId:participant, primary:files[`entries/${id}/primary`], grant});
}
export async function pruneLegacy(files, crypto) {
  const next = {...files};
  for (const [path, bytes] of Object.entries(files)) {
    const match = /^participants\/([0-9a-f]{64})\/name.json$/.exec(path);
    if (match) {
      const id = hex(random(16));
      writeEntry(next, id, await crypto('metadata_encrypt', {entryId:id, participantId:match[1], name:JSON.parse(text(decode(bytes))).name, recipients:recipients(files)}));
      next[`participants/${match[1]}/meta.entry`] = encode(textBytes(`${id}\n`));
      delete next[path];
    }
    if (/^participants\/[0-9a-f]{64}\/browser.json$/.test(path)) delete next[path];
  }
  return next;
}
export async function renameParticipant(files, participant, name, ownId, identity, crypto) {
  if (!files[`participants/${participant}/pub.pem`]) throw Error('Unknown wallet participant');
  const next = await pruneLegacy(files, crypto);
  const old = await decryptMetadata(next, participant, ownId, identity, crypto);
  const id = metadataPointers(next)[participant] ?? hex(random(16));
  const encrypted = await crypto('metadata_encrypt', {entryId:id, participantId:participant, name, recipients:recipients(next), ...(old ? {payload:old.payload} : {})});
  writeEntry(next, id, encrypted);
  next[`participants/${participant}/meta.entry`] = encode(textBytes(`${id}\n`));
  return next;
}
