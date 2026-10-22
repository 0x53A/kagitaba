export const staleDraft = 'This entry changed or was deleted. Reopen it before saving; your draft has been kept.';

export function checkDraft(files, id, expectedPrimary) {
  if ((files[`entries/${id}/primary`] ?? null) !== expectedPrimary) throw Error(staleDraft);
}

// Ordinary edits cannot rotate attachment keys. Keep their immutable blobs and
// require the existing grant recipients; dedicated native revocation rekeys them.
export function replaceEntry(files, id, encrypted) {
  const prefix = `entries/${id}/`, grants = `${prefix}grants/`;
  if (Object.keys(files).some(path => path.startsWith(`${prefix}attachments/`)) &&
      Object.keys(files).some(path => path.startsWith(grants) && !Object.hasOwn(encrypted.grants, path.slice(grants.length)))) {
    throw Error('Use the native app to change attachment recipients');
  }
  const next = {...files};
  for (const path of Object.keys(next)) if (path === `${prefix}primary` || path.startsWith(grants)) delete next[path];
  next[`${prefix}primary`] = encrypted.primary;
  for (const [recipient, grant] of Object.entries(encrypted.grants)) next[`${grants}${recipient}`] = grant;
  return next;
}
