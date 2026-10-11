export const staleDraft = 'This entry changed or was deleted. Reopen it before saving; your draft has been kept.';

export function checkDraft(files, id, expectedPrimary) {
  if ((files[`entries/${id}/primary`] ?? null) !== expectedPrimary) throw Error(staleDraft);
}
