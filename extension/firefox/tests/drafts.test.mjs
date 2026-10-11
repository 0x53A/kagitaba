import test from 'node:test';
import assert from 'node:assert/strict';
import {checkDraft} from '../src/drafts.mjs';

test('an open edit cannot overwrite a synced revision or resurrect a deletion',()=>{
  const id='a'.repeat(32),path=`entries/${id}/primary`;
  checkDraft({[path]:'old'},id,'old');
  checkDraft({},id,null);
  assert.throws(()=>checkDraft({[path]:'peer update'},id,'old'),/changed or was deleted/);
  assert.throws(()=>checkDraft({},id,'old'),/changed or was deleted/);
  assert.throws(()=>checkDraft({[path]:'existing'},id,null),/changed or was deleted/);
  assert.throws(()=>checkDraft({[path]:'existing'},id,undefined),/changed or was deleted/);
});
