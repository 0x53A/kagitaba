import test from 'node:test';
import assert from 'node:assert/strict';
import {checkDraft, replaceEntry} from '../src/drafts.mjs';

test('an open edit cannot overwrite a synced revision or resurrect a deletion',()=>{
  const id='a'.repeat(32),path=`entries/${id}/primary`;
  checkDraft({[path]:'old'},id,'old');
  checkDraft({},id,null);
  assert.throws(()=>checkDraft({[path]:'peer update'},id,'old'),/changed or was deleted/);
  assert.throws(()=>checkDraft({},id,'old'),/changed or was deleted/);
  assert.throws(()=>checkDraft({[path]:'existing'},id,null),/changed or was deleted/);
  assert.throws(()=>checkDraft({[path]:'existing'},id,undefined),/changed or was deleted/);
});

test('ordinary edits preserve immutable attachment blobs and cannot reduce their recipients',()=>{
  const id='a'.repeat(32), prefix=`entries/${id}/`;
  const files={unrelated:'kept',[`${prefix}primary`]:'old',[`${prefix}grants/alice`]:'a',[`${prefix}grants/bob`]:'b',[`${prefix}attachments/${'b'.repeat(32)}`]:'ciphertext'};
  const result=replaceEntry(files,id,{primary:'new',grants:{alice:'aa',bob:'bb'}});
  assert.equal(result[`${prefix}attachments/${'b'.repeat(32)}`],'ciphertext');
  assert.equal(result[`${prefix}primary`],'new');assert.equal(result.unrelated,'kept');
  assert.equal(files[`${prefix}primary`],'old');
  assert.throws(()=>replaceEntry(files,id,{primary:'new',grants:{alice:'aa'}}),/native app/);
});
