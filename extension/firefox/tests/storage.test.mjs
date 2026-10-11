import 'fake-indexeddb/auto';
import test from 'node:test';
import assert from 'node:assert/strict';
import {InstallationStore} from '../src/storage.mjs';
test('installation envelope survives reopening only after durable transaction completion',async()=>{const first=await new InstallationStore().open();const value={envelope:'encrypted',unlock:{credentialId:'public'}};await first.set('installation',value);first.db.close();const next=await new InstallationStore().open();assert.deepEqual(await next.get('installation'),value);next.db.close();});
