import test from 'node:test';
import assert from 'node:assert/strict';
import {withBackupFlags} from '../src/passkey-flags.mjs';
test('stored backup flags override request data and absence restores legacy defaults',()=>{
 const attack={rpId:'example.test',kagitabaBackupFlags:{eligible:false,state:false}};
 assert.deepEqual(withBackupFlags(attack,{}),{rpId:'example.test'});
 const stored={eligible:true,state:true};
 assert.deepEqual(withBackupFlags(attack,{kagitabaBackupFlags:stored}),{rpId:'example.test',kagitabaBackupFlags:stored});
 assert.equal(withBackupFlags(attack,{kagitabaBackupFlags:null}).kagitabaBackupFlags,null);
 assert.deepEqual(attack.kagitabaBackupFlags,{eligible:false,state:false});
});
