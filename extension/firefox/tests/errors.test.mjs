import test from 'node:test';
import assert from 'node:assert/strict';
import {safeDiagnostic, uiDiagnostic, connectionStep} from '../src/errors.mjs';

test('diagnostics never forward library secrets, response bodies or URLs', () => {
  const secret = 'SECRET-TOKEN';
  for (const error of [new Error(secret), {code: 'HttpError', message: secret, data: {statusCode: 403, response: secret}}, {code:'NotFoundError', data:{what:secret}}]) {
    assert.ok(!safeDiagnostic(error).includes(secret));
  }
  assert.match(safeDiagnostic({code:'HttpError',data:{statusCode:403}}), /denied access/);
});
test('connection errors retain safe phase and trust rejection', async () => {
  await assert.rejects(connectionStep('verify', () => {throw new Error('Rollback or divergent history');}), error => {
    assert.equal(uiDiagnostic(error), 'Connection failed during verify: Rollback or divergent history'); return true;
  });
});
test('fallback exposes only known error codes and bundled source coordinates', () => {
  const error = {code:'InternalError',message:'SECRET',stack:'SECRET\nfoo@moz-extension://some-id/background.js:123:45\nSECRET'};
  assert.match(safeDiagnostic(error), /InternalError.*background.js:123:45/);
  assert.ok(!safeDiagnostic(error).includes('SECRET'));
  assert.ok(!safeDiagnostic({code:'SECRET',message:'SECRET',stack:'SECRET'}).includes('SECRET'));
});
