// Only encrypted credential state can choose BE/BS, never website request data.
export function withBackupFlags(request, credential) {
  const result = {...request};
  delete result.kagitabaBackupFlags;
  if (Object.hasOwn(credential, 'kagitabaBackupFlags')) result.kagitabaBackupFlags = credential.kagitabaBackupFlags;
  return result;
}
