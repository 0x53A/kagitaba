export const encode = bytes => {
  let value = '';
  for (const byte of new Uint8Array(bytes)) value += String.fromCharCode(byte);
  return btoa(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};
export const decode = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid binary encoding');
  return Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0));
};
export const random = size => crypto.getRandomValues(new Uint8Array(size));
export const textBytes = value => new TextEncoder().encode(value);
export const text = value => new TextDecoder('utf-8', {fatal: true}).decode(value);
export const hex = value => [...value].map(v => v.toString(16).padStart(2, '0')).join('');
