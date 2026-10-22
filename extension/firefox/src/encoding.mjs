export const encode = bytes => {
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), parts = [];
  for (let i=0;i<input.length;i+=32768) parts.push(String.fromCharCode(...input.subarray(i,i+32768)));
  return btoa(parts.join('')).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
};
export const decode = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error('Invalid binary encoding');
  const binary = atob(value.replaceAll('-', '+').replaceAll('_', '/')), bytes = new Uint8Array(binary.length);
  for (let i=0;i<bytes.length;i++) bytes[i]=binary.charCodeAt(i);
  return bytes;
};
export const random = size => crypto.getRandomValues(new Uint8Array(size));
export const textBytes = value => new TextEncoder().encode(value);
export const text = value => new TextDecoder('utf-8', {fatal: true}).decode(value);
export const hex = value => [...value].map(v => v.toString(16).padStart(2, '0')).join('');
