// Only single, explicitly approved credentials cross this isolated bridge.
const documentToken = crypto.randomUUID();
window.addEventListener('message', async event => {
  if (event.source !== window || event.origin !== location.origin || typeof event.data?.id !== 'string' || event.data.id.length > 80) return;
  if (event.data.channel === 'kagitaba-cancel') {
    browser.runtime.sendMessage({type: 'cancel', id: event.data.id, documentToken}).catch(() => {});
    return;
  }
  if (event.data.channel !== 'kagitaba-request') return;
  let answer;
  try { answer = await browser.runtime.sendMessage({type: 'webauthn', id: event.data.id, kind: event.data.kind, input: event.data.input, documentToken}); }
  catch { answer = {error: 'Kagitaba is unavailable'}; }
  window.postMessage({channel: 'kagitaba-response', id: event.data.id, ...answer}, location.origin);
});
browser.runtime.onMessage.addListener(message => {
  if (message.type === 'probe') return Promise.resolve({documentToken, origin: location.origin});
  if (message.documentToken !== documentToken || message.origin !== location.origin) throw new Error('The document changed');
  if (message.type === 'fill') {
    const passwords = [...document.querySelectorAll('input[type=password]')].filter(el => !el.disabled && el.getClientRects().length);
    if (!passwords.length) throw new Error('No visible password field');
    const password = passwords[0];
    const root = password.form ?? document;
    const usernames = [...root.querySelectorAll('input')].filter(el => !el.disabled && el.getClientRects().length && (['text', 'email'].includes(el.type) || el.autocomplete === 'username'));
    const set = (el, value) => {Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value); el.dispatchEvent(new Event('input', {bubbles: true})); el.dispatchEvent(new Event('change', {bubbles: true}));};
    if (usernames.length) set(usernames.at(-1), message.username);
    set(password, message.password);
    return Promise.resolve(true);
  }
  if (message.type === 'capture') {
    const password = [...document.querySelectorAll('input[type=password]')].find(el => !el.disabled && el.getClientRects().length);
    if (!password) throw new Error('No visible password field');
    const root = password.form ?? document;
    const username = [...root.querySelectorAll('input')].filter(el => ['text', 'email'].includes(el.type) && !el.disabled && el.getClientRects().length).at(-1);
    return Promise.resolve({username: username?.value ?? '', password: password.value});
  }
});
