// This page-hosted surface only routes requests. Never put secrets or approval
// controls here: the surrounding website can obscure or imitate this UI.
export function passkeyChooser(documentToken) {
  let host, active;
  const dismiss = () => {host?.remove(); host = undefined; active = undefined;};
  return message => {
    if (message.type === 'passkey-dismiss') {
      if (active === message.requestId) dismiss();
      return;
    }
    dismiss();
    active = message.requestId;
    host = document.createElement('div');
    host.id = 'kagitaba-passkey-chooser';
    host.style.cssText = 'all:initial!important;position:fixed!important;top:16px!important;right:16px!important;z-index:2147483647!important;display:block!important;max-width:calc(100vw - 32px)!important;';
    const root = host.attachShadow({mode: 'open'});
    const style = document.createElement('style');
    style.textContent = ':host{color-scheme:dark}section{box-sizing:border-box;font:14px/1.5 monospace;background:#10191e;color:#e4eef0;border:1px solid #56d6df;border-top:4px solid #56d6df;padding:16px;max-width:520px;max-height:calc(100vh - 32px);overflow-y:auto;scrollbar-gutter:auto;scrollbar-color:#67858f #111b20;box-shadow:0 6px 24px #0008}h2{font:700 16px/1.4 monospace;margin:0 0 6px}p{margin:8px 0;overflow-wrap:anywhere;color:#a3bbc3}p.site{color:#e4eef0;font-weight:600;margin-bottom:16px}.actions{display:flex;gap:8px;flex-wrap:wrap}button{font:inherit;border:1px solid #71848c;border-radius:0;background:#1e3038;color:#e4eef0;padding:8px;cursor:pointer}button:hover:not(:disabled){background:#29444c;border-color:#56d6df}button:focus-visible{outline:2px solid #56d6df;outline-offset:2px}button:disabled{opacity:.6;cursor:wait}.error{color:#ffb699}';
    const section = document.createElement('section');
    section.setAttribute('role', 'region');
    section.setAttribute('aria-label', 'Kagitaba passkey options');
    const title = document.createElement('h2');
    title.textContent = message.kind === 'create' ? 'Kagitaba · Save a passkey' : 'Kagitaba · Sign in with a passkey';
    const site = document.createElement('p');
    site.textContent = message.origin;
    site.className = 'site';
    const status = document.createElement('p');
    status.setAttribute('role', 'status');
    status.textContent = message.error ?? (message.busy ? 'Continue in the selected app to approve. You can still cancel or use Firefox.' : 'Choose where to continue.');
    if (message.error) status.className = 'error';
    const actions = document.createElement('div');
    actions.className = 'actions';
    for (const [backend, label] of [['browser', 'Browser wallet'], ['native', 'Native app'], ['firefox', 'Let Firefox handle it'], ['cancel', 'Cancel']]) {
      if (['browser', 'native'].includes(backend) && !message.backends.includes(backend)) continue;
      const button = document.createElement('button');
      button.type = 'button';
      button.textContent = label;
      button.dataset.backend = backend;
      button.disabled = message.busy && ['browser', 'native'].includes(backend);
      button.addEventListener('click', async event => {
        if (!event.isTrusted) return;
        button.disabled = true;
        try {
          await browser.runtime.sendMessage({type: 'passkey-choice', requestId: message.requestId, documentToken, backend});
        } catch {status.textContent = 'Kagitaba is unavailable. Cancel and retry the website request.';}
        finally {if (button.isConnected) button.disabled = false;}
      });
      actions.append(button);
    }
    section.append(title, site, status, actions);
    root.append(style, section);
    (document.body ?? document.documentElement).append(host);
  };
}
