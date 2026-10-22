// Backend selection is not authorization. Each backend still owns its approval.
export class PasskeyRouter {
  constructor({api, native, requests, currentDocument}) {
    Object.assign(this, {api, native, requests, currentDocument});
  }
  show(request, error) {
    return this.api.tabs.sendMessage(request.tabId, {
      type: 'passkey-chooser', requestId: request.id, origin: request.origin,
      documentToken: request.documentToken, kind: request.kind,
      backends: request.backends, busy: request.phase !== 'choose', error,
    }, {frameId: 0});
  }
  start(request, backends) {
    return new Promise(resolve => {
      let finished = false;
      const timer = setTimeout(() => request.finish({error: 'Request expired'}), request.timeout);
      Object.assign(request, {backends, phase: 'choose', finish: result => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        this.requests.delete(request.id);
        this.native.cancelPage(request.tabId, request.pageId, request.documentToken);
        this.api.tabs.sendMessage(request.tabId, {type: 'passkey-dismiss', requestId: request.id,
          origin: request.origin, documentToken: request.documentToken}, {frameId: 0}).catch(() => {});
        if (request.windowId !== undefined && !result.credential) this.api.windows.remove(request.windowId).catch(() => {});
        resolve(result);
      }});
      this.requests.set(request.id, request);
      this.show(request).catch(() => request.finish({error: 'Unable to show passkey chooser'}));
    });
  }
  async choose(message, sender) {
    const request = this.requests.get(message.requestId);
    if (!request || sender.frameId !== 0 || sender.tab?.id !== request.tabId
      || message.documentToken !== request.documentToken || new URL(sender.url).origin !== request.origin) return false;
    if (!['browser', 'native', 'firefox', 'cancel'].includes(message.backend)) return false;
    await this.currentDocument(request);
    if (!this.requests.has(request.id)) return false;
    if (message.backend === 'cancel' || message.backend === 'firefox') {
      request.finish(message.backend === 'firefox' ? {fallback: true} : {error: 'Request cancelled'});
      return true;
    }
    if (request.phase !== 'choose' || !request.backends.includes(message.backend)) return false;
    request.phase = message.backend;
    try {
      await this.show(request);
      if (!this.requests.has(request.id)) return false;
      if (message.backend === 'browser') {
        const window = await this.api.windows.create({url: this.api.runtime.getURL(`app.html?request=${request.id}`), type: 'popup', width: 480, height: 640});
        if (this.requests.has(request.id)) request.windowId = window.id;
        else this.api.windows.remove(window.id).catch(() => {});
      } else {
        const result = await this.native.passkey(request.tabId, request, request.documentToken, request.pageId);
        if (this.requests.has(request.id)) request.finish(result);
      }
    } catch {
      if (this.requests.has(request.id)) {
        request.phase = 'choose';
        const error = message.backend === 'native'
          ? 'Native request did not complete. Open and unlock Kagitaba, then retry, or choose another option.'
          : 'Unable to open wallet approval. Retry or let Firefox handle it.';
        await this.show(request, error).catch(() => request.finish({error: 'Kagitaba is unavailable'}));
      }
    }
    return true;
  }
}
