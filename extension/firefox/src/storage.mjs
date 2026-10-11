export class InstallationStore {
  async open() {
    this.db = await new Promise((resolve, reject) => {
      const request = indexedDB.open('kagitaba-installation', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('records');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Unable to open persistent storage'));
    });
    return this;
  }
  async get(key) {
    return new Promise((resolve, reject) => {
      const request = this.db.transaction('records').objectStore('records').get(key);
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error('Unable to read persistent storage'));
    });
  }
  async set(key, value) {
    return new Promise((resolve, reject) => {
      const transaction = this.db.transaction('records', 'readwrite', {durability: 'strict'});
      transaction.objectStore('records').put(value, key);
      transaction.oncomplete = resolve;
      transaction.onerror = transaction.onabort = () => reject(new Error('Unable to save persistent storage'));
    });
  }
}
