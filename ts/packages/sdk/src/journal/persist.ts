/**
 * `navigator.storage.persist`: asks the browser not to evict the journal.
 * False when the browser refuses or has no storage manager.
 */
export async function requestPersistence(): Promise<boolean> {
  const storage = (globalThis as { navigator?: { storage?: StorageManager } }).navigator?.storage;
  if (storage === undefined || typeof storage.persist !== 'function') return false;
  try {
    return await storage.persist();
  } catch {
    return false;
  }
}

/** Whether storage is already persistent. 'unknown' when the browser cannot say. */
export async function persistedState(): Promise<boolean | 'unknown'> {
  const storage = (globalThis as { navigator?: { storage?: StorageManager } }).navigator?.storage;
  if (storage === undefined || typeof storage.persisted !== 'function') return 'unknown';
  try {
    return await storage.persisted();
  } catch {
    return 'unknown';
  }
}
