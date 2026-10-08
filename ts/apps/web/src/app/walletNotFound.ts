// Set when the user picks Mobile Wallet Adapter on a device with no wallet app
// that answers it. Readable with useSyncExternalStore.

type Listener = () => void;

let notFound = false;
const listeners = new Set<Listener>();

export function reportWalletNotFound(): void {
  notFound = true;
  for (const listener of listeners) listener();
}

export function getWalletNotFound(): boolean {
  return notFound;
}

export function subscribeWalletNotFound(listener: Listener): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}
