// Saves bytes generated on this device as a file. Nothing is uploaded.

export function saveFile(data: Uint8Array | string, name: string, type: string): void {
  const part = typeof data === 'string' ? data : new Uint8Array(data);
  const url = URL.createObjectURL(new Blob([part], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  // Revoked after the click has been handled, so the download can start.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
