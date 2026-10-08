/**
 * Saves bytes as a file the user downloads. Generated locally. Nothing is
 * uploaded. File names never carry order ids, prices or sizes.
 */
export function downloadBytes(name: string, bytes: Uint8Array, type: string): void {
  const blob = new Blob([bytes.slice().buffer], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.rel = 'noopener';
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function downloadJson(name: string, value: unknown): void {
  const text = JSON.stringify(
    value,
    (_k, v: unknown) => (typeof v === 'bigint' ? v.toString() : v),
    2,
  );
  downloadBytes(name, new TextEncoder().encode(text), 'application/json');
}
