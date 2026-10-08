// Reads custom-property declarations out of tokens.css for the tests. The
// file keeps one declaration per line. Comments name the theme blocks.

export type TokenMap = Record<string, string>;

/** Custom properties declared in the first rule whose selector matches exactly. */
export function declarationsOf(css: string, selector: string): TokenMap {
  const stripped = css.replace(/\/\*[\s\S]*?\*\//g, '');
  const rule = /([^{}]+)\{([^{}]*)\}/g;
  for (let m = rule.exec(stripped); m; m = rule.exec(stripped)) {
    const selectors = (m[1] ?? '').split(',').map((s) => s.trim().replace(/\s+/g, ' '));
    if (!selectors.includes(selector)) continue;
    const map: TokenMap = {};
    for (const decl of (m[2] ?? '').split(';')) {
      const colon = decl.indexOf(':');
      if (colon < 0) continue;
      const name = decl.slice(0, colon).trim();
      if (name.startsWith('--')) map[name] = decl.slice(colon + 1).trim();
    }
    return map;
  }
  throw new Error(`no rule for ${selector}`);
}
