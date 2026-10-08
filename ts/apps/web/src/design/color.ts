// Colour arithmetic for the design-system tests: WCAG 2.x contrast, alpha
// compositing, CIELAB deltaE76 and colour-vision-deficiency simulation.

/** sRGB components in [0, 1] and alpha in [0, 1]. */
export interface Rgba {
  r: number;
  g: number;
  b: number;
  a: number;
}

const HEX = /^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const FUNCTION = /^(rgba?|hsla?|oklab|oklch)\(([^)]*)\)$/i;
const NUMBER = /^([+-]?(?:\d+\.?\d*|\.\d+)(?:e[+-]?\d+)?)(%|deg|grad|rad|turn)?$/i;

const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

/** A number with an optional unit. A percentage is scaled so 100 % is `full`. */
function quantity(text: string, full: number, source: string): number {
  const match = NUMBER.exec(text);
  if (!match?.[1]) throw new Error(`unsupported colour: ${source}`);
  const n = Number(match[1]);
  switch (match[2]?.toLowerCase()) {
    case undefined:
      return n;
    case '%':
      return (n / 100) * full;
    default:
      throw new Error(`unsupported colour: ${source}`);
  }
}

/** A hue in degrees, from a bare number or deg, grad, rad or turn. */
function hue(text: string, source: string): number {
  const match = NUMBER.exec(text);
  if (!match?.[1]) throw new Error(`unsupported colour: ${source}`);
  const n = Number(match[1]);
  const unit = match[2]?.toLowerCase();
  if (unit === '%') throw new Error(`unsupported colour: ${source}`);
  const degrees =
    unit === 'turn'
      ? n * 360
      : unit === 'rad'
        ? (n * 180) / Math.PI
        : unit === 'grad'
          ? n * 0.9
          : n;
  return ((degrees % 360) + 360) % 360;
}

/** Legacy `a, b, c[, alpha]` or modern `a b c[ / alpha]` arguments. */
function colourArguments(
  body: string,
  source: string,
): [string, string, string, string | undefined] {
  const trimmed = body.trim();
  const parts = trimmed.includes(',')
    ? trimmed.split(',').map((p) => p.trim())
    : (() => {
        const [main = '', alpha, ...rest] = trimmed.split('/').map((p) => p.trim());
        if (rest.length > 0) throw new Error(`unsupported colour: ${source}`);
        const channels = main.split(/\s+/);
        return alpha === undefined ? channels : [...channels, alpha];
      })();
  const [a, b, c, alpha, ...extra] = parts;
  if (a === undefined || b === undefined || c === undefined || extra.length > 0) {
    throw new Error(`unsupported colour: ${source}`);
  }
  return [a, b, c, alpha];
}

// CSS Color 4, "Converting HSL colors to sRGB colors".
function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  const f = (n: number) => {
    const k = (n + h / 30) % 12;
    return l - s * Math.min(l, 1 - l) * Math.max(-1, Math.min(k - 3, 9 - k, 1));
  };
  return [f(0), f(8), f(4)];
}

// Björn Ottosson's OKLab to linear sRGB. Out-of-gamut values are clipped.
function oklabToRgb(l: number, a: number, b: number): [number, number, number] {
  const l1 = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3;
  const m1 = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3;
  const s1 = (l - 0.0894841775 * a - 1.291485548 * b) ** 3;
  const encode = (c: number) => fromLinear(clamp01(c));
  return [
    encode(4.0767416621 * l1 - 3.3077115913 * m1 + 0.2309699292 * s1),
    encode(-1.2684380046 * l1 + 2.6097574011 * m1 - 0.3413193965 * s1),
    encode(-0.0041960863 * l1 - 0.7034186147 * m1 + 1.707614701 * s1),
  ];
}

/**
 * Parses #RGB, #RGBA, #RRGGBB, #RRGGBBAA and rgb, hsl, oklab and
 * oklch in both the comma and the space / slash syntax. Throws on anything
 * else, so a scan can report a colour it cannot evaluate.
 */
export function parseColor(text: string): Rgba {
  const value = text.trim();
  const hex = HEX.exec(value);
  if (hex?.[1]) {
    const digits = hex[1].length <= 4 ? [...hex[1]].map((d) => d + d).join('') : hex[1];
    const channel = (i: number) => parseInt(digits.slice(i, i + 2), 16) / 255;
    return { r: channel(0), g: channel(2), b: channel(4), a: digits.length === 8 ? channel(6) : 1 };
  }
  const fn = FUNCTION.exec(value);
  if (fn?.[1] && fn[2] !== undefined) {
    const [x, y, z, alpha] = colourArguments(fn[2], text);
    const a = alpha === undefined ? 1 : clamp01(quantity(alpha, 1, text));
    const name = fn[1].toLowerCase();
    if (name.startsWith('rgb')) {
      const [r, g, b] = [x, y, z].map((c) => clamp01(quantity(c, 255, text) / 255));
      return { r: r ?? 0, g: g ?? 0, b: b ?? 0, a };
    }
    if (name.startsWith('hsl')) {
      // Saturation and lightness are percentages, with or without the % sign.
      const percent = (t: string) => clamp01(quantity(t.endsWith('%') ? t : `${t}%`, 1, text));
      const [r, g, b] = hslToRgb(hue(x, text), percent(y), percent(z));
      return { r, g, b, a };
    }
    const lightness = quantity(x, 1, text);
    if (name === 'oklab') {
      const [r, g, b] = oklabToRgb(lightness, quantity(y, 0.4, text), quantity(z, 0.4, text));
      return { r, g, b, a };
    }
    const chroma = quantity(y, 0.4, text);
    const h = (hue(z, text) * Math.PI) / 180;
    const [r, g, b] = oklabToRgb(lightness, chroma * Math.cos(h), chroma * Math.sin(h));
    return { r, g, b, a };
  }
  throw new Error(`unsupported colour: ${text}`);
}

export function toHex(color: Rgba): string {
  const byte = (c: number) =>
    Math.round(Math.min(1, Math.max(0, c)) * 255)
      .toString(16)
      .padStart(2, '0');
  return `#${byte(color.r)}${byte(color.g)}${byte(color.b)}`.toUpperCase();
}

/** Source-over compositing of `top` (with its alpha) onto an opaque `bottom`. */
export function composite(top: Rgba, bottom: Rgba): Rgba {
  const a = top.a;
  return {
    r: top.r * a + bottom.r * (1 - a),
    g: top.g * a + bottom.g * (1 - a),
    b: top.b * a + bottom.b * (1 - a),
    a: 1,
  };
}

/** `amount` of `color` over `base`, both treated as opaque. */
export function mix(color: Rgba, base: Rgba, amount: number): Rgba {
  return composite({ ...color, a: amount }, base);
}

function toLinear(c: number): number {
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

function fromLinear(c: number): number {
  return c <= 0.0031308 ? 12.92 * c : 1.055 * c ** (1 / 2.4) - 0.055;
}

export function relativeLuminance(color: Rgba): number {
  return 0.2126 * toLinear(color.r) + 0.7152 * toLinear(color.g) + 0.0722 * toLinear(color.b);
}

/** WCAG 2.x contrast ratio between two opaque colours. */
export function contrastRatio(a: Rgba, b: Rgba): number {
  const la = relativeLuminance(a);
  const lb = relativeLuminance(b);
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}

/** CIELAB (D65) from sRGB. */
export function toLab(color: Rgba): [number, number, number] {
  const r = toLinear(color.r);
  const g = toLinear(color.g);
  const b = toLinear(color.b);
  // IEC 61966-2-1 matrix at full precision, so white lands on the D65 white point.
  const x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047;
  const y = 0.2126729 * r + 0.7151522 * g + 0.072175 * b;
  const z = (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883;
  const f = (t: number) => (t > 216 / 24389 ? Math.cbrt(t) : ((24389 / 27) * t + 16) / 116);
  const fx = f(x);
  const fy = f(y);
  const fz = f(z);
  return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
}

export function deltaE76(a: Rgba, b: Rgba): number {
  const [l1, a1, b1] = toLab(a);
  const [l2, a2, b2] = toLab(b);
  return Math.hypot(l1 - l2, a1 - a2, b1 - b2);
}

export type Vision = 'normal' | 'deuteranopia' | 'protanopia';

// Machado, Oliveira and Fernandes (2009), severity 1.0, applied to linear RGB.
const MACHADO: Record<Exclude<Vision, 'normal'>, readonly number[][]> = {
  protanopia: [
    [0.152286, 1.052583, -0.204868],
    [0.114503, 0.786281, 0.099216],
    [-0.003882, -0.048116, 1.051998],
  ],
  deuteranopia: [
    [0.367322, 0.860646, -0.227968],
    [0.280085, 0.672501, 0.047413],
    [-0.01182, 0.04294, 0.968881],
  ],
};

export function simulateVision(color: Rgba, vision: Vision): Rgba {
  if (vision === 'normal') return color;
  const lin = [toLinear(color.r), toLinear(color.g), toLinear(color.b)];
  const [r, g, b] = MACHADO[vision].map((row) => {
    const v =
      (row[0] ?? 0) * (lin[0] ?? 0) + (row[1] ?? 0) * (lin[1] ?? 0) + (row[2] ?? 0) * (lin[2] ?? 0);
    return fromLinear(Math.min(1, Math.max(0, v)));
  });
  return { r: r ?? 0, g: g ?? 0, b: b ?? 0, a: color.a };
}

/** Smallest deltaE76 between two colours over normal vision and both dichromacies. */
export function minDeltaE76UnderCvd(a: Rgba, b: Rgba): number {
  const visions: Vision[] = ['normal', 'deuteranopia', 'protanopia'];
  return Math.min(...visions.map((v) => deltaE76(simulateVision(a, v), simulateVision(b, v))));
}
