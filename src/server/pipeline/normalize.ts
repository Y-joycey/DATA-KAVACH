export interface NormalizedView {
  original: string;
  normalized: string;
  /** Maps each character index in `normalized` to its starting index in `original` */
  normToOrigStart: number[];
  /** Maps each character index in `normalized` to its exclusive ending index in `original` */
  normToOrigEnd: number[];
  detectedLanguage: string;
  languageSupported: boolean;
  normalizationNotes: string[];
}

const ZERO_WIDTH_RE = /[\u200B-\u200D\uFEFF\u00AD]/g;

// Minimal intentional confusable map (Cyrillic/fullwidth homoglyphs used in adversarial evasion)
const CONFUSABLE_MAP: Record<string, string> = {
  '\u0410': 'A',
  '\u0412': 'B',
  '\u0421': 'C',
  '\u0415': 'E',
  '\u041D': 'H',
  '\u041A': 'K',
  '\u041C': 'M',
  '\u041E': 'O',
  '\u0420': 'P',
  '\u0422': 'T',
  '\u0425': 'X',
  '\u0430': 'a',
  '\u0435': 'e',
  '\u043E': 'o',
  '\u0440': 'p',
  '\u0441': 'c',
  '\u0445': 'x',
};

export function detectLanguage(text: string): {
  language: string;
  supported: boolean;
} {
  const hasDevanagari = /[\u0900-\u097F]/.test(text);
  const hasKannada = /[\u0C80-\u0CFF]/.test(text);
  const hasTamil = /[\u0B80-\u0BFF]/.test(text);
  const hasTelugu = /[\u0C00-\u0C7F]/.test(text);
  const hasBengali = /[\u0980-\u09FF]/.test(text);
  const hasLatin = /[A-Za-z]/.test(text);

  const hinglishMarkers = /\b(mera|meri|naam|pata|aadhaar|janam|dinank|khata|namaste|kripya|hai|ka|ki|ke)\b/i;

  if (hasDevanagari && hasLatin) {
    return { language: 'Hindi-English (Code-Mixed)', supported: true };
  }
  if (hasDevanagari) {
    return { language: 'Hindi (Devanagari)', supported: true };
  }
  if (hasKannada && hasLatin) {
    return { language: 'Kannada-English (Code-Mixed)', supported: true };
  }
  if (hasKannada) {
    return { language: 'Kannada', supported: true };
  }
  if (hasTamil || hasTelugu || hasBengali) {
    return { language: 'Indic Script (Experimental Hook)', supported: false };
  }
  if (hasLatin && hinglishMarkers.test(text)) {
    return { language: 'Hinglish (Transliterated Code-Mixed)', supported: true };
  }
  return { language: 'Indian English', supported: true };
}

/**
 * Builds a non-destructive normalized analysis view while preserving exact
 * bidirectional character offsets back into the immutable original string.
 */
export function buildNormalizedView(original: string): NormalizedView {
  const normChars: string[] = [];
  const normToOrigStart: number[] = [];
  const normToOrigEnd: number[] = [];
  const notes: string[] = [];

  let strippedZeroWidth = false;
  let collapsedWhitespace = false;
  let replacedConfusables = false;

  let i = 0;
  let lastWasSpace = false;

  while (i < original.length) {
    const ch = original[i];

    if (ZERO_WIDTH_RE.test(ch)) {
      ZERO_WIDTH_RE.lastIndex = 0;
      strippedZeroWidth = true;
      i++;
      continue;
    }

    // NFKC per character/cluster keeps offset attribution exact for 1->k expansions
    let nfkc = ch.normalize('NFKC');
    if (CONFUSABLE_MAP[nfkc]) {
      nfkc = CONFUSABLE_MAP[nfkc];
      replacedConfusables = true;
    }

    if (ch === ' ' || ch === '\t') {
      if (lastWasSpace) {
        collapsedWhitespace = true;
        i++;
        continue;
      }
      normChars.push(' ');
      normToOrigStart.push(i);
      normToOrigEnd.push(i + 1);
      lastWasSpace = true;
      i++;
      continue;
    }

    lastWasSpace = ch === '\n' || ch === '\r';
    for (let k = 0; k < nfkc.length; k++) {
      normChars.push(nfkc[k]);
      normToOrigStart.push(i);
      normToOrigEnd.push(i + 1);
    }
    i++;
  }

  if (strippedZeroWidth) notes.push('zero-width characters stripped in analysis copy');
  if (collapsedWhitespace) notes.push('repeated inline spaces collapsed in analysis copy');
  if (replacedConfusables) notes.push('homoglyph confusables mapped in analysis copy');

  const lang = detectLanguage(original);

  return {
    original,
    normalized: normChars.join(''),
    normToOrigStart,
    normToOrigEnd,
    detectedLanguage: lang.language,
    languageSupported: lang.supported,
    normalizationNotes: notes,
  };
}

export function mapNormSpanToOrig(
  view: NormalizedView,
  normStart: number,
  normEnd: number
): { start: number; end: number; raw: string } {
  if (normStart < 0 || normEnd <= normStart || normStart >= view.normToOrigStart.length) {
    return { start: 0, end: 0, raw: '' };
  }
  const safeEndIdx = Math.min(normEnd - 1, view.normToOrigEnd.length - 1);
  const start = view.normToOrigStart[normStart];
  const end = view.normToOrigEnd[safeEndIdx];
  return {
    start,
    end,
    raw: view.original.slice(start, end),
  };
}
