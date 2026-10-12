// Text scorers: TF-IDF + logistic regression, as sklearn's TfidfVectorizer(analyzer="char") or
// the word variant (lowercase [a-z0-9]+ tokens and token pairs; models/text_scorers.py) followed
// by LogisticRegression. The vocabulary is cut to the bundle's terms and the L2 norm runs over
// those terms only, as in the fitted vectorizer. Values are rounded to float32 where sklearn
// stores float32 (dtype=np.float32).

const fround = Math.fround;

export function loadChar(payload) {
  const index = new Map();
  payload.terms.forEach((term, i) => index.set(term, i));
  return {
    index,
    idf: Float32Array.from(payload.idf),
    coef: Float32Array.from(payload.coef),
    intercept: payload.intercept,
    minN: payload.ngram_range[0],
    maxN: payload.ngram_range[1],
    sublinear: payload.sublinear_tf,
    eps: payload.eps,
    kind: payload.kind ?? "char",
    piece: payload.piece ?? "url",
  };
}

const WORD = /[a-z0-9]+/g;

// Word terms as sklearn's analyzer="word": tokens of the lowercased text, then pairs joined by a space.
function* wordTerms(text, minN, maxN) {
  const tokens = text.toLowerCase().match(WORD) ?? [];
  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i + n <= tokens.length; i++) yield tokens.slice(i, i + n).join(" ");
  }
}

// sklearn _char_ngrams: runs of 2+ white-space characters become one space; n-grams of every
// size from minN to maxN over code points.
function* ngrams(text, minN, maxN) {
  const cps = Array.from(text.replace(/\s\s+/g, " "));
  for (let n = minN; n <= Math.min(maxN, cps.length); n++) {
    for (let i = 0; i + n <= cps.length; i++) yield cps.slice(i, i + n).join("");
  }
}

// Probability of the positive class for one text.
export function charProb(model, text) {
  const counts = new Map();
  const terms = model.kind === "word" ? wordTerms(text, model.minN, model.maxN) : ngrams(text, model.minN, model.maxN);
  for (const g of terms) {
    const i = model.index.get(g);
    if (i !== undefined) counts.set(i, (counts.get(i) ?? 0) + 1);
  }
  let norm = 0;
  const weights = [];
  for (const [i, c] of counts) {
    const tf = model.sublinear ? fround(1 + fround(Math.log(c))) : c;
    const w = fround(tf * model.idf[i]);
    weights.push([i, w]);
    norm += w * w;
  }
  norm = Math.sqrt(norm);
  let z = model.intercept;
  if (norm > 0) for (const [i, w] of weights) z += fround(w / norm) * model.coef[i];
  return 1 / (1 + Math.exp(-z));
}

// logit with the clip used by models/stack.py.
export function logit(p, eps) {
  const c = Math.min(Math.max(p, eps), 1 - eps);
  return Math.log(c / (1 - c));
}
