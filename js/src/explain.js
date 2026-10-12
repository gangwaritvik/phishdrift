// Plain-English reasons for a tier A verdict: path-dependent TreeSHAP on the exported trees, a
// line-by-line port of models/explain.py (same numbers as LightGBM's pred_contrib), then the
// bundle's reason rules for the features pushing hardest toward phishing.

const ZERO_THRESHOLD = 1e-35;

function goesLeft(tree, node, value) {
  const m = tree.m[node];
  const nan = Number.isNaN(value);
  const v = nan && m !== 2 ? 0 : value;
  if ((m === 1 && Math.abs(v) <= ZERO_THRESHOLD) || (m === 2 && nan)) return tree.d[node] === 1;
  return v <= tree.t[node];
}

function cover(tree, child) {
  return child < 0 ? tree.n[~child] : tree.c[child];
}

// Path entries are [feature, zeroFraction, oneFraction, weight].
function extend(path, pz, po, pi) {
  const n = path.length;
  const out = path.map((e) => e.slice());
  out.push([pi, pz, po, n === 0 ? 1 : 0]);
  for (let i = n - 1; i >= 0; i--) {
    out[i + 1][3] += (po * out[i][3] * (i + 1)) / (n + 1);
    out[i][3] = (pz * out[i][3] * (n - i)) / (n + 1);
  }
  return out;
}

function unwind(path, i) {
  const n = path.length - 1;
  const out = path.map((e) => e.slice());
  const one = out[i][2];
  const zero = out[i][1];
  let next = out[n][3];
  for (let j = n - 1; j >= 0; j--) {
    if (one !== 0) {
      const tmp = out[j][3];
      out[j][3] = (next * (n + 1)) / ((j + 1) * one);
      next = tmp - (out[j][3] * zero * (n - j)) / (n + 1);
    } else {
      out[j][3] = (out[j][3] * (n + 1)) / (zero * (n - j));
    }
  }
  for (let j = i; j < n; j++) {
    out[j][0] = out[j + 1][0];
    out[j][1] = out[j + 1][1];
    out[j][2] = out[j + 1][2];
  }
  return out.slice(0, n);
}

function unwoundSum(path, i) {
  return unwind(path, i).reduce((s, e) => s + e[3], 0);
}

function treeContributions(tree, x, phi) {
  if (tree.f.length === 0) return;
  const recurse = (node, path0, pz, po, pi) => {
    let path = extend(path0, pz, po, pi);
    if (node < 0) {
      const leaf = tree.v[~node];
      for (let i = 1; i < path.length; i++) {
        phi[path[i][0]] += unwoundSum(path, i) * (path[i][2] - path[i][1]) * leaf;
      }
      return;
    }
    const f = tree.f[node];
    const left = tree.l[node];
    const right = tree.r[node];
    const [hot, cold] = goesLeft(tree, node, x[f]) ? [left, right] : [right, left];
    let iz = 1;
    let io = 1;
    let k = -1;
    for (let j = 1; j < path.length; j++) {
      if (path[j][0] === f) {
        k = j;
        break;
      }
    }
    if (k >= 0) {
      iz = path[k][1];
      io = path[k][2];
      path = unwind(path, k);
    }
    const c = tree.c[node];
    recurse(hot, path, (iz * cover(tree, hot)) / c, io, f);
    recurse(cold, path, (iz * cover(tree, cold)) / c, 0, f);
  };
  recurse(0, [], 1, 1, -1);
}

// Log-odds contribution of each feature; `values` in the order of model.names.
export function contributions(trees, values) {
  const x = values.map((v) => Math.fround(v));
  const phi = new Array(x.length).fill(0);
  for (const tree of trees) treeContributions(tree, x, phi);
  return phi;
}

// Same text as fmt() in models/explain.py.
export function fmt(v) {
  return Number.isInteger(v) ? String(v) : v.toFixed(2);
}

// Up to `top` sentences for the features pushing hardest toward phishing.
export function reasons(phi, values, names, rules, { top, min_logodds: minLogodds }) {
  const order = phi.map((_, i) => i).sort((a, b) => phi[b] - phi[a] || a - b);
  const out = [];
  for (const i of order) {
    if (out.length === top || phi[i] < minLogodds) break;
    const v = Math.fround(values[i]);
    const rule = rules[names[i]];
    if (Number.isNaN(v)) continue;
    if ((rule.lo !== null && v < rule.lo) || (rule.hi !== null && v > rule.hi)) continue;
    out.push({ feature: names[i], contribution: phi[i], text: rule.text.replace("{v}", fmt(v)) });
  }
  return out;
}
