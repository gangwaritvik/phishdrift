// Theme switch shared by the URL check page and the extension: five themes, one round swatch each;
// picking one ripples the new theme out from that swatch (View Transitions API; an instant change
// where it is missing or reduced motion is on). The caller says where the choice is saved.
export const THEMES = [
  ["paper", "Paper", "#F3EEE3", "#15130E"],
  ["midnight", "Midnight", "#090C12", "#5EE6D0"],
  ["pop", "Pop", "#FFD23F", "#3D5AFE"],
  ["clinic", "Clinic", "#F4F7F9", "#0E7C86"],
  ["terminal", "Terminal", "#050805", "#6CFF6C"],
];
const ids = THEMES.map(([id]) => id);

export function startTheme(...wanted) {
  return wanted.find((t) => ids.includes(t)) ?? (matchMedia("(prefers-color-scheme: dark)").matches ? "midnight" : "paper");
}

export function setTheme(id, from, save) {
  const apply = () => {
    document.documentElement.dataset.theme = id;
    for (const b of document.querySelectorAll(".lens button")) {
      b.setAttribute("aria-checked", String(b.dataset.id === id));
      b.tabIndex = b.dataset.id === id ? 0 : -1;
    }
    save?.(id);
  };
  if (!document.startViewTransition || matchMedia("(prefers-reduced-motion: reduce)").matches || !from) return apply();
  const r = from.getBoundingClientRect();
  const x = r.left + r.width / 2;
  const y = r.top + r.height / 2;
  const end = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
  document.startViewTransition(apply).ready.then(() =>
    document.documentElement.animate(
      { clipPath: [`circle(0 at ${x}px ${y}px)`, `circle(${end}px at ${x}px ${y}px)`] },
      { duration: 700, easing: "cubic-bezier(.4,0,.2,1)", pseudoElement: "::view-transition-new(root)" },
    ),
  );
}

// Fills `lens` (a div with class "lens") with the swatches; `save(id)` stores the choice.
export function buildLens(lens, save) {
  lens.setAttribute("role", "radiogroup");
  lens.setAttribute("aria-label", "Theme");
  for (const [id, name, a, b] of THEMES) {
    const btn = Object.assign(document.createElement("button"), { type: "button" });
    btn.dataset.id = id;
    btn.setAttribute("role", "radio");
    btn.setAttribute("aria-label", `${name} theme`);
    btn.style.setProperty("--a", a);
    btn.style.setProperty("--b", b);
    btn.append(Object.assign(document.createElement("span"), { textContent: name }));
    btn.addEventListener("click", () => setTheme(id, btn, save));
    lens.append(btn);
  }
  lens.addEventListener("keydown", (e) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const next = ids[(ids.indexOf(document.documentElement.dataset.theme) + step + ids.length) % ids.length];
    const btn = lens.querySelector(`[data-id=${next}]`);
    setTheme(next, btn, save);
    btn.focus();
  });
}
