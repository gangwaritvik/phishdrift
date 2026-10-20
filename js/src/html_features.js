// Tier B page features, a line-by-line port of features/html_features.py.
//
// The page is parsed once with js/src/htmlparser.js (a port of CPython's html.parser), fed in
// the same FEED_CHUNK pieces as Python. Python string semantics come from js/src/pystr.js:
// lengths, slices and caps are in code points, whitespace is str.isspace, regexes use
// Python's \s \w \b, lower() is Python's. Missing values are NaN; an unusable page (no HTML,
// little visible text, a parked / error page, a timeout or a failure) gives NaN everywhere.
//
//   import { buildLists } from "./features.js";
//   const lists = buildLists(listsJson, pslRules);   // the tier A lists object
//   const values = extractHtml(url, html, lists);     // { n_forms: 1, ... } keyed by NAMES_B

import { HTMLParser } from "./htmlparser.js";
import {
  cpBack, cpForward, cpHead, cpLen, foldI, pyJoinSplit, pyLower, pyRegex, pyStrip, stripChars,
} from "./pystr.js";
import { isDigitStr, parse } from "./urlparts.js";

export const NAMES_B = [
  "n_forms", "n_password_fields", "n_credential_forms", "n_password_outside_form",
  "n_password_forms_external", "n_input_hidden", "hidden_input_ratio", "has_submit_button",
  "n_form_action_empty", "n_form_action_hash", "n_form_action_js", "n_form_action_mailto",
  "n_form_action_external", "n_otp_fields", "n_card_fields", "n_cvv_fields", "n_upi_pin_fields",
  "n_links", "link_internal_ratio", "link_external_ratio", "link_null_ratio",
  "n_external_link_domains", "n_anchor_text_mismatch", "n_links_insecure_http", "n_links_ip_host",
  "n_links_shortener", "has_base_external", "meta_script_link_internal_ratio", "n_script_src",
  "script_external_ratio", "css_external_ratio", "n_img", "img_external_ratio", "n_img_data_uri",
  "has_favicon", "favicon_external", "resource_external_ratio", "n_external_resource_domains",
  "has_title", "title_empty", "title_has_credential_word", "domain_in_title",
  "title_domain_match", "url_title_match", "has_description", "has_copyright",
  "domain_in_copyright", "n_bank_words", "n_pay_words", "n_crypto_words", "n_urgency_words",
  "n_credential_words", "brand_in_title_mismatch", "n_brands_in_text_mismatch", "n_social_links",
  "page_size", "n_lines", "longest_line", "visible_text_len", "text_to_code_ratio", "n_tags",
  "max_dom_depth", "n_iframes", "n_hidden_iframes", "has_meta_refresh", "meta_refresh_external",
  "right_click_disabled", "n_onmouseover", "n_window_open", "n_js_redirects",
  "has_viewport_meta", "robots_noindex", "n_scripts_inline", "script_chars_ratio", "n_eval",
  "n_atob", "n_unescape", "n_document_write", "n_fromcharcode", "script_entropy",
  "script_escape_ratio", "n_ajax_calls", "n_telegram_endpoints", "n_webhook_endpoints",
];

// Work limits (per page), as in Python.
export const MAX_HTML_CHARS = 500_000;
export const MIN_VISIBLE_CHARS = 200;
export const MAX_PAGE_SECONDS = 8.0;
const MAX_EVENTS = 300_000;
export const FEED_CHUNK = 32_768;
const TIME_CHECK_EVERY = 256;
const MAX_TEXT_CHARS = 300_000;
const MAX_SCRIPT_CHARS = 300_000;
const MAX_TOKENS = 30_000;
const MAX_REFS = 3_000;
const MAX_STACK = 512;
const STACK_SEARCH = 64;
const MAX_ANCHOR_TEXT = 200;
const MAX_TITLE_CHARS = 300;
const ENTROPY_CHARS = 50_000;
const MIN_ENTROPY_CHARS = 100;
const JUNK_MAX_TEXT = 2_000;
const JUNK_SCAN_CHARS = 2_000;
const BRAND_TEXT_MIN = 2;
const COPYRIGHT_BEFORE = 60;
const COPYRIGHT_SKIP = new Set(["copyright", "c", "all", "rights", "reserved"]); // brand-page rule only
const COPYRIGHT_AFTER = 100;

const words = (s) => s.split(" ");
const VOID_TAGS = new Set(words(
  "area base basefont bgsound br col command embed frame hr img input keygen link meta " +
    "param source track wbr",
));
const IMPLICIT_END = new Set(words("p li option tr td th dt dd thead tbody tfoot"));
const JS_TYPES = ["javascript", "ecmascript", "module", "jsx", "babel"];
const MEDIA_TAGS = new Set(words("video audio source embed object track"));
const SOCIAL_DOMAINS = words(
  "facebook.com fb.com twitter.com x.com instagram.com linkedin.com youtube.com youtu.be " +
    "pinterest.com tiktok.com whatsapp.com wa.me t.me telegram.me reddit.com snapchat.com",
);

const BANK_WORDS = (
  "bank,banking,netbanking,ifsc,iban,swift,atm,account number,credit card,debit card," +
  "net banking,internet banking,online banking,bank account,routing number"
).split(",");
const PAY_WORDS = (
  "payment,payments,pay,pay now,invoice,billing,checkout,transaction,refund,wallet,upi," +
  "card number,cvv,expiry date,expiration date,security code,billing address"
).split(",");
const CRYPTO_WORDS = (
  "bitcoin,btc,ethereum,eth,crypto,cryptocurrency,wallet,seed phrase,recovery phrase," +
  "private key,metamask,blockchain,usdt,airdrop,nft,binance,coinbase,ledger,trezor," +
  "connect wallet,defi"
).split(",");
const URGENCY_WORDS = (
  "urgent,urgently,immediately,suspended,suspend,suspension,expire,expires,expired,expiring," +
  "within 24 hours,within 48 hours,action required,unusual activity,suspicious activity," +
  "unauthorized,unauthorised,locked,final notice,final warning,restricted,deactivated," +
  "terminated,verify your,confirm your,security alert,limited access,act now,last chance," +
  "will be closed,will be suspended,will be deactivated,will be terminated"
).split(",");
const CREDENTIAL_WORDS = (
  "login,log in,sign in,signin,password,username,user name,passcode,otp,forgot password," +
  "verification code,pin,credentials"
).split(",");
const TITLE_WORDS = [...new Set([...CREDENTIAL_WORDS, ...words("verify verification confirm account secure update suspended")])];

// Patterns: the Python sources, rewritten by pyRegex (flag "i" = re.I, used on foldI(text)).
const TOKEN = /[a-z0-9]+/g;
const ALNUM = /[^a-z0-9]+/g;
const SPACES = pyRegex(String.raw`\s+`, "g");
const COPYRIGHT = pyRegex(String.raw`©|copyright|all rights reserved`, "i");
const TEXT_DOMAIN = pyRegex(
  String.raw`^(?:https?://)?(?:[a-z0-9\-]+\.)+[a-z]{2,24}(?:[/:?#]\S*)?$`, "i",
);
const AUTHORITY = pyRegex(String.raw`^(?:[a-z][a-z0-9+.\-]*:)?[/\\]{2}([^/?#\\]*)`, "i");
const SCHEME = pyRegex(String.raw`^([a-z][a-z0-9+.\-]*):`, "i");
const REFRESH_URL = pyRegex(String.raw`url\s*=\s*['"]?([^'";]+)`, "id");

const OTP = pyRegex(
  String.raw`(?<![a-z])otp(?![a-z])|one[\s_\-]?time|verif\w*[\s_\-]?code|sms[\s_\-]?code|2fa|` +
    String.raw`(?<![a-z])mfa(?![a-z])|auth\w*[\s_\-]?code|passcode`,
);
const CARD = pyRegex(String.raw`(?<![a-z])card|(?<![a-z])cc[\s_\-]?(?:num|number|no)|ccnum`);
const CVV = pyRegex(
  String.raw`cvv|cvc|cvn|(?<![a-z])csc(?![a-z])|card[\s_\-]?code|security[\s_\-]?code`,
);
const PIN = pyRegex(
  String.raw`upi[\s_\-]?pin|(?<![a-z])m?pin(?![a-z])|atm[\s_\-]?pin|(?:debit|card)[\s_\-]?pin`,
);
const NON_TEXT_INPUTS = new Set(words("hidden submit button image reset checkbox radio file range color"));

const EVAL = pyRegex(String.raw`eval\s*\(|new\s+function\s*\(`, "g");
const ATOB = pyRegex(String.raw`atob\s*\(`, "g");
const UNESCAPE = pyRegex(String.raw`unescape\s*\(`, "g");
const DOC_WRITE = pyRegex(String.raw`document\.write(?:ln)?\s*\(`, "g");
const FROMCHAR = pyRegex(String.raw`string\.fromcharcode`, "g");
const WINDOW_OPEN = pyRegex(String.raw`window\.open\s*\(`, "g");
const LOC_ASSIGN = pyRegex(String.raw`location(?:\.href)?\s*=(?!=)`, "g");
const LOC_CALL = pyRegex(String.raw`location\.(?:replace|assign)\s*\(`, "g");
const AJAX = pyRegex(
  String.raw`xmlhttprequest|fetch\s*\(|\$\.(?:ajax|post|get)\s*\(|\.ajax\s*\(|sendbeacon`, "g",
);
const TELEGRAM = pyRegex(String.raw`api\.telegram\.org`, "g");
const WEBHOOK = pyRegex(
  String.raw`discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|formspree\.io|` +
    String.raw`formsubmit\.co|getform\.io|web3forms\.com|script\.google\.com/macros|emailjs|` +
    String.raw`pipedream\.net|requestbin|submit-form\.com|ngrok`,
  "g",
);
const ESCAPES = pyRegex(String.raw`\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\[0-7]{3}`, "gi");
const CONTEXTMENU_OFF = pyRegex(String.raw`return\s+false|preventdefault`);

const JUNK_TITLE = pyRegex(
  String.raw`^\W*(?:(?:http\s*)?(?:error\s*)?(?:400|401|403|404|405|410|429|500|502|503|504|520|521|522` +
    String.raw`|523|524|525)\b|error\b|not found|page not found|access denied|forbidden\b|` +
    String.raw`service (?:temporarily )?unavailable|bad gateway|gateway time-?out|just a moment|` +
    String.raw`attention required|please wait|checking your browser|account suspended|` +
    String.raw`(?:this )?(?:site|website|page|domain) (?:is |has been )?(?:suspended|disabled|blocked|` +
    String.raw`unavailable|removed|expired|parked)|domain (?:for sale|expired|parking|parked)|parked\b|` +
    String.raw`default (?:web )?(?:site )?page|welcome to nginx|apache2? .{0,30}default page|it works\b|` +
    String.raw`index of /|under construction|coming soon|website disabled|buy this domain|sedo\b|` +
    String.raw`hugedomains|suspended page)`,
  "i",
);
const JUNK_BODY = pyRegex(
  String.raw`this (?:web)?site can.?t be reached|dns_probe|` +
    String.raw`(?:this )?domain (?:name )?(?:is |may be |has )?(?:for sale|expired|parked|available)|` +
    String.raw`(?:buy|purchase|inquire about) this domain|parked (?:free|domain|by|at|with)|` +
    String.raw`sedoparking|hugedomains|afternic|` +
    String.raw`this (?:account|site|website|page|domain|web page) (?:has been|is|was) (?:temporarily )?` +
    String.raw`(?:suspended|disabled|deactivated|removed|taken down|blocked|banned)|` +
    String.raw`(?:has|have) been (?:taken down|removed) (?:due|because|for)|` +
    String.raw`deceptive site ahead|reported (?:as )?(?:an )?(?:attack|phishing|unsafe)|` +
    String.raw`(?:error|http)\s*(?:403|404|500|502|503)|(?:403|404|500|502|503)\s*` +
    String.raw`(?:error|forbidden|not found|service)|not found on this server|` +
    String.raw`the requested url was not found|welcome to nginx|apache2? .{0,30}default page|` +
    String.raw`it works!|index of /|default web site page|` +
    String.raw`enable javascript and cookies to continue|checking if the site connection is secure|` +
    String.raw`ddos protection by|you don.?t have permission to access|` +
    String.raw`(?:site|website) is (?:currently )?(?:unavailable|under maintenance|down)|` +
    String.raw`under construction|coming soon|temporarily unavailable`,
);

class Abort extends Error {}
class Timeout extends Error {}

const now = () => (globalThis.performance ? globalThis.performance.now() : Date.now());

const ref = (kind, domain = "", isIp = false, isShort = false, isSocial = false) => ({
  kind, domain, isIp, isShort, isSocial,
});
const EMPTY = ref("empty");
const NULL = ref("null");
const DATA = ref("data");
const OTHER = ref("other");

const norm = (text) => pyLower(text).replace(ALNUM, "");
const ratio = (count, total) => (total ? count / total : NaN);
const countAll = (re, s) => {
  let n = 0;
  for (const _ of s.matchAll(re)) n++;
  return n;
};

// Python: -sum(c / n * math.log2(c / n) for c in Counter(text).values()); CPython's sum() of
// floats is Neumaier-compensated (3.12+), done the same way here.
function entropy(text) {
  const counts = new Map();
  let n = 0;
  for (const ch of text) {
    counts.set(ch, (counts.get(ch) || 0) + 1);
    n++;
  }
  let total = 0;
  let comp = 0;
  let first = true;
  for (const c of counts.values()) {
    const x = (c / n) * Math.log2(c / n);
    if (first) {
      total = x;
      first = false;
      continue;
    }
    const t = total + x;
    if (Math.abs(total) >= Math.abs(x)) comp += total - t + x;
    else comp += x - t + total;
    total = t;
  }
  if (comp && Number.isFinite(comp)) total += comp;
  return -total;
}

const under = (host, domains) => {
  for (const d of domains) if (host === d || host.endsWith(`.${d}`)) return true;
  return false;
};

function rsplitLast(s, sep) {
  const i = s.lastIndexOf(sep);
  return i < 0 ? s : s.slice(i + sep.length);
}

class Resolver {
  constructor(parts, lists) {
    this.lists = lists;
    this.shorteners = [...lists.shorteners];
    this.pageDomain = parts.domain;
    this.internal = ref("internal", parts.domain);
    this.cache = new Map();
  }

  host(authority) {
    const cached = this.cache.get(authority);
    if (cached !== undefined) return cached;
    const host = rsplitLast(authority, "@");
    const p = parse(host, this.lists.platforms, this.lists.psl);
    let r;
    if (p === null) r = OTHER;
    else {
      let bare = host.split(":").length - 1 === 1 ? host.slice(0, host.lastIndexOf(":")) : host;
      bare = stripChars(bare, "[]");
      if (bare.startsWith("www.")) bare = bare.slice(4);
      const kind = p.domain === this.pageDomain ? "internal" : "external";
      r = ref(kind, p.domain, p.isIp, under(bare, this.shorteners), under(bare, SOCIAL_DOMAINS));
    }
    if (this.cache.size < 2_000) this.cache.set(authority, r);
    return r;
  }

  ref(raw) {
    if (raw === null || raw === undefined) return EMPTY;
    const s = pyStrip(raw).replaceAll("\t", "").replaceAll("\n", "").replaceAll("\r", "");
    if (!s) return EMPTY;
    if (s[0] === "#") return NULL;
    const m = SCHEME.exec(foldI(s));
    if (m) {
      const scheme = pyLower(s.slice(0, m[1].length));
      if (scheme === "javascript" || scheme === "vbscript") return NULL;
      if (scheme === "data" || scheme === "blob") return DATA;
      if (!["http", "https", "ftp", "ws", "wss"].includes(scheme)) return OTHER;
    } else if (!(s.startsWith("//") || s.startsWith("\\\\"))) return this.internal;
    const a = AUTHORITY.exec(foldI(s));
    if (a === null) return this.internal;
    const end = a[0].length;
    const authority = pyLower(s.slice(end - a[1].length, end));
    if (!authority) return this.internal;
    return this.host(authority);
  }

  textDomain(text) {
    if (cpLen(text) > 120 || !TEXT_DOMAIN.test(foldI(text))) return null;
    let s = pyLower(text);
    if (s.startsWith("http://") || s.startsWith("https://")) s = s.slice(s.indexOf("//") + 2);
    const authority = s.split(/[/?#]/, 1)[0];
    const p = parse(authority, this.lists.platforms, this.lists.psl);
    if (p === null || !p.suffix) return null;
    return p.domain;
  }
}

function hiddenFrame(a) {
  if (a.has("hidden")) return true;
  for (const key of ["width", "height"]) {
    let value = pyLower(pyStrip(a.get(key) ?? ""));
    if (value.endsWith("px")) value = value.slice(0, -2);
    value = pyStrip(value);
    if (value === "0" || value === "1") return true;
  }
  const style = pyLower(a.get("style") ?? "").replaceAll(" ", "");
  return ["display:none", "visibility:hidden", "width:0", "height:0"].some((t) => style.includes(t));
}

// One pass over the page. Keeps counts and small bounded lists, never the DOM.
class Collector extends HTMLParser {
  constructor(deadline) {
    super();
    Object.assign(this, {
      deadline, events: 0, nTags: 0, stack: [], maxDepth: 0,
      textParts: [], textLen: 0, titleSeen: false, titleDone: false, inTitle: false,
      titleParts: [], titleLen: 0, skip: 0,
      inScript: false, scriptIsJs: false, scriptBuf: [], scriptBufLen: 0, scriptTexts: [],
      scriptLen: 0, nScriptsInline: 0, scriptSrcs: [], inStyle: false, handlerParts: [],
      handlerLen: 0, rightClickAttr: false, nOnmouseover: 0,
      anchors: [], anchorHref: null, anchorBuf: [], anchorLen: 0, cssHrefs: [], iconHrefs: [],
      linkTagHrefs: [], metaUrls: [], imgSrcs: [], mediaSrcs: [], frameSrcs: [], nFrames: 0,
      nHiddenFrames: 0, baseHref: null,
      hasDescription: false, siteName: "", hasViewport: false, robotsNoindex: false, refresh: null,
      nForms: 0, form: null, forms: [], nPassword: 0, nPasswordOutside: 0, nInputs: 0,
      nHidden: 0, hasSubmit: false, nOtp: 0, nCard: 0, nCvv: 0, nPin: 0,
    });
  }

  tick() {
    this.events += 1;
    if (this.events > MAX_EVENTS) throw new Abort();
    if (this.events % TIME_CHECK_EVERY === 0 && now() > this.deadline) throw new Timeout();
  }

  push(tag) {
    const stack = this.stack;
    if (IMPLICIT_END.has(tag) && stack.length && stack[stack.length - 1] === tag) stack.pop();
    if (stack.length < MAX_STACK) stack.push(tag);
    this.maxDepth = Math.max(this.maxDepth, stack.length);
  }

  pop(tag) {
    const stack = this.stack;
    const low = Math.max(0, stack.length - STACK_SEARCH);
    for (let i = stack.length - 1; i >= low; i--) {
      if (stack[i] === tag) {
        stack.length = i;
        return;
      }
    }
  }

  endAnchor() {
    if (this.anchorHref !== null && this.anchors.length < MAX_REFS) {
      const text = pyStrip(this.anchorBuf.join("").replace(SPACES, " "));
      this.anchors.push([this.anchorHref, text]);
    }
    this.anchorHref = null;
    this.anchorBuf = [];
    this.anchorLen = 0;
  }

  endForm() {
    if (this.form !== null) this.forms.push([this.form[0], this.form[1]]);
    this.form = null;
  }

  endScript() {
    if (this.scriptIsJs) {
      const text = this.scriptBuf.join("");
      if (pyStrip(text)) {
        this.nScriptsInline += 1;
        if (this.scriptLen < MAX_SCRIPT_CHARS) {
          const piece = cpHead(text, MAX_SCRIPT_CHARS - this.scriptLen);
          this.scriptTexts.push(piece);
          this.scriptLen += cpLen(piece);
        }
      }
    }
    this.scriptBuf = [];
    this.scriptBufLen = 0;
    this.inScript = false;
    this.scriptIsJs = false;
  }

  finish() {
    this.endAnchor();
    this.endForm();
    if (this.inScript) this.endScript();
  }

  handle_startendtag(tag, attrs) {
    this.start(tag, attrs, true);
  }

  handle_starttag(tag, attrs) {
    this.start(tag, attrs, false);
  }

  start(tag, attrs, selfClosing) {
    this.tick();
    this.nTags += 1;
    this.inTitle = false;
    const a = new Map();
    for (const [key, value] of attrs) if (!a.has(key)) a.set(key, value || "");
    for (const [key, value] of a) {
      if (key.startsWith("on") && key.length > 2) {
        if (key === "onmouseover") this.nOnmouseover += 1;
        else if (key === "oncontextmenu") {
          const low = pyLower(value);
          if (CONTEXTMENU_OFF.test(low) || low.includes("false")) this.rightClickAttr = true;
        }
        if (this.handlerLen < MAX_SCRIPT_CHARS && value) {
          this.handlerParts.push(cpHead(value, 2000));
          this.handlerLen += Math.min(cpLen(value), 2000);
        }
      }
    }
    if (!(VOID_TAGS.has(tag) || selfClosing)) this.push(tag);

    if (tag === "a") {
      if (a.has("href")) {
        this.endAnchor();
        this.anchorHref = a.get("href");
      }
    } else if (tag === "input") this.input(a);
    else if (tag === "form") {
      this.endForm();
      this.nForms += 1;
      this.form = [a.has("action") ? a.get("action") : null, 0];
    } else if (tag === "button") {
      const kind = pyLower(pyStrip(a.get("type") ?? ""));
      if ((kind === "submit" || kind === "") && this.form !== null) this.hasSubmit = true;
    } else if (tag === "script") {
      if (a.has("src")) this.scriptSrcs.push(a.get("src"));
      if (!selfClosing) {
        const kind = pyLower(pyStrip(a.get("type") ?? ""));
        this.inScript = true;
        this.scriptIsJs = !a.has("src") && (!kind || JS_TYPES.some((t) => kind.includes(t)));
      }
    } else if (tag === "style") {
      if (!selfClosing) this.inStyle = true;
    } else if (tag === "link") {
      const rel = pyLower(a.get("rel") ?? "");
      const href = a.get("href");
      if (href !== undefined) {
        if (rel.includes("stylesheet")) this.cssHrefs.push(href);
        if (rel.includes("icon")) this.iconHrefs.push(href);
        if (this.linkTagHrefs.length < MAX_REFS) this.linkTagHrefs.push(href);
      }
    } else if (tag === "img") {
      const src = a.get("src") || a.get("data-src");
      if (src !== undefined && this.imgSrcs.length < MAX_REFS) this.imgSrcs.push(src);
    } else if (tag === "iframe" || tag === "frame") {
      this.nFrames += 1;
      if (a.get("src") !== undefined && this.frameSrcs.length < MAX_REFS) this.frameSrcs.push(a.get("src"));
      if (hiddenFrame(a)) this.nHiddenFrames += 1;
    } else if (MEDIA_TAGS.has(tag)) {
      const src = a.get("src") || a.get("data");
      if (src !== undefined && this.mediaSrcs.length < MAX_REFS) this.mediaSrcs.push(src);
    } else if (tag === "meta") this.meta(a);
    else if (tag === "base") {
      if (a.has("href") && this.baseHref === null) this.baseHref = a.get("href");
    } else if (tag === "title") {
      if (!selfClosing) {
        this.inTitle = true;
        this.titleSeen = true;
      }
    } else if ((tag === "noscript" || tag === "template") && !selfClosing) this.skip += 1;
  }

  input(a) {
    const kind = pyLower(pyStrip(a.get("type") ?? "")) || "text";
    this.nInputs += 1;
    if (kind === "hidden") {
      this.nHidden += 1;
      return;
    }
    if (kind === "submit" || kind === "image") this.hasSubmit = true;
    if (kind === "password") {
      this.nPassword += 1;
      if (this.form !== null) this.form[1] += 1;
      else this.nPasswordOutside += 1;
    }
    if (NON_TEXT_INPUTS.has(kind)) return;
    const hint = pyLower(
      ["name", "id", "placeholder", "autocomplete", "aria-label", "title"].map((k) => a.get(k) ?? "").join(" "),
    );
    if (!pyStrip(hint)) return;
    this.nOtp += +OTP.test(hint);
    this.nCard += +CARD.test(hint);
    this.nCvv += +CVV.test(hint);
    this.nPin += +PIN.test(hint);
  }

  meta(a) {
    const name = pyLower(pyStrip(a.get("name") ?? ""));
    const content = a.get("content") ?? "";
    const equiv = pyLower(pyStrip(a.get("http-equiv") ?? ""));
    const prop = pyLower(pyStrip(a.get("property") ?? ""));
    if (prop === "og:site_name" && !this.siteName) this.siteName = cpHead(content, MAX_TITLE_CHARS);
    if (equiv === "refresh" && this.refresh === null) this.refresh = content;
    if (name === "description" && pyStrip(content)) this.hasDescription = true;
    else if (name === "viewport") this.hasViewport = true;
    else if ((name === "robots" || name === "googlebot") && pyLower(content).includes("noindex")) {
      this.robotsNoindex = true;
    }
    const low = pyLower(pyStrip(content));
    if (
      (low.startsWith("http://") || low.startsWith("https://") || low.startsWith("//")) &&
      this.metaUrls.length < MAX_REFS
    ) {
      this.metaUrls.push(content);
    }
  }

  handle_endtag(tag) {
    this.tick();
    if (tag === "a") this.endAnchor();
    else if (tag === "form") this.endForm();
    else if (tag === "script") {
      if (this.inScript) this.endScript();
    } else if (tag === "style") this.inStyle = false;
    else if (tag === "title") {
      if (this.inTitle) this.titleDone = true;
      this.inTitle = false;
    } else if ((tag === "noscript" || tag === "template") && this.skip > 0) this.skip -= 1;
    if (!VOID_TAGS.has(tag)) this.pop(tag);
  }

  handle_data(data) {
    this.tick();
    if (this.inScript) {
      if (this.scriptIsJs && this.scriptBufLen < MAX_SCRIPT_CHARS) {
        this.scriptBuf.push(data);
        this.scriptBufLen += cpLen(data);
      }
      return;
    }
    if (this.inStyle) return;
    if (this.inTitle) {
      if (!this.titleDone && this.titleLen < MAX_TITLE_CHARS) {
        this.titleParts.push(data);
        this.titleLen += cpLen(data);
      }
      return;
    }
    if (this.skip) return;
    const s = pyJoinSplit(data);
    if (!s) return;
    if (this.textLen < MAX_TEXT_CHARS) {
      const piece = cpHead(s, MAX_TEXT_CHARS - this.textLen);
      this.textParts.push(piece);
      this.textLen += cpLen(piece) + 1;
    }
    if (this.anchorHref !== null && this.anchorLen < MAX_ANCHOR_TEXT) {
      this.anchorBuf.push(`${s} `);
      this.anchorLen += cpLen(s) + 1;
    }
  }

  handle_comment() {
    this.tick();
  }

  handle_decl() {
    this.tick();
  }

  handle_pi() {
    this.tick();
  }

  unknown_decl() {
    this.tick();
  }

  get text() {
    return this.textParts.join(" ");
  }

  get title() {
    return cpHead(pyJoinSplit(this.titleParts.join("")), MAX_TITLE_CHARS);
  }
}

// Python: for start in range(0, len(html), FEED_CHUNK): feed(html[start:start + FEED_CHUNK]),
// pieces counted in code points.
function parsePage(html, deadline) {
  const parser = new Collector(deadline);
  try {
    let start = 0;
    while (start < html.length) {
      const stop = cpForward(html, start, FEED_CHUNK);
      parser.feed(html.slice(start, stop));
      start = stop;
      if (now() > deadline) throw new Timeout();
    }
    parser.close();
  } catch (e) {
    if (!(e instanceof Abort)) throw e;
  }
  parser.finish();
  return parser;
}

function isJunk(c, text) {
  if (c.nPassword || cpLen(text) >= JUNK_MAX_TEXT) return false;
  return JUNK_TITLE.test(foldI(pyLower(c.title))) || JUNK_BODY.test(pyLower(cpHead(text, JUNK_SCAN_CHARS)));
}

function grams(tokens) {
  const g = new Map();
  const add = (k) => g.set(k, (g.get(k) || 0) + 1);
  for (const t of tokens) add(t);
  for (let i = 0; i + 1 < tokens.length; i++) add(`${tokens[i]} ${tokens[i + 1]}`);
  for (let i = 0; i + 2 < tokens.length; i++) add(`${tokens[i]} ${tokens[i + 1]} ${tokens[i + 2]}`);
  return g;
}

function brandHits(g, brands) {
  const hits = new Map();
  for (const [gram, n] of g) {
    const key = gram.includes(" ") ? gram.replaceAll(" ", "") : gram;
    if (brands.has(key)) hits.set(key, (hits.get(key) || 0) + n);
  }
  return hits;
}

const countPhrases = (g, phrases) => phrases.reduce((n, p) => n + (g.get(p) || 0), 0);

function trigrams(s) {
  const out = new Set();
  for (let i = 0; i + 2 < s.length; i++) out.add(s.slice(i, i + 3)); // s is ASCII (norm)
  return out;
}

function tokensOf(lowText, limit = Infinity) {
  const out = [];
  for (const m of lowText.matchAll(TOKEN)) {
    if (out.length >= limit) break;
    out.push(m[0]);
  }
  return out;
}

function classifyAll(res, refs) {
  let internal = 0;
  let external = 0;
  const domains = new Set();
  for (const raw of refs) {
    const r = res.ref(raw);
    if (r.kind === "internal") internal += 1;
    else if (r.kind === "external") {
      external += 1;
      domains.add(r.domain);
    }
  }
  return [internal, external, domains];
}

function compute(c, html, size, parts, lists, text) {
  const out = {};
  const res = new Resolver(parts, lists);
  const nHtml = cpLen(html);

  // ---- forms ----
  const kinds = { empty: 0, hash: 0, js: 0, mailto: 0, external: 0 };
  let nCred = 0;
  let nCredExt = 0;
  const formActions = [];
  for (const [action, nPass] of c.forms) {
    const raw = pyStrip(action ?? "");
    const low = pyLower(raw);
    if (action !== null) formActions.push(raw);
    if (!raw) kinds.empty += 1;
    else if (raw.startsWith("#")) kinds.hash += 1;
    else if (low.startsWith("javascript:")) kinds.js += 1;
    else if (low.startsWith("mailto:")) kinds.mailto += 1;
    else if (res.ref(raw).kind === "external") {
      kinds.external += 1;
      if (nPass) nCredExt += 1;
    }
    if (nPass) nCred += 1;
  }
  Object.assign(out, {
    n_forms: c.nForms,
    n_password_fields: c.nPassword,
    n_credential_forms: nCred,
    n_password_outside_form: c.nPasswordOutside,
    n_password_forms_external: nCredExt,
    n_input_hidden: c.nHidden,
    hidden_input_ratio: ratio(c.nHidden, c.nInputs),
    has_submit_button: +c.hasSubmit,
    n_form_action_empty: kinds.empty,
    n_form_action_hash: kinds.hash,
    n_form_action_js: kinds.js,
    n_form_action_mailto: kinds.mailto,
    n_form_action_external: kinds.external,
    n_otp_fields: c.nOtp,
    n_card_fields: c.nCard,
    n_cvv_fields: c.nCvv,
    n_upi_pin_fields: c.nPin,
  });

  // ---- links ----
  const linkKinds = { internal: 0, external: 0, null: 0, empty: 0 };
  const extDomains = new Set();
  let mismatch = 0;
  let insecure = 0;
  let ipHosts = 0;
  let shorteners = 0;
  let socials = 0;
  for (const [href, anchorText] of c.anchors) {
    const r = res.ref(href);
    linkKinds[r.kind] = (linkKinds[r.kind] || 0) + 1;
    if (r.kind === "external") {
      extDomains.add(r.domain);
      ipHosts += +r.isIp;
      shorteners += +r.isShort;
      socials += +r.isSocial;
    }
    if (pyLower(pyStrip(href)).startsWith("http://")) insecure += 1;
    if ((r.kind === "internal" || r.kind === "external") && anchorText) {
      const claimed = res.textDomain(anchorText);
      if (claimed !== null && claimed !== r.domain) mismatch += 1;
    }
  }
  const nLinks = c.anchors.length;
  out.n_links = nLinks;
  out.link_internal_ratio = ratio(linkKinds.internal, nLinks);
  out.link_external_ratio = ratio(linkKinds.external, nLinks);
  out.link_null_ratio = ratio(linkKinds.null + linkKinds.empty, nLinks);
  out.n_external_link_domains = extDomains.size;
  out.n_anchor_text_mismatch = mismatch;
  out.n_links_insecure_http = insecure;
  out.n_links_ip_host = ipHosts;
  out.n_links_shortener = shorteners;
  out.has_base_external = +(c.baseHref !== null && res.ref(c.baseHref).kind === "external");
  const [tagInt, tagExt] = classifyAll(res, [...c.metaUrls, ...c.scriptSrcs, ...c.linkTagHrefs]);
  out.meta_script_link_internal_ratio = ratio(tagInt, tagInt + tagExt);

  // ---- resources ----
  const [sInt, sExt, sDom] = classifyAll(res, c.scriptSrcs);
  const [cInt, cExt, cDom] = classifyAll(res, c.cssHrefs);
  const [iInt, iExt, iDom] = classifyAll(res, c.imgSrcs);
  const [mInt, mExt, mDom] = classifyAll(res, c.mediaSrcs);
  const [fInt, fExt, fDom] = classifyAll(res, c.frameSrcs);
  out.n_script_src = c.scriptSrcs.length;
  out.script_external_ratio = ratio(sExt, sInt + sExt);
  out.css_external_ratio = ratio(cExt, cInt + cExt);
  out.n_img = c.imgSrcs.length;
  out.img_external_ratio = ratio(iExt, iInt + iExt);
  out.n_img_data_uri = c.imgSrcs.filter((s) => pyLower(pyStrip(s)).startsWith("data:")).length;
  out.has_favicon = +(c.iconHrefs.length > 0);
  out.favicon_external = c.iconHrefs.length
    ? +c.iconHrefs.some((h) => res.ref(h).kind === "external")
    : NaN;
  const allInt = sInt + cInt + iInt + mInt + fInt;
  const allExt = sExt + cExt + iExt + mExt + fExt;
  out.resource_external_ratio = ratio(allExt, allInt + allExt);
  out.n_external_resource_domains = new Set([...sDom, ...cDom, ...iDom, ...mDom, ...fDom]).size;

  // ---- text ----
  const title = c.title;
  const lowText = pyLower(text);
  const tokens = tokensOf(lowText, MAX_TOKENS);
  const g = grams(tokens);
  const label = norm(parts.label);
  const domainOk = !parts.isIp && !parts.isPlatform && label.length >= 3;
  const normTitle = norm(title);
  const titleTokens = tokensOf(pyLower(title));
  const titleGrams = titleTokens.length ? grams(titleTokens) : new Map();
  const hasTitleText = Boolean(normTitle);
  out.has_title = +c.titleSeen;
  out.title_empty = c.titleSeen ? +!hasTitleText : NaN;
  out.title_has_credential_word = hasTitleText ? +TITLE_WORDS.some((w) => titleGrams.has(w)) : NaN;
  if (hasTitleText && domainOk) {
    out.domain_in_title = +normTitle.includes(label);
    const tri = trigrams(label);
    const titleTri = trigrams(normTitle);
    let both = 0;
    for (const t of tri) both += +titleTri.has(t);
    out.title_domain_match = tri.size ? both / tri.size : NaN;
  } else {
    out.domain_in_title = NaN;
    out.title_domain_match = NaN;
  }
  const urlNorm = norm(parts.canon);
  const titleWords = new Set(titleTokens.filter((w) => w.length >= 3));
  let inUrl = 0;
  for (const w of titleWords) inUrl += +urlNorm.includes(w);
  out.url_title_match = titleWords.size ? inUrl / titleWords.size : NaN;
  out.has_description = +c.hasDescription;
  const m = COPYRIGHT.exec(foldI(text));
  out.has_copyright = +(m !== null);
  if (m === null || !domainOk) out.domain_in_copyright = NaN;
  else {
    const from = cpBack(text, m.index, COPYRIGHT_BEFORE);
    const to = cpForward(text, m.index + m[0].length, COPYRIGHT_AFTER);
    out.domain_in_copyright = +norm(text.slice(from, to)).includes(label);
  }
  out.n_bank_words = countPhrases(g, BANK_WORDS);
  out.n_pay_words = countPhrases(g, PAY_WORDS);
  out.n_crypto_words = countPhrases(g, CRYPTO_WORDS);
  out.n_urgency_words = countPhrases(g, URGENCY_WORDS);
  out.n_credential_words = countPhrases(g, CREDENTIAL_WORDS);
  const brands = lists.brandSet;
  if (brands.size) {
    const own = norm(parts.label);
    const foreign = (hits) => hits.filter((b) => !(b === own || (own.length >= 4 && b.startsWith(own))));
    out.brand_in_title_mismatch = hasTitleText
      ? +(foreign([...brandHits(titleGrams, brands).keys()]).length > 0)
      : NaN;
    const textHits = [...brandHits(g, brands)].filter(([, n]) => n >= BRAND_TEXT_MIN).map(([b]) => b);
    out.n_brands_in_text_mismatch = foreign(textHits).length;
  } else {
    out.brand_in_title_mismatch = NaN;
    out.n_brands_in_text_mismatch = NaN;
  }
  out.n_social_links = socials;

  // ---- scripts ----
  const scriptText = c.scriptTexts.join("");
  const jsAll = pyLower(`${scriptText}\n${c.handlerParts.join("\n")}`);
  const exfil = `${jsAll}\n${pyLower(formActions.join("\n"))}`;
  out.n_scripts_inline = c.nScriptsInline;
  out.script_chars_ratio = nHtml ? c.scriptLen / nHtml : NaN;
  out.n_eval = countAll(EVAL, jsAll);
  out.n_atob = countAll(ATOB, jsAll);
  out.n_unescape = countAll(UNESCAPE, jsAll);
  out.n_document_write = countAll(DOC_WRITE, jsAll);
  out.n_fromcharcode = countAll(FROMCHAR, jsAll);
  const sample = cpHead(scriptText, ENTROPY_CHARS);
  out.script_entropy = cpLen(sample) >= MIN_ENTROPY_CHARS ? entropy(sample) : NaN;
  if (scriptText) {
    let escaped = 0;
    for (const e of foldI(scriptText).matchAll(ESCAPES)) escaped += e[0].length; // ASCII matches
    out.script_escape_ratio = escaped / cpLen(scriptText);
  } else out.script_escape_ratio = NaN;
  out.n_ajax_calls = countAll(AJAX, jsAll);
  out.n_telegram_endpoints = countAll(TELEGRAM, exfil);
  out.n_webhook_endpoints = countAll(WEBHOOK, exfil);

  // ---- structure ----
  const lines = html.split("\n");
  const textLen = cpLen(text);
  out.page_size = size;
  out.n_lines = lines.length;
  let longest = 0;
  for (const line of lines) longest = Math.max(longest, cpLen(line));
  out.longest_line = longest;
  out.visible_text_len = textLen;
  out.text_to_code_ratio = nHtml ? textLen / nHtml : NaN;
  out.n_tags = c.nTags;
  out.max_dom_depth = c.maxDepth;
  out.n_iframes = c.nFrames;
  out.n_hidden_iframes = c.nHiddenFrames;
  out.has_meta_refresh = +(c.refresh !== null);
  if (c.refresh === null) out.meta_refresh_external = NaN;
  else {
    const target = REFRESH_URL.exec(foldI(c.refresh));
    out.meta_refresh_external = +(
      target !== null && res.ref(c.refresh.slice(...target.indices[1])).kind === "external"
    );
  }
  out.right_click_disabled = +(
    c.rightClickAttr || (jsAll.includes("contextmenu") && CONTEXTMENU_OFF.test(jsAll))
  );
  out.n_onmouseover = c.nOnmouseover;
  out.n_window_open = countAll(WINDOW_OPEN, jsAll);
  out.n_js_redirects = countAll(LOC_ASSIGN, jsAll) + countAll(LOC_CALL, jsAll);
  out.has_viewport_meta = +c.hasViewport;
  out.robots_noindex = +c.robotsNoindex;
  return out;
}

// What the brand-page rule (brand_rules.js) needs, as page_facts in features/html_features.py.
// Computed on every parsed page, also short ones. Not model features.
export function pageFacts(c, text, brands) {
  const found = (source) => {
    const tokens = tokensOf(pyLower(source));
    return tokens.length && brands.size ? [...brandHits(grams(tokens), brands).keys()].sort() : [];
  };
  // the owner named right after the copyright mark, not the words around it (see Python)
  const m = COPYRIGHT.exec(foldI(text));
  let owner = "";
  if (m !== null) {
    const start = m.index + m[0].length;
    const after = tokensOf(pyLower(text.slice(start, cpForward(text, start, COPYRIGHT_AFTER))));
    owner = after.filter((t) => !isDigitStr(t) && !COPYRIGHT_SKIP.has(t)).slice(0, 4).join(" ");
  }
  const titleGrams = grams(tokensOf(pyLower(c.title)));
  return {
    title_brands: found(c.title),
    title_login: +TITLE_WORDS.some((w) => titleGrams.has(w)),
    title_norm: norm(c.title),
    site_named: +Boolean(norm(c.siteName)),
    site_brands: found(c.siteName),
    copyright_brands: found(owner),
    password_fields: c.nPassword,
    otp_fields: c.nOtp,
    card_fields: c.nCard + c.nCvv,
    pin_fields: c.nPin,
  };
}

export function nanFeatures() {
  return Object.fromEntries(NAMES_B.map((n) => [n, NaN]));
}

// { values, status }; values is null unless status is "ok". Status: ok, empty, no_url, short,
// junk, timeout, failed (as in Python). Never throws. `parts` (from urlparts.parse) is optional.
// `minVisibleChars` lowers the visible-text floor (the extension uses 0 for a bare login form,
// which the models never saw in training; the default matches Python). With `facts` (an object),
// pageFacts of any page that parsed (also short and junk ones) go in it, with brands from
// `factBrands` (a Set; default lists.brandSet).
export function analyzeHtml(
  url,
  html,
  lists,
  parts = null,
  { minVisibleChars = MIN_VISIBLE_CHARS, facts = null, factBrands = null } = {},
) {
  try {
    let page = html;
    if (page instanceof Uint8Array) page = new TextDecoder("utf-8").decode(page);
    if (typeof page !== "string" || !pyStrip(page)) return { values: null, status: "empty" };
    let p = parts;
    if (p === null) p = typeof url === "string" ? parse(url, lists.platforms, lists.psl) : null;
    if (p === null) return { values: null, status: "no_url" };
    const size = cpLen(page);
    page = cpHead(page, MAX_HTML_CHARS).replaceAll("\x00", "");
    const collector = parsePage(page, now() + MAX_PAGE_SECONDS * 1000);
    const text = collector.text;
    if (facts !== null) Object.assign(facts, pageFacts(collector, text, factBrands ?? lists.brandSet));
    if (cpLen(pyStrip(text)) < minVisibleChars) return { values: null, status: "short" };
    if (isJunk(collector, text)) return { values: null, status: "junk" };
    const values = compute(collector, page, size, p, lists, text);
    return { values: Object.fromEntries(NAMES_B.map((n) => [n, Number(values[n])])), status: "ok" };
  } catch (e) {
    return { values: null, status: e instanceof Timeout ? "timeout" : "failed" };
  }
}

// All tier B features of a page; every value is NaN when the HTML is missing or unusable.
export function extractHtml(url, html, lists, parts = null, options = {}) {
  const { values } = analyzeHtml(url, html, lists, parts, options);
  return values ?? nanFeatures();
}
