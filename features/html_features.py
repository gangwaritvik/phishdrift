"""Tier B: features of the page HTML. Every name is declared in ``features/registry.py``.

``extract_html(url, html, parts) -> dict[str, float]`` parses the page once with the standard
library ``html.parser`` (no new dependency) and derives every tier B value from that single pass.

Rules
-----
- Missing or unusable HTML gives NaN for every tier B value, never 0. Unusable means: ``None``,
  empty, under ``MIN_VISIBLE_CHARS`` characters of visible text, or an obvious parked, takedown or
  error page. A parser failure or a page that exceeds ``MAX_PAGE_SECONDS`` is also all-NaN.
- Only the first ``MAX_HTML_CHARS`` characters are parsed. Work per page is bounded: no recursion,
  a cap on parser events, a cap on text kept, and a wall-clock check inside the parse loop (no
  signals, so it also works on Windows). Nothing is ever fetched.
- Domain-relative features (internal / external links, domain in title, ...) use the masked
  registrable domain from ``features.urlparts`` (platform identity replaced by a neutral token),
  so a hosting platform's name never reaches a feature. Domain-in-text features are NaN for IP and
  platform hosts, where there is no domain label to look for.
- No popularity and no blocklist information is used.
"""

from __future__ import annotations

import math
import re
import time
from collections import Counter
from functools import lru_cache
from html.parser import HTMLParser
from typing import NamedTuple

from features.lists import Lists, load_lists
from features.registry import NAMES_B
from features.urlparts import Parts, parse

NAN = float("nan")

# Work limits (per page).
MAX_HTML_CHARS = 500_000  # only this much of the page is parsed
MIN_VISIBLE_CHARS = 200  # less visible text than this = unusable page
MAX_PAGE_SECONDS = 8.0  # wall-clock guard checked inside the parse loop; exceeded = all NaN
MAX_EVENTS = 300_000  # parser callbacks; beyond this the rest of the page is ignored
FEED_CHUNK = 32_768  # characters handed to the parser at a time
TIME_CHECK_EVERY = 256  # callbacks between clock checks
MAX_TEXT_CHARS = 300_000  # visible text kept
MAX_SCRIPT_CHARS = 300_000  # inline script kept
MAX_TOKENS = 30_000  # words used for word counts and brand matching
MAX_REFS = 3_000  # anchors, resources kept per page
MAX_STACK = 512  # open-element stack (also the cap of ``max_dom_depth``)
STACK_SEARCH = 64  # an end tag looks this far down the stack for its start tag
MAX_ANCHOR_TEXT = 200
MAX_TITLE_CHARS = 300
ENTROPY_CHARS = 50_000
MIN_ENTROPY_CHARS = 100
JUNK_MAX_TEXT = 2_000  # parked / error patterns only apply to pages with less text than this
JUNK_SCAN_CHARS = 2_000
BRAND_TEXT_MIN = 2  # mentions of a brand in the text before it counts
COPYRIGHT_BEFORE, COPYRIGHT_AFTER = 60, 100


def _split(text: str, sep: str | None = None) -> list[str]:
    return text.split(sep)


VOID_TAGS = frozenset(
    _split(
        "area base basefont bgsound br col command embed frame hr img input keygen link meta "
        "param source track wbr"
    )
)
IMPLICIT_END = frozenset(_split("p li option tr td th dt dd thead tbody tfoot"))
JS_TYPES = ("javascript", "ecmascript", "module", "jsx", "babel")
MEDIA_TAGS = frozenset(_split("video audio source embed object track"))
SOCIAL_DOMAINS = _split(
    "facebook.com fb.com twitter.com x.com instagram.com linkedin.com youtube.com youtu.be "
    "pinterest.com tiktok.com whatsapp.com wa.me t.me telegram.me reddit.com snapchat.com"
)

# Word and phrase lists for the text counts. Phrases are lower case, one space between words.
BANK_WORDS = _split(
    "bank,banking,netbanking,ifsc,iban,swift,atm,account number,credit card,debit card,"
    "net banking,internet banking,online banking,bank account,routing number",
    ",",
)
PAY_WORDS = _split(
    "payment,payments,pay,pay now,invoice,billing,checkout,transaction,refund,wallet,upi,"
    "card number,cvv,expiry date,expiration date,security code,billing address",
    ",",
)
CRYPTO_WORDS = _split(
    "bitcoin,btc,ethereum,eth,crypto,cryptocurrency,wallet,seed phrase,recovery phrase,"
    "private key,metamask,blockchain,usdt,airdrop,nft,binance,coinbase,ledger,trezor,"
    "connect wallet,defi",
    ",",
)
URGENCY_WORDS = _split(
    "urgent,urgently,immediately,suspended,suspend,suspension,expire,expires,expired,expiring,"
    "within 24 hours,within 48 hours,action required,unusual activity,suspicious activity,"
    "unauthorized,unauthorised,locked,final notice,final warning,restricted,deactivated,"
    "terminated,verify your,confirm your,security alert,limited access,act now,last chance,"
    "will be closed,will be suspended,will be deactivated,will be terminated",
    ",",
)
CREDENTIAL_WORDS = _split(
    "login,log in,sign in,signin,password,username,user name,passcode,otp,forgot password,"
    "verification code,pin,credentials",
    ",",
)
TITLE_WORDS = frozenset(CREDENTIAL_WORDS) | frozenset(
    _split("verify verification confirm account secure update suspended")
)

_TOKEN = re.compile(r"[a-z0-9]+")
_ALNUM = re.compile(r"[^a-z0-9]+")
_SPACES = re.compile(r"\s+")
_COPYRIGHT = re.compile(r"©|copyright|all rights reserved", re.I)
_TEXT_DOMAIN = re.compile(r"^(?:https?://)?(?:[a-z0-9\-]+\.)+[a-z]{2,24}(?:[/:?#]\S*)?$", re.I)
_AUTHORITY = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:)?[/\\]{2}([^/?#\\]*)", re.I)
_SCHEME = re.compile(r"^([a-z][a-z0-9+.\-]*):", re.I)
_REFRESH_URL = re.compile(r"url\s*=\s*['\"]?([^'\";]+)", re.I)

# Input field hints: matched against name, id, placeholder, autocomplete, aria-label and title.
_OTP = re.compile(
    r"(?<![a-z])otp(?![a-z])|one[\s_\-]?time|verif\w*[\s_\-]?code|sms[\s_\-]?code|2fa|"
    r"(?<![a-z])mfa(?![a-z])|auth\w*[\s_\-]?code|passcode"
)
_CARD = re.compile(r"(?<![a-z])card|(?<![a-z])cc[\s_\-]?(?:num|number|no)|ccnum")
_CVV = re.compile(r"cvv|cvc|cvn|(?<![a-z])csc(?![a-z])|card[\s_\-]?code|security[\s_\-]?code")
_PIN = re.compile(
    r"upi[\s_\-]?pin|(?<![a-z])m?pin(?![a-z])|atm[\s_\-]?pin|(?:debit|card)[\s_\-]?pin"
)
_NON_TEXT_INPUTS = frozenset(
    _split("hidden submit button image reset checkbox radio file range color")
)

# Script patterns (applied to lower-cased text; each starts with a literal for speed).
_EVAL = re.compile(r"eval\s*\(|new\s+function\s*\(")
_ATOB = re.compile(r"atob\s*\(")
_UNESCAPE = re.compile(r"unescape\s*\(")
_DOC_WRITE = re.compile(r"document\.write(?:ln)?\s*\(")
_FROMCHAR = re.compile(r"string\.fromcharcode")
_WINDOW_OPEN = re.compile(r"window\.open\s*\(")
_LOC_ASSIGN = re.compile(r"location(?:\.href)?\s*=(?!=)")
_LOC_CALL = re.compile(r"location\.(?:replace|assign)\s*\(")
_AJAX = re.compile(r"xmlhttprequest|fetch\s*\(|\$\.(?:ajax|post|get)\s*\(|\.ajax\s*\(|sendbeacon")
_TELEGRAM = re.compile(r"api\.telegram\.org")
_WEBHOOK = re.compile(
    r"discord(?:app)?\.com/api/webhooks|hooks\.slack\.com|webhook\.site|formspree\.io|"
    r"formsubmit\.co|getform\.io|web3forms\.com|script\.google\.com/macros|emailjs|"
    r"pipedream\.net|requestbin|submit-form\.com|ngrok"
)
_ESCAPES = re.compile(r"\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\[0-7]{3}", re.I)
_CONTEXTMENU_OFF = re.compile(r"return\s+false|preventdefault")

# Obvious placeholder pages. Only applied to short pages without a password field, so a phishing
# page that talks about a suspended "account" is not mistaken for a takedown page: the body
# patterns name the site, domain or page itself ("this account has been suspended").
_JUNK_TITLE = re.compile(
    r"^\W*(?:(?:http\s*)?(?:error\s*)?(?:400|401|403|404|405|410|429|500|502|503|504|520|521|522"
    r"|523|524|525)\b|error\b|not found|page not found|access denied|forbidden\b|"
    r"service (?:temporarily )?unavailable|bad gateway|gateway time-?out|just a moment|"
    r"attention required|please wait|checking your browser|account suspended|"
    r"(?:this )?(?:site|website|page|domain) (?:is |has been )?(?:suspended|disabled|blocked|"
    r"unavailable|removed|expired|parked)|domain (?:for sale|expired|parking|parked)|parked\b|"
    r"default (?:web )?(?:site )?page|welcome to nginx|apache2? .{0,30}default page|it works\b|"
    r"index of /|under construction|coming soon|website disabled|buy this domain|sedo\b|"
    r"hugedomains|suspended page)",
    re.I,
)
_JUNK_BODY = re.compile(
    r"this (?:web)?site can.?t be reached|dns_probe|"
    r"(?:this )?domain (?:name )?(?:is |may be |has )?(?:for sale|expired|parked|available)|"
    r"(?:buy|purchase|inquire about) this domain|parked (?:free|domain|by|at|with)|"
    r"sedoparking|hugedomains|afternic|"
    r"this (?:account|site|website|page|domain|web page) (?:has been|is|was) (?:temporarily )?"
    r"(?:suspended|disabled|deactivated|removed|taken down|blocked|banned)|"
    r"(?:has|have) been (?:taken down|removed) (?:due|because|for)|"
    r"deceptive site ahead|reported (?:as )?(?:an )?(?:attack|phishing|unsafe)|"
    r"(?:error|http)\s*(?:403|404|500|502|503)|(?:403|404|500|502|503)\s*"
    r"(?:error|forbidden|not found|service)|not found on this server|"
    r"the requested url was not found|welcome to nginx|apache2? .{0,30}default page|"
    r"it works!|index of /|default web site page|"
    r"enable javascript and cookies to continue|checking if the site connection is secure|"
    r"ddos protection by|you don.?t have permission to access|"
    r"(?:site|website) is (?:currently )?(?:unavailable|under maintenance|down)|"
    r"under construction|coming soon|temporarily unavailable"
)


class _Abort(Exception):
    """Event cap reached: the rest of the page is ignored."""


class _Timeout(Exception):
    """Wall-clock limit reached: the page gets no features."""


class _Ref(NamedTuple):
    kind: str  # internal, external, null, data, other, empty
    domain: str
    is_ip: bool
    is_short: bool
    is_social: bool


_EMPTY = _Ref("empty", "", False, False, False)
_NULL = _Ref("null", "", False, False, False)
_DATA = _Ref("data", "", False, False, False)
_OTHER = _Ref("other", "", False, False, False)


def _norm(text: str) -> str:
    return _ALNUM.sub("", text.lower())


def _ratio(count: float, total: float) -> float:
    return count / total if total else NAN


def _entropy(text: str) -> float:
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _under(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


class _Resolver:
    """Classify a reference (href, src, action) against the page's masked registrable domain."""

    def __init__(self, parts: Parts, lists: Lists):
        self.platforms = lists.platforms
        self.shorteners = tuple(lists.shorteners)
        self.page_domain = parts.domain
        self.internal = _Ref("internal", parts.domain, False, False, False)
        self._cache: dict[str, _Ref] = {}

    def host(self, authority: str) -> _Ref:
        cached = self._cache.get(authority)
        if cached is not None:
            return cached
        host = authority.rsplit("@", 1)[-1]
        p = parse(host, self.platforms)
        if p is None:
            ref = _OTHER
        else:
            bare = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
            bare = bare.strip("[]").removeprefix("www.")
            kind = "internal" if p.domain == self.page_domain else "external"
            ref = _Ref(
                kind,
                p.domain,
                p.is_ip,
                _under(bare, self.shorteners),
                _under(bare, SOCIAL_DOMAINS),
            )
        if len(self._cache) < 2_000:
            self._cache[authority] = ref
        return ref

    def ref(self, raw: str | None) -> _Ref:
        if raw is None:
            return _EMPTY
        s = raw.strip().replace("\t", "").replace("\n", "").replace("\r", "")
        if not s:
            return _EMPTY
        if s[0] == "#":
            return _NULL
        m = _SCHEME.match(s)
        if m:
            scheme = m.group(1).lower()
            if scheme in ("javascript", "vbscript"):
                return _NULL
            if scheme in ("data", "blob"):
                return _DATA
            if scheme not in ("http", "https", "ftp", "ws", "wss"):
                return _OTHER
        elif not (s.startswith("//") or s.startswith("\\\\")):
            return self.internal
        a = _AUTHORITY.match(s)
        if a is None:
            return self.internal
        authority = a.group(1).lower()
        if not authority:
            return self.internal
        return self.host(authority)

    def text_domain(self, text: str) -> str | None:
        """Registrable domain a link text claims to be, or None if it is not a domain."""
        if len(text) > 120 or not _TEXT_DOMAIN.match(text):
            return None
        s = text.lower()
        if s.startswith("http://") or s.startswith("https://"):
            s = s.split("//", 1)[1]
        authority = re.split(r"[/?#]", s, maxsplit=1)[0]
        p = parse(authority, self.platforms)
        if p is None or not p.suffix:
            return None
        return p.domain


class _Collector(HTMLParser):
    """One pass over the page. Keeps counts and small bounded lists, never the DOM."""

    def __init__(self, deadline: float):
        super().__init__(convert_charrefs=True)
        self.deadline = deadline
        self.events = 0
        self.n_tags = 0
        self.stack: list[str] = []
        self.max_depth = 0
        # text
        self.text_parts: list[str] = []
        self.text_len = 0
        self.title_seen = False
        self.title_done = False
        self.in_title = False
        self.title_parts: list[str] = []
        self.skip = 0  # inside noscript / template
        # scripts
        self.in_script = False
        self.script_is_js = False
        self.script_buf: list[str] = []
        self.script_buf_len = 0
        self.script_texts: list[str] = []
        self.script_len = 0
        self.n_scripts_inline = 0
        self.script_srcs: list[str] = []
        self.in_style = False
        self.handler_parts: list[str] = []
        self.handler_len = 0
        self.right_click_attr = False
        self.n_onmouseover = 0
        # links and resources
        self.anchors: list[tuple[str, str]] = []
        self.anchor_href: str | None = None
        self.anchor_buf: list[str] = []
        self.anchor_len = 0
        self.css_hrefs: list[str] = []
        self.icon_hrefs: list[str] = []
        self.link_tag_hrefs: list[str] = []
        self.meta_urls: list[str] = []
        self.img_srcs: list[str] = []
        self.media_srcs: list[str] = []
        self.frame_srcs: list[str] = []
        self.n_frames = 0
        self.n_hidden_frames = 0
        self.base_href: str | None = None
        # meta
        self.has_description = False
        self.has_viewport = False
        self.robots_noindex = False
        self.refresh: str | None = None
        # forms
        self.n_forms = 0
        self.form: list | None = None  # [action, n_password]
        self.forms: list[tuple[str | None, int]] = []
        self.n_password = 0
        self.n_password_outside = 0
        self.n_inputs = 0
        self.n_hidden = 0
        self.has_submit = False
        self.n_otp = self.n_card = self.n_cvv = self.n_pin = 0

    # --- bookkeeping -------------------------------------------------------------------------
    def _tick(self) -> None:
        self.events += 1
        if self.events > MAX_EVENTS:
            raise _Abort
        if self.events % TIME_CHECK_EVERY == 0 and time.monotonic() > self.deadline:
            raise _Timeout

    def _push(self, tag: str) -> None:
        if tag in IMPLICIT_END and self.stack and self.stack[-1] == tag:
            self.stack.pop()
        if len(self.stack) < MAX_STACK:
            self.stack.append(tag)
        self.max_depth = max(self.max_depth, len(self.stack))

    def _pop(self, tag: str) -> None:
        stack = self.stack
        low = max(0, len(stack) - STACK_SEARCH)
        for i in range(len(stack) - 1, low - 1, -1):
            if stack[i] == tag:
                del stack[i:]
                return

    def _end_anchor(self) -> None:
        if self.anchor_href is not None and len(self.anchors) < MAX_REFS:
            text = _SPACES.sub(" ", "".join(self.anchor_buf)).strip()
            self.anchors.append((self.anchor_href, text))
        self.anchor_href = None
        self.anchor_buf = []
        self.anchor_len = 0

    def _end_form(self) -> None:
        if self.form is not None:
            self.forms.append((self.form[0], self.form[1]))
        self.form = None

    def _end_script(self) -> None:
        if self.script_is_js:
            text = "".join(self.script_buf)
            if text.strip():
                self.n_scripts_inline += 1
                if self.script_len < MAX_SCRIPT_CHARS:
                    self.script_texts.append(text[: MAX_SCRIPT_CHARS - self.script_len])
                    self.script_len += len(self.script_texts[-1])
        self.script_buf = []
        self.script_buf_len = 0
        self.in_script = False
        self.script_is_js = False

    def finish(self) -> None:
        self._end_anchor()
        self._end_form()
        if self.in_script:
            self._end_script()

    # --- parser callbacks --------------------------------------------------------------------
    def handle_startendtag(self, tag, attrs):
        self._start(tag, attrs, True)

    def handle_starttag(self, tag, attrs):
        self._start(tag, attrs, False)

    def _start(self, tag: str, attrs, self_closing: bool) -> None:
        self._tick()
        self.n_tags += 1
        self.in_title = False
        a: dict[str, str] = {}
        for key, value in attrs:
            if key not in a:
                a[key] = value or ""
        for key, value in a.items():
            if key.startswith("on") and len(key) > 2:
                if key == "onmouseover":
                    self.n_onmouseover += 1
                elif key == "oncontextmenu" and (
                    _CONTEXTMENU_OFF.search(value.lower()) or "false" in value.lower()
                ):
                    self.right_click_attr = True
                if self.handler_len < MAX_SCRIPT_CHARS and value:
                    self.handler_parts.append(value[:2000])
                    self.handler_len += min(len(value), 2000)
        if not (tag in VOID_TAGS or self_closing):
            self._push(tag)

        if tag == "a":
            if "href" in a:
                self._end_anchor()
                self.anchor_href = a["href"]
        elif tag == "input":
            self._input(a)
        elif tag == "form":
            self._end_form()
            self.n_forms += 1
            self.form = [a.get("action"), 0]
        elif tag == "button":
            kind = a.get("type", "").strip().lower()
            if kind in ("submit", "") and self.form is not None:
                self.has_submit = True
        elif tag == "script":
            if "src" in a:
                self.script_srcs.append(a["src"])
            if not self_closing:  # content of any script element is never visible text
                kind = a.get("type", "").strip().lower()
                self.in_script = True
                self.script_is_js = "src" not in a and (
                    not kind or any(t in kind for t in JS_TYPES)
                )
        elif tag == "style":
            if not self_closing:
                self.in_style = True
        elif tag == "link":
            rel = a.get("rel", "").lower()
            href = a.get("href")
            if href is not None:
                if "stylesheet" in rel:
                    self.css_hrefs.append(href)
                if "icon" in rel:
                    self.icon_hrefs.append(href)
                if len(self.link_tag_hrefs) < MAX_REFS:
                    self.link_tag_hrefs.append(href)
        elif tag == "img":
            src = a.get("src") or a.get("data-src")
            if src is not None and len(self.img_srcs) < MAX_REFS:
                self.img_srcs.append(src)
        elif tag in ("iframe", "frame"):
            self.n_frames += 1
            if a.get("src") is not None and len(self.frame_srcs) < MAX_REFS:
                self.frame_srcs.append(a["src"])
            if _hidden_frame(a):
                self.n_hidden_frames += 1
        elif tag in MEDIA_TAGS:
            src = a.get("src") or a.get("data")
            if src is not None and len(self.media_srcs) < MAX_REFS:
                self.media_srcs.append(src)
        elif tag == "meta":
            self._meta(a)
        elif tag == "base":
            if "href" in a and self.base_href is None:
                self.base_href = a["href"]
        elif tag == "title":
            if not self_closing:  # any title element hides its text; only the first one counts
                self.in_title = True
                self.title_seen = True
        elif tag in ("noscript", "template") and not self_closing:
            self.skip += 1

    def _input(self, a: dict[str, str]) -> None:
        kind = a.get("type", "").strip().lower() or "text"
        self.n_inputs += 1
        if kind == "hidden":
            self.n_hidden += 1
            return
        if kind in ("submit", "image"):
            self.has_submit = True
        if kind == "password":
            self.n_password += 1
            if self.form is not None:
                self.form[1] += 1
            else:
                self.n_password_outside += 1
        if kind in _NON_TEXT_INPUTS:
            return
        hint = " ".join(
            a.get(k, "")
            for k in ("name", "id", "placeholder", "autocomplete", "aria-label", "title")
        ).lower()
        if not hint.strip():
            return
        self.n_otp += bool(_OTP.search(hint))
        self.n_card += bool(_CARD.search(hint))
        self.n_cvv += bool(_CVV.search(hint))
        self.n_pin += bool(_PIN.search(hint))

    def _meta(self, a: dict[str, str]) -> None:
        name = a.get("name", "").strip().lower()
        content = a.get("content", "")
        equiv = a.get("http-equiv", "").strip().lower()
        if equiv == "refresh" and self.refresh is None:
            self.refresh = content
        if name == "description" and content.strip():
            self.has_description = True
        elif name == "viewport":
            self.has_viewport = True
        elif name in ("robots", "googlebot") and "noindex" in content.lower():
            self.robots_noindex = True
        low = content.strip().lower()
        if (low.startswith(("http://", "https://", "//"))) and len(self.meta_urls) < MAX_REFS:
            self.meta_urls.append(content)

    def handle_endtag(self, tag):
        self._tick()
        if tag == "a":
            self._end_anchor()
        elif tag == "form":
            self._end_form()
        elif tag == "script":
            if self.in_script:
                self._end_script()
        elif tag == "style":
            self.in_style = False
        elif tag == "title":
            if self.in_title:
                self.title_done = True
            self.in_title = False
        elif tag in ("noscript", "template") and self.skip > 0:
            self.skip -= 1
        if tag not in VOID_TAGS:
            self._pop(tag)

    def handle_data(self, data):
        self._tick()
        if self.in_script:
            if self.script_is_js and self.script_buf_len < MAX_SCRIPT_CHARS:
                self.script_buf.append(data)
                self.script_buf_len += len(data)
            return
        if self.in_style:
            return
        if self.in_title:
            if not self.title_done and sum(map(len, self.title_parts)) < MAX_TITLE_CHARS:
                self.title_parts.append(data)
            return
        if self.skip:
            return
        s = " ".join(data.split())
        if not s:
            return
        if self.text_len < MAX_TEXT_CHARS:
            piece = s[: MAX_TEXT_CHARS - self.text_len]
            self.text_parts.append(piece)
            self.text_len += len(piece) + 1
        if self.anchor_href is not None and self.anchor_len < MAX_ANCHOR_TEXT:
            self.anchor_buf.append(s + " ")
            self.anchor_len += len(s) + 1

    def handle_comment(self, data):
        self._tick()

    def handle_decl(self, decl):
        self._tick()

    def handle_pi(self, data):
        self._tick()

    def unknown_decl(self, data):
        self._tick()

    # --- derived -----------------------------------------------------------------------------
    @property
    def text(self) -> str:
        return " ".join(self.text_parts)

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())[:MAX_TITLE_CHARS]


def _hidden_frame(a: dict[str, str]) -> bool:
    if "hidden" in a:
        return True
    for key in ("width", "height"):
        value = a.get(key, "").strip().lower().removesuffix("px").strip()
        if value in ("0", "1"):
            return True
    style = a.get("style", "").lower().replace(" ", "")
    return any(t in style for t in ("display:none", "visibility:hidden", "width:0", "height:0"))


def _parse(html: str, deadline: float) -> _Collector:
    parser = _Collector(deadline)
    try:
        for start in range(0, len(html), FEED_CHUNK):
            parser.feed(html[start : start + FEED_CHUNK])
            if time.monotonic() > deadline:
                raise _Timeout
        parser.close()
    except _Abort:
        pass
    parser.finish()
    return parser


def _is_junk(c: _Collector, text: str) -> bool:
    """Parked, takedown or error page: short, no password field, and a known placeholder phrase."""
    if c.n_password or len(text) >= JUNK_MAX_TEXT:
        return False
    return bool(
        _JUNK_TITLE.search(c.title.lower()) or _JUNK_BODY.search(text[:JUNK_SCAN_CHARS].lower())
    )


@lru_cache(maxsize=8)
def _brand_set(brands: tuple[str, ...]) -> frozenset[str]:
    return frozenset(brands)


def _grams(tokens: list[str]) -> Counter:
    """Counts of single words, word pairs and word triples (joined by one space)."""
    grams: Counter = Counter(tokens)
    grams.update(map(" ".join, zip(tokens, tokens[1:], strict=False)))
    grams.update(map(" ".join, zip(tokens, tokens[1:], tokens[2:], strict=False)))
    return grams


def _brand_hits(grams: Counter, brands: frozenset[str]) -> Counter:
    """Brand mentions: a brand matches one word or 2-3 words written together or apart."""
    hits: Counter = Counter()
    for gram, n in grams.items():
        key = gram.replace(" ", "") if " " in gram else gram
        if key in brands:
            hits[key] += n
    return hits


def _count(grams: Counter, phrases) -> int:
    return sum(grams.get(p, 0) for p in phrases)


def _trigrams(s: str) -> set[str]:
    return {s[i : i + 3] for i in range(len(s) - 2)}


def _classify_all(resolver: _Resolver, refs) -> tuple[int, int, set[str]]:
    """(internal count, external count, external domains) of a list of references."""
    internal = external = 0
    domains: set[str] = set()
    for raw in refs:
        r = resolver.ref(raw)
        if r.kind == "internal":
            internal += 1
        elif r.kind == "external":
            external += 1
            domains.add(r.domain)
    return internal, external, domains


def _compute(
    c: _Collector, html: str, size: int, parts: Parts, lists: Lists, text: str
) -> dict[str, float]:
    out: dict[str, float] = {}
    res = _Resolver(parts, lists)
    n_html = len(html)

    # ---- forms ----
    kinds = Counter()
    n_cred = n_cred_ext = 0
    form_actions: list[str] = []
    for action, n_pass in c.forms:
        raw = (action or "").strip()
        low = raw.lower()
        if action is not None:
            form_actions.append(raw)
        if not raw:
            kinds["empty"] += 1
        elif raw.startswith("#"):
            kinds["hash"] += 1
        elif low.startswith("javascript:"):
            kinds["js"] += 1
        elif low.startswith("mailto:"):
            kinds["mailto"] += 1
        elif res.ref(raw).kind == "external":
            kinds["external"] += 1
            if n_pass:
                n_cred_ext += 1
        if n_pass:
            n_cred += 1
    out["n_forms"] = c.n_forms
    out["n_password_fields"] = c.n_password
    out["n_credential_forms"] = n_cred
    out["n_password_outside_form"] = c.n_password_outside
    out["n_password_forms_external"] = n_cred_ext
    out["n_input_hidden"] = c.n_hidden
    out["hidden_input_ratio"] = _ratio(c.n_hidden, c.n_inputs)
    out["has_submit_button"] = float(c.has_submit)
    out["n_form_action_empty"] = kinds["empty"]
    out["n_form_action_hash"] = kinds["hash"]
    out["n_form_action_js"] = kinds["js"]
    out["n_form_action_mailto"] = kinds["mailto"]
    out["n_form_action_external"] = kinds["external"]
    out["n_otp_fields"] = c.n_otp
    out["n_card_fields"] = c.n_card
    out["n_cvv_fields"] = c.n_cvv
    out["n_upi_pin_fields"] = c.n_pin

    # ---- links ----
    link_kinds = Counter()
    ext_domains: set[str] = set()
    mismatch = insecure = ip_hosts = shorteners = socials = 0
    for href, anchor_text in c.anchors:
        r = res.ref(href)
        link_kinds[r.kind] += 1
        if r.kind == "external":
            ext_domains.add(r.domain)
            ip_hosts += r.is_ip
            shorteners += r.is_short
            socials += r.is_social
        if href.strip().lower().startswith("http://"):
            insecure += 1
        if r.kind in ("internal", "external") and anchor_text:
            claimed = res.text_domain(anchor_text)
            if claimed is not None and claimed != r.domain:
                mismatch += 1
    n_links = len(c.anchors)
    out["n_links"] = n_links
    out["link_internal_ratio"] = _ratio(link_kinds["internal"], n_links)
    out["link_external_ratio"] = _ratio(link_kinds["external"], n_links)
    out["link_null_ratio"] = _ratio(link_kinds["null"] + link_kinds["empty"], n_links)
    out["n_external_link_domains"] = len(ext_domains)
    out["n_anchor_text_mismatch"] = mismatch
    out["n_links_insecure_http"] = insecure
    out["n_links_ip_host"] = ip_hosts
    out["n_links_shortener"] = shorteners
    out["has_base_external"] = float(
        c.base_href is not None and res.ref(c.base_href).kind == "external"
    )
    tag_int, tag_ext, _ = _classify_all(res, [*c.meta_urls, *c.script_srcs, *c.link_tag_hrefs])
    out["meta_script_link_internal_ratio"] = _ratio(tag_int, tag_int + tag_ext)

    # ---- resources ----
    s_int, s_ext, s_dom = _classify_all(res, c.script_srcs)
    c_int, c_ext, c_dom = _classify_all(res, c.css_hrefs)
    i_int, i_ext, i_dom = _classify_all(res, c.img_srcs)
    m_int, m_ext, m_dom = _classify_all(res, c.media_srcs)
    f_int, f_ext, f_dom = _classify_all(res, c.frame_srcs)
    out["n_script_src"] = len(c.script_srcs)
    out["script_external_ratio"] = _ratio(s_ext, s_int + s_ext)
    out["css_external_ratio"] = _ratio(c_ext, c_int + c_ext)
    out["n_img"] = len(c.img_srcs)
    out["img_external_ratio"] = _ratio(i_ext, i_int + i_ext)
    out["n_img_data_uri"] = sum(1 for s in c.img_srcs if s.strip().lower().startswith("data:"))
    out["has_favicon"] = float(bool(c.icon_hrefs))
    if c.icon_hrefs:
        out["favicon_external"] = float(any(res.ref(h).kind == "external" for h in c.icon_hrefs))
    else:
        out["favicon_external"] = NAN
    all_int = s_int + c_int + i_int + m_int + f_int
    all_ext = s_ext + c_ext + i_ext + m_ext + f_ext
    out["resource_external_ratio"] = _ratio(all_ext, all_int + all_ext)
    out["n_external_resource_domains"] = len(s_dom | c_dom | i_dom | m_dom | f_dom)

    # ---- text ----
    title = c.title
    low_text = text.lower()
    tokens = _TOKEN.findall(low_text)[:MAX_TOKENS]
    grams = _grams(tokens)
    label = _norm(parts.label)
    domain_ok = not parts.is_ip and not parts.is_platform and len(label) >= 3
    norm_title = _norm(title)
    title_tokens = _TOKEN.findall(title.lower())
    title_grams = _grams(title_tokens) if title_tokens else Counter()
    has_title_text = bool(norm_title)
    out["has_title"] = float(c.title_seen)
    out["title_empty"] = float(not has_title_text) if c.title_seen else NAN
    out["title_has_credential_word"] = (
        float(any(w in title_grams for w in TITLE_WORDS)) if has_title_text else NAN
    )
    if has_title_text and domain_ok:
        out["domain_in_title"] = float(label in norm_title)
        tri = _trigrams(label)
        out["title_domain_match"] = len(tri & _trigrams(norm_title)) / len(tri) if tri else NAN
    else:
        out["domain_in_title"] = NAN
        out["title_domain_match"] = NAN
    url_norm = _norm(parts.canon)
    words = {w for w in title_tokens if len(w) >= 3}
    out["url_title_match"] = sum(1 for w in words if w in url_norm) / len(words) if words else NAN
    out["has_description"] = float(c.has_description)
    m = _COPYRIGHT.search(text)
    out["has_copyright"] = float(m is not None)
    if m is None or not domain_ok:
        out["domain_in_copyright"] = NAN
    else:
        window = text[max(0, m.start() - COPYRIGHT_BEFORE) : m.end() + COPYRIGHT_AFTER]
        out["domain_in_copyright"] = float(label in _norm(window))
    out["n_bank_words"] = _count(grams, BANK_WORDS)
    out["n_pay_words"] = _count(grams, PAY_WORDS)
    out["n_crypto_words"] = _count(grams, CRYPTO_WORDS)
    out["n_urgency_words"] = _count(grams, URGENCY_WORDS)
    out["n_credential_words"] = _count(grams, CREDENTIAL_WORDS)
    brands = _brand_set(lists.brands)
    if brands:
        own = _norm(parts.label)  # "paypal" for paypal.co.uk, the neutral token for a platform

        def foreign(hits) -> list[str]:
            # a brand belongs to the page only if the page's own domain label is that brand
            # (or the label is the start of a longer brand: amazon for amazonpay)
            return [b for b in hits if not (b == own or (len(own) >= 4 and b.startswith(own)))]

        title_hits = _brand_hits(title_grams, brands) if has_title_text else None
        out["brand_in_title_mismatch"] = (
            float(bool(foreign(title_hits))) if title_hits is not None else NAN
        )
        text_hits = _brand_hits(grams, brands)
        out["n_brands_in_text_mismatch"] = len(
            foreign(b for b, n in text_hits.items() if n >= BRAND_TEXT_MIN)
        )
    else:
        out["brand_in_title_mismatch"] = NAN
        out["n_brands_in_text_mismatch"] = NAN
    out["n_social_links"] = socials

    # ---- scripts (also used by structure) ----
    script_text = "".join(c.script_texts)
    js_all = (script_text + "\n" + "\n".join(c.handler_parts)).lower()
    exfil = js_all + "\n" + "\n".join(form_actions).lower()
    out["n_scripts_inline"] = c.n_scripts_inline
    out["script_chars_ratio"] = c.script_len / n_html if n_html else NAN
    out["n_eval"] = len(_EVAL.findall(js_all))
    out["n_atob"] = len(_ATOB.findall(js_all))
    out["n_unescape"] = len(_UNESCAPE.findall(js_all))
    out["n_document_write"] = len(_DOC_WRITE.findall(js_all))
    out["n_fromcharcode"] = len(_FROMCHAR.findall(js_all))
    sample = script_text[:ENTROPY_CHARS]
    out["script_entropy"] = _entropy(sample) if len(sample) >= MIN_ENTROPY_CHARS else NAN
    if script_text:
        escaped = sum(len(x) for x in _ESCAPES.findall(script_text))
        out["script_escape_ratio"] = escaped / len(script_text)
    else:
        out["script_escape_ratio"] = NAN
    out["n_ajax_calls"] = len(_AJAX.findall(js_all))
    out["n_telegram_endpoints"] = len(_TELEGRAM.findall(exfil))
    out["n_webhook_endpoints"] = len(_WEBHOOK.findall(exfil))

    # ---- structure ----
    lines = html.split("\n")
    out["page_size"] = size
    out["n_lines"] = len(lines)
    out["longest_line"] = max(map(len, lines))
    out["visible_text_len"] = len(text)
    out["text_to_code_ratio"] = len(text) / n_html if n_html else NAN
    out["n_tags"] = c.n_tags
    out["max_dom_depth"] = c.max_depth
    out["n_iframes"] = c.n_frames
    out["n_hidden_iframes"] = c.n_hidden_frames
    out["has_meta_refresh"] = float(c.refresh is not None)
    if c.refresh is None:
        out["meta_refresh_external"] = NAN
    else:
        target = _REFRESH_URL.search(c.refresh)
        out["meta_refresh_external"] = float(
            target is not None and res.ref(target.group(1)).kind == "external"
        )
    out["right_click_disabled"] = float(
        c.right_click_attr
        or ("contextmenu" in js_all and _CONTEXTMENU_OFF.search(js_all) is not None)
    )
    out["n_onmouseover"] = c.n_onmouseover
    out["n_window_open"] = len(_WINDOW_OPEN.findall(js_all))
    out["n_js_redirects"] = len(_LOC_ASSIGN.findall(js_all)) + len(_LOC_CALL.findall(js_all))
    out["has_viewport_meta"] = float(c.has_viewport)
    out["robots_noindex"] = float(c.robots_noindex)
    return out


def nan_features() -> dict[str, float]:
    """Every tier B value as NaN: the answer for a page with no usable HTML."""
    return dict.fromkeys(NAMES_B, NAN)


def analyze(
    url: str, html: str | bytes | None, parts: Parts | None = None, *, lists: Lists | None = None
) -> tuple[dict[str, float] | None, str]:
    """``(values, status)``; values is None unless status is ``ok``.

    Status: ``ok``, ``empty`` (no HTML), ``no_url``, ``short`` (under ``MIN_VISIBLE_CHARS`` of
    visible text), ``junk`` (parked / takedown / error page), ``timeout`` or ``failed``.
    Never raises.
    """
    try:
        lists = lists or load_lists()
        if isinstance(html, bytes):
            html = html.decode("utf-8", "replace")
        if not isinstance(html, str) or not html.strip():
            return None, "empty"
        if parts is None:
            parts = parse(url, lists.platforms) if isinstance(url, str) else None
        if parts is None:
            return None, "no_url"
        size = len(html)
        page = html[:MAX_HTML_CHARS].replace("\x00", "")
        collector = _parse(page, time.monotonic() + MAX_PAGE_SECONDS)
        text = collector.text
        if len(text.strip()) < MIN_VISIBLE_CHARS:
            return None, "short"
        if _is_junk(collector, text):
            return None, "junk"
        values = _compute(collector, page, size, parts, lists, text)
        return {name: float(values[name]) for name in NAMES_B}, "ok"
    except _Timeout:
        return None, "timeout"
    except Exception:
        return None, "failed"


def extract_html(
    url: str, html: str | bytes | None, parts: Parts | None = None, *, lists: Lists | None = None
) -> dict[str, float]:
    """All tier B features of a page; every value is NaN when the HTML is missing or unusable."""
    values, _ = analyze(url, html, parts, lists=lists)
    return values if values is not None else nan_features()
