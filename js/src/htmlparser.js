// A port of CPython 3.13's html.parser.HTMLParser (convert_charrefs=True, scripting=False) and
// html.unescape, so the tier B features see exactly the events Python sees: the same regexes,
// the same goahead loop, the same data held back at the end of a fed piece, the same
// buffering in feed(). Entity tables come from Python (js/src/pydata.js).
//
// Positions in rawdata are UTF-16 indices. Where CPython counts characters (feed()'s pending
// length and parse threshold, the 34-character window that holds back a cut-off "&"), the
// count is in code points, as in Python. Callers must feed the same pieces Python is fed
// (split on code points, never inside a surrogate pair).
//
// With convert_charrefs=True the "&" branches of goahead() are never reached (data runs up to
// the next "<", and in CDATA mode `interesting` only finds the end tag), so they are left out.
// _markupbase's line/offset bookkeeping (updatepos) is not needed by any caller and is skipped.

import { HTML5, INVALID_CHARREFS, INVALID_CODEPOINTS } from "./pydata.js";
import { cpBack, cpLen, pyLower, pyStrip } from "./pystr.js";

const ENTITIES = new Map(Object.entries(HTML5));
const INVALID_REFS = new Map(Object.entries(INVALID_CHARREFS).map(([k, v]) => [Number(k), v]));
const INVALID_CPS = new Set(INVALID_CODEPOINTS);
const MAX_STR_DIGITS = 4300; // sys.int_info.default_max_str_digits: int() of more digits raises

// --- html.unescape -------------------------------------------------------------------------

const CHARREF = /&(#[0-9]+;?|#[xX][0-9a-fA-F]+;?|[^\t\n\f <&#;]{1,32};?)/gu;

function replaceCharref(s) {
  if (s[0] === "#") {
    let num;
    if (s[1] === "x" || s[1] === "X") {
      num = parseInt(s.slice(2).replace(/;$/, ""), 16);
    } else {
      const digits = s.slice(1).replace(/;$/, "");
      if (digits.length > MAX_STR_DIGITS) {
        throw new Error(`Exceeds the limit (${MAX_STR_DIGITS} digits) for integer string conversion`);
      }
      num = parseInt(digits, 10);
    }
    if (INVALID_REFS.has(num)) return INVALID_REFS.get(num);
    if ((num >= 0xd800 && num <= 0xdfff) || num > 0x10ffff) return "�";
    if (INVALID_CPS.has(num)) return "";
    return String.fromCodePoint(num);
  }
  if (ENTITIES.has(s)) return ENTITIES.get(s);
  const cps = Array.from(s);
  for (let x = cps.length - 1; x > 1; x--) {
    const head = cps.slice(0, x).join("");
    if (ENTITIES.has(head)) return ENTITIES.get(head) + cps.slice(x).join("");
  }
  return `&${s}`;
}

export function unescape(s) {
  if (!s.includes("&")) return s;
  return s.replace(CHARREF, (_, g) => replaceCharref(g));
}

const ATTR_CHARREF = /&(#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*)[;=]?/g;

function unescapeAttrvalue(s) {
  return s.replace(ATTR_CHARREF, (ref) => {
    if (ref.startsWith("&#")) return unescape(ref);
    if (!ref.endsWith("=") && ENTITIES.has(ref.slice(1))) return unescape(ref);
    return ref;
  });
}

// --- regexes (html/parser.py) ----------------------------------------------------------------

const STARTTAGOPEN = /<[a-zA-Z]/y;
const ENDTAGOPEN = /<\/[a-zA-Z]/y;
const PICLOSE = />/g;
const COMMENTCLOSE = /--!?>/g;
const COMMENTABRUPTCLOSE = /-?>/y;
const AMP_END = /[\t\n\r\f ;]/g;
const TAGFIND_TOLERANT = /([a-zA-Z][^\t\n\r\f />]*)(?:[\t\n\r\f ]|\/(?!>))*/y;
const ATTRFIND_TOLERANT = new RegExp(
  "((?<=['\"\\t\\n\\r\\f /])[^\\t\\n\\r\\f />][^\\t\\n\\r\\f /=>]*)" + // attribute name
    "([\\t\\n\\r\\f ]*=[\\t\\n\\r\\f ]*" + // value indicator
    "('[^']*'" + // LITA-enclosed value
    '|"[^"]*"' + // LIT-enclosed value
    "|(?!['\"])[^>\\t\\n\\r\\f ]*" + // bare value
    "))?" +
    "(?:[\\t\\n\\r\\f ]|/(?!>))*", // possibly followed by a space
  "y",
);
const LOCATETAGEND = new RegExp(
  "[a-zA-Z][^\\t\\n\\r\\f />]*" + // tag name
    "[\\t\\n\\r\\f /]*" + // optional whitespace before attribute name
    "(?:(?<=['\"\\t\\n\\r\\f /])[^\\t\\n\\r\\f />][^\\t\\n\\r\\f /=>]*" + // attribute name
    "(?:[\\t\\n\\r\\f ]*=[\\t\\n\\r\\f ]*" + // value indicator
    "(?:'[^']*'" +
    '|"[^"]*"' +
    "|(?!['\"])[^>\\t\\n\\r\\f ]*" +
    "))?" +
    "[\\t\\n\\r\\f /]*" + // possibly followed by a space
    ")*" +
    ">?",
  "y",
);

const CDATA_CONTENT_ELEMENTS = new Set(["script", "style", "xmp", "iframe", "noembed", "noframes"]);
const RCDATA_CONTENT_ELEMENTS = new Set(["textarea", "title"]);

function matchAt(re, s, i) {
  re.lastIndex = i;
  return re.exec(s);
}

function searchFrom(re, s, i) {
  re.lastIndex = i;
  return re.exec(s);
}

export class HTMLParser {
  constructor() {
    this.reset();
  }

  reset() {
    this.rawdata = "";
    this.lasttag = "???";
    this.interesting = null; // null = interesting_normal (not used with convert_charrefs)
    this.cdataElem = null;
    this.supportCdata = true;
    this.escapable = true;
    this.pending = [];
    this.pendingLen = 0;
    this.parseThreshold = 1;
  }

  feed(data) {
    this.pendingLen += cpLen(data);
    if (this.pendingLen < this.parseThreshold) {
      this.pending.push(data);
      return;
    }
    if (!this.pending.length) {
      this.rawdata += data;
    } else {
      this.pending.push(data);
      this.rawdata += this.pending.join("");
      this.pending = [];
    }
    this.pendingLen = 0;
    const n = this.rawdata.length;
    this.goahead(false);
    if (this.rawdata.length < n) this.parseThreshold = 1; // some data was parsed
    else this.parseThreshold = cpLen(this.rawdata); // nothing parsed: wait until it doubles
  }

  close() {
    if (this.pending.length) {
      this.rawdata += this.pending.join("");
      this.pending = [];
      this.pendingLen = 0;
    }
    this.goahead(true);
  }

  setCdataMode(elem, escapable = false) {
    this.cdataElem = elem.toLowerCase();
    this.escapable = escapable;
    if (this.cdataElem === "plaintext") this.interesting = /$(?![\s\S])/g; // \Z
    else this.interesting = new RegExp(`</${this.cdataElem}(?=[\\t\\n\\r\\f />])`, "gi");
  }

  clearCdataMode() {
    this.interesting = null;
    this.cdataElem = null;
    this.escapable = true;
  }

  goahead(end) {
    const rawdata = this.rawdata;
    let i = 0;
    const n = rawdata.length;
    while (i < n) {
      let j;
      if (!this.cdataElem) {
        j = rawdata.indexOf("<", i);
        if (j < 0) {
          // a charref may be cut in half at the end: look for an & near the end that is not
          // followed by a space or ;  (34 characters, counted in code points)
          const from = Math.max(i, cpBack(rawdata, n, 34));
          const amppos = rawdata.lastIndexOf("&");
          if (amppos >= from && amppos >= 0 && searchFrom(AMP_END, rawdata, amppos) === null) {
            break; // wait till we get all the text
          }
          j = n;
        }
      } else {
        const match = searchFrom(this.interesting, rawdata, i);
        if (match) j = match.index;
        else break; // cdata_elem is set
      }
      if (i < j) {
        if (this.escapable) this.handle_data(unescape(rawdata.slice(i, j)));
        else this.handle_data(rawdata.slice(i, j));
      }
      i = j;
      if (i === n) break;
      // rawdata[i] is "<" here (see the header)
      let k;
      if (matchAt(STARTTAGOPEN, rawdata, i)) k = this.parseStarttag(i);
      else if (rawdata.startsWith("</", i)) k = this.parseEndtag(i);
      else if (rawdata.startsWith("<!--", i)) k = this.parseComment(i);
      else if (rawdata.startsWith("<?", i)) k = this.parsePi(i);
      else if (rawdata.startsWith("<!", i)) k = this.parseHtmlDeclaration(i);
      else if (i + 1 < n || end) {
        this.handle_data("<");
        k = i + 1;
      } else break;
      if (k < 0) {
        if (!end) break;
        if (matchAt(STARTTAGOPEN, rawdata, i)) {
          // pass
        } else if (rawdata.startsWith("</", i)) {
          if (i + 2 === n) this.handle_data("</");
          else if (matchAt(ENDTAGOPEN, rawdata, i)) {
            // pass
          } else this.handle_comment(rawdata.slice(i + 2)); // bogus comment
        } else if (rawdata.startsWith("<!--", i)) {
          let jj = n;
          for (const suffix of ["--!", "--", "-"]) {
            if (rawdata.length - suffix.length >= i + 4 && rawdata.endsWith(suffix)) {
              jj -= suffix.length;
              break;
            }
          }
          this.handle_comment(rawdata.slice(i + 4, jj));
        } else if (rawdata.startsWith("<![CDATA[", i) && this.supportCdata) {
          this.unknown_decl(rawdata.slice(i + 3));
        } else if (rawdata.slice(i, i + 9).toLowerCase() === "<!doctype") {
          this.handle_decl(rawdata.slice(i + 2));
        } else if (rawdata.startsWith("<!", i)) {
          this.handle_comment(rawdata.slice(i + 2)); // bogus comment
        } else if (rawdata.startsWith("<?", i)) {
          this.handle_pi(rawdata.slice(i + 2));
        } else {
          throw new Error("we should not get here!");
        }
        k = n;
      }
      i = k;
    }
    if (end && i < n) {
      if (this.escapable) this.handle_data(unescape(rawdata.slice(i, n)));
      else this.handle_data(rawdata.slice(i, n));
      i = n;
    }
    this.rawdata = rawdata.slice(i);
  }

  parseHtmlDeclaration(i) {
    const rawdata = this.rawdata;
    if (rawdata.startsWith("<!--", i)) return this.parseComment(i);
    if (rawdata.startsWith("<![CDATA[", i) && this.supportCdata) {
      const j = rawdata.indexOf("]]>", i + 9);
      if (j < 0) return -1;
      this.unknown_decl(rawdata.slice(i + 3, j));
      return j + 3;
    }
    if (rawdata.slice(i, i + 9).toLowerCase() === "<!doctype") {
      const gtpos = rawdata.indexOf(">", i + 9);
      if (gtpos === -1) return -1;
      this.handle_decl(rawdata.slice(i + 2, gtpos));
      return gtpos + 1;
    }
    return this.parseBogusComment(i);
  }

  parseComment(i) {
    const rawdata = this.rawdata;
    // an empty comment is abruptly closed by the first ">" or "->"
    let match = matchAt(COMMENTABRUPTCLOSE, rawdata, i + 4);
    if (!match) {
      match = searchFrom(COMMENTCLOSE, rawdata, i + 4);
      if (!match) return -1;
    }
    this.handle_comment(rawdata.slice(i + 4, match.index));
    return match.index + match[0].length;
  }

  parseBogusComment(i) {
    const rawdata = this.rawdata;
    const pos = rawdata.indexOf(">", i + 2);
    if (pos === -1) return -1;
    this.handle_comment(rawdata.slice(i + 2, pos));
    return pos + 1;
  }

  parsePi(i) {
    const rawdata = this.rawdata;
    const match = searchFrom(PICLOSE, rawdata, i + 2);
    if (!match) return -1;
    this.handle_pi(rawdata.slice(i + 2, match.index));
    return match.index + 1;
  }

  parseStarttag(i) {
    const endpos = this.checkForWholeStartTag(i);
    if (endpos < 0) return endpos;
    const rawdata = this.rawdata;
    const attrs = [];
    const match = matchAt(TAGFIND_TOLERANT, rawdata, i + 1);
    let k = match.index + match[0].length;
    const tag = pyLower(match[1]);
    this.lasttag = tag;
    while (k < endpos) {
      const m = matchAt(ATTRFIND_TOLERANT, rawdata, k);
      if (!m) break;
      const attrname = m[1];
      const rest = m[2];
      let attrvalue = m[3];
      if (!rest) attrvalue = null;
      else if (
        (attrvalue.slice(0, 1) === "'" && attrvalue.slice(-1) === "'") ||
        (attrvalue.slice(0, 1) === '"' && attrvalue.slice(-1) === '"')
      ) {
        attrvalue = attrvalue.slice(1, -1);
      }
      if (attrvalue) attrvalue = unescapeAttrvalue(attrvalue);
      attrs.push([pyLower(attrname), attrvalue]);
      k = m.index + m[0].length;
      if (m[0].length === 0) break; // cannot happen (the name is never empty); guards a loop
    }
    const endText = pyStrip(rawdata.slice(k, endpos));
    if (endText !== ">" && endText !== "/>") {
      this.handle_data(rawdata.slice(i, endpos));
      return endpos;
    }
    if (endText.endsWith("/>")) {
      this.handle_startendtag(tag, attrs); // XHTML-style empty tag
    } else {
      this.handle_starttag(tag, attrs);
      if (CDATA_CONTENT_ELEMENTS.has(tag) || tag === "plaintext") this.setCdataMode(tag, false);
      else if (RCDATA_CONTENT_ELEMENTS.has(tag)) this.setCdataMode(tag, true);
    }
    return endpos;
  }

  checkForWholeStartTag(i) {
    const rawdata = this.rawdata;
    const match = matchAt(LOCATETAGEND, rawdata, i + 1);
    const j = match.index + match[0].length;
    if (rawdata[j - 1] !== ">") return -1;
    return j;
  }

  parseEndtag(i) {
    const rawdata = this.rawdata;
    if (rawdata.indexOf(">", i + 2) < 0) return -1; // fast check
    if (!matchAt(ENDTAGOPEN, rawdata, i)) {
      if (rawdata.slice(i + 2, i + 3) === ">") return i + 3; // </> is ignored
      return this.parseBogusComment(i);
    }
    let match = matchAt(LOCATETAGEND, rawdata, i + 2);
    const j = match.index + match[0].length;
    if (rawdata[j - 1] !== ">") return -1;
    match = matchAt(TAGFIND_TOLERANT, rawdata, i + 2);
    const tag = pyLower(match[1]);
    this.handle_endtag(tag);
    this.clearCdataMode();
    return j;
  }

  // Overridable handlers (same names as Python).
  handle_startendtag(tag, attrs) {
    this.handle_starttag(tag, attrs);
    this.handle_endtag(tag);
  }
  handle_starttag() {}
  handle_endtag() {}
  handle_data() {}
  handle_comment() {}
  handle_decl() {}
  handle_pi() {}
  unknown_decl() {}
}
