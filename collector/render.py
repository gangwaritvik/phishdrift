"""Render natural legitimate pages in a headless browser (train/serve gap of the page model).

``python -m collector render-ood [--size N] [--workers N] [--limit N] [--retry-failed]``

The page model (tier B) was trained on raw server HTML: dataset-saved HTML and our crawler's plain
HTTP fetches. The extension scores the live rendered DOM (``outerHTML`` after scripts ran). This
module takes the naturally browsed legitimate pages that already have raw HTML (the
``crawl-ood --html-pass`` output, ``paths.ood_html_dir`` in ``configs/render.yaml``), samples some
of them, and renders each with the locally installed Chrome or Edge:

    <browser> --headless=new --dump-dom --virtual-time-budget=MS --user-data-dir=<new temp dir> URL

A fresh temporary profile is made for every page and deleted after it, so the user's own profile,
extensions and sign-ins are never used. Every page has a hard wall-clock limit; when it runs out
the browser's whole process tree is killed. Only legitimate pages are rendered: the input folder is
the out-of-distribution legitimate set, which never holds a feed or phishing URL.

Output (``paths.out_dir``, default ``data/raw/ood_render``):
  sample.csv            id, url, domain: the sample, drawn once (fixed seed) and reused on reruns
  raw/<id>.html         the stored raw HTML of each sampled page
  rendered/<id>.html    the rendered DOM (written by the worker that rendered it)
  status/<id>.json      one result per page: the checkpoint (a page with a file here is skipped)
  render_index.csv      id, url, domain, raw_file, rendered_file, status, seconds, ...
                        (written by the main process only; paths relative to the folder)
Safe to stop with Ctrl+C and rerun: finished pages are skipped and running browsers are killed.
"""

from __future__ import annotations

import concurrent.futures as cf
import contextlib
import json
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha1
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

SAMPLE_NAME = "sample.csv"
INDEX_NAME = "render_index.csv"
OK, TIMEOUT, NET_ERROR, ERROR, EMPTY, PENDING = (
    "ok",
    "timeout",
    "net_error",
    "error",
    "empty",
    "pending",
)
INDEX_COLUMNS = [
    "id",
    "url",
    "domain",
    "raw_file",
    "rendered_file",
    "status",
    "seconds",
    "raw_bytes",
    "rendered_bytes",
    "error",
]
_NET_ERROR = re.compile(r"\b(ERR_[A-Z_]+)\b")
_BLANK = re.compile(r"\s+")
_BLANK_DOM = "<html><head></head><body></body></html>"


def page_id(url: str) -> str:
    """Stable file name for a page (the URL itself may hold characters Windows forbids)."""
    return sha1(url.encode("utf-8")).hexdigest()[:16]


# --- sample ----------------------------------------------------------------------------------


def load_candidates(ood_html_dir: Path, min_html_chars: int) -> pd.DataFrame:
    """Pages of the ``crawl-ood --html-pass`` output that have raw HTML (one row per URL)."""
    from collector.ood import load_pages  # local: keeps this module light for the tests

    pages = load_pages(ood_html_dir)
    pages = pages[pages["html"].notna()]
    pages = pages[pages["html"].astype(str).str.len() >= min_html_chars]
    pages = pages.drop_duplicates("url").reset_index(drop=True)
    return pages[["url", "domain", "html"]].assign(domain=lambda d: d["domain"].astype(str))


def sample_pages(pages: pd.DataFrame, size: int, max_per_site: int, seed: int) -> pd.DataFrame:
    """Seeded sample of ``size`` pages with at most ``max_per_site`` per domain.

    Pages are shuffled with ``seed``; every site's first page comes before any site's second page,
    so a small sample covers as many sites as possible. Returns url, domain, html, id.
    """
    if not len(pages):
        return pages.assign(id=pd.Series(dtype=str))
    order = list(range(len(pages)))
    random.Random(seed).shuffle(order)
    d = pages.iloc[order].reset_index(drop=True)
    d["_pos"] = range(len(d))
    d["_rank"] = d.groupby("domain", sort=False).cumcount()
    d = d[d["_rank"] < max_per_site].sort_values(["_rank", "_pos"], kind="stable").head(size)
    d = d.drop(columns=["_pos", "_rank"]).reset_index(drop=True)
    d["id"] = d["url"].map(page_id)
    return d


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


def plan(out_dir: Path, cfg: dict, load: Callable[[], pd.DataFrame], resample: bool = False):
    """The saved sample, or a fresh one from ``load()``; raw HTML files are written once.
    ``load`` is not called when a sample exists and every raw file is in place."""
    out_dir = Path(out_dir)
    path = out_dir / SAMPLE_NAME
    scfg = cfg["sample"]
    if path.exists() and not resample:
        sample = pd.read_csv(path, dtype=str, keep_default_na=False)
        missing = [i for i in sample["id"] if not (out_dir / "raw" / f"{i}.html").exists()]
        if missing:  # a stop between the sample and its raw files: take them from the input
            pages = load().assign(id=lambda d: d["url"].map(page_id))
            html = dict(zip(pages["id"], pages["html"], strict=True))
            for i in missing:
                if i in html:
                    _atomic_write(out_dir / "raw" / f"{i}.html", str(html[i]).encode("utf-8"))
        log.info("render: reusing the saved sample of %d pages (%s)", len(sample), path)
        return sample
    sample = sample_pages(load(), scfg["size"], scfg["max_per_site"], scfg["seed"])
    for row in sample.itertuples(index=False):
        _atomic_write(out_dir / "raw" / f"{row.id}.html", str(row.html).encode("utf-8"))
    sample = sample[["id", "url", "domain"]]
    _atomic_write(path, sample.to_csv(index=False, lineterminator="\n").encode("utf-8"))
    log.info(
        "render: drew %d pages from %d sites -> %s", len(sample), sample["domain"].nunique(), path
    )
    return sample


# --- browser ---------------------------------------------------------------------------------


def browser_candidates(env: dict | None = None) -> dict[str, list[Path]]:
    """Usual install locations of Chrome, Edge and Chromium, by kind."""
    env = os.environ if env is None else env
    win_roots = [env.get(k) for k in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA")]
    win_roots = [Path(r) for r in win_roots if r]
    out: dict[str, list[Path]] = {
        "chrome": [r / "Google" / "Chrome" / "Application" / "chrome.exe" for r in win_roots],
        "edge": [r / "Microsoft" / "Edge" / "Application" / "msedge.exe" for r in win_roots],
        "chromium": [],
    }
    for kind, names in {
        "chrome": ["google-chrome", "google-chrome-stable", "chrome"],
        "edge": ["microsoft-edge", "msedge"],
        "chromium": ["chromium", "chromium-browser"],
    }.items():
        out[kind] += [Path(p) for p in (shutil.which(n) for n in names) if p]
    out["chrome"].append(
        Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    )  # macOS
    pw = env.get("PLAYWRIGHT_BROWSERS_PATH")
    if pw:
        out["chromium"] += sorted(Path(pw).glob("chromium-*/chrome-linux/chrome"), reverse=True)
    return out


def find_browser(bcfg: dict, env: dict | None = None) -> Path:
    """The configured executable, or the first installed one in ``prefer`` order."""
    if bcfg.get("executable"):
        exe = Path(bcfg["executable"])
        if not exe.exists():
            raise FileNotFoundError(f"browser.executable does not exist: {exe}")
        return exe
    found = browser_candidates(env)
    for kind in bcfg.get("prefer", ["chrome", "edge", "chromium"]):
        for exe in found.get(kind, []):
            if exe.exists():
                return exe
    raise FileNotFoundError(
        "no Chrome, Edge or Chromium found: set browser.executable in configs/render.yaml "
        "or pass --browser PATH"
    )


def browser_command(exe: Path, url: str, profile_dir: Path, bcfg: dict) -> list[str]:
    """Headless DOM dump in a fresh profile: no extensions, no sync, no first-run UI."""
    cmd = [
        str(exe),
        "--headless=new",
        "--dump-dom",
        f"--virtual-time-budget={int(bcfg['virtual_time_budget_ms'])}",
        f"--user-data-dir={profile_dir}",
        f"--window-size={bcfg.get('window_size', '1366,768')}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--mute-audio",
        "--hide-scrollbars",
    ]
    if bcfg.get("user_agent"):
        cmd.append(f"--user-agent={bcfg['user_agent']}")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        cmd.append("--no-sandbox")  # Chromium refuses to start as root otherwise (containers)
    cmd += [str(a) for a in bcfg.get("extra_args") or []]
    cmd.append(url)
    return cmd


class ProcessRegistry:
    """Running browser processes, so Ctrl+C can kill every one of them."""

    def __init__(self) -> None:
        self._procs: set[subprocess.Popen] = set()
        self._lock = threading.Lock()
        self.stop = threading.Event()

    def add(self, p: subprocess.Popen) -> None:
        with self._lock:
            self._procs.add(p)

    def remove(self, p: subprocess.Popen) -> None:
        with self._lock:
            self._procs.discard(p)

    def kill_all(self) -> None:
        self.stop.set()
        with self._lock:
            procs = list(self._procs)
        for p in procs:
            kill_tree(p)


def kill_tree(p: subprocess.Popen) -> None:
    """Kill the browser and every child process it started."""
    if p.poll() is not None:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(p.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
        else:
            os.killpg(p.pid, signal.SIGKILL)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        p.kill()
        p.wait(timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def _remove_dir(path: Path) -> None:
    for _ in range(5):  # Windows keeps files locked for a moment after the process ends
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            return
        time.sleep(0.5)


@dataclass
class Result:
    status: str
    seconds: float
    html: bytes | None = None
    error: str = ""


def render_with_browser(
    exe: Path, url: str, bcfg: dict, registry: ProcessRegistry | None = None
) -> Result:
    """Render one page; never raises. The profile folder is removed afterwards."""
    profile = Path(tempfile.mkdtemp(prefix="phishdrift-render-"))
    cmd = browser_command(exe, url, profile, bcfg)
    kwargs: dict = {"stdout": subprocess.PIPE, "stderr": subprocess.DEVNULL}
    if sys.platform == "win32":  # Ctrl+C reaches only us; we kill the browsers ourselves
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    t0 = time.monotonic()
    try:
        try:
            p = subprocess.Popen(cmd, **kwargs)
        except OSError as exc:
            return Result(ERROR, time.monotonic() - t0, error=f"start failed: {exc}")
        if registry is not None:
            registry.add(p)
        try:
            out, _ = p.communicate(timeout=float(bcfg["timeout_s"]))
        except subprocess.TimeoutExpired:
            kill_tree(p)
            return Result(TIMEOUT, time.monotonic() - t0, error=f"over {bcfg['timeout_s']} s")
        finally:
            if registry is not None:
                registry.remove(p)
        secs = time.monotonic() - t0
        if registry is not None and registry.stop.is_set():
            return Result(ERROR, secs, error="interrupted")
        return classify(out or b"", p.returncode, secs, int(bcfg.get("max_html_chars", 0)))
    finally:
        _remove_dir(profile)


def classify(out: bytes, returncode: int, seconds: float, max_chars: int = 0) -> Result:
    """Turn a browser's stdout into a result: the browser's own error page is not a render."""
    text = out.decode("utf-8", errors="replace")
    if 'id="main-frame-error"' in text:
        m = _NET_ERROR.search(text)
        return Result(NET_ERROR, seconds, error=m.group(1) if m else "browser error page")
    if not text.strip():
        return Result(EMPTY if returncode == 0 else ERROR, seconds, error=f"exit {returncode}")
    if _BLANK.sub("", text) == _BLANK_DOM:  # nothing committed before the time budget ran out
        return Result(EMPTY, seconds, error="blank document")
    if max_chars:
        text = text[:max_chars]
    return Result(OK, seconds, html=text.encode("utf-8"))


# --- checkpoints and index -------------------------------------------------------------------


def load_statuses(out_dir: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for f in sorted((Path(out_dir) / "status").glob("*.json")):
        try:
            rec = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):  # a half-written file cannot exist (atomic), but be safe
            continue
        out[f.stem] = rec
    return out


def todo_ids(sample: pd.DataFrame, statuses: dict[str, dict], retry_failed: bool) -> list[str]:
    """Pages still to render: no result yet, or a failed one when ``retry_failed``."""
    out = []
    for i in sample["id"]:
        rec = statuses.get(i)
        if rec is None or (retry_failed and rec.get("status") != OK):
            out.append(i)
    return out


def save_result(out_dir: Path, pid: str, url: str, domain: str, res: Result) -> dict:
    """Rendered file first, then the status file (the checkpoint): a stop in between only
    re-renders that page."""
    out_dir = Path(out_dir)
    rendered = out_dir / "rendered" / f"{pid}.html"
    if res.status == OK and res.html is not None:
        _atomic_write(rendered, res.html)
    rec = {
        "id": pid,
        "url": url,
        "domain": domain,
        "status": res.status,
        "seconds": round(res.seconds, 2),
        "rendered_bytes": len(res.html) if res.status == OK and res.html is not None else 0,
        "error": res.error,
        "rendered_at": datetime.now(UTC).isoformat(),
    }
    _atomic_write(out_dir / "status" / f"{pid}.json", json.dumps(rec).encode("utf-8"))
    return rec


def build_index(out_dir: Path, sample: pd.DataFrame) -> Path:
    """``render_index.csv``: every sampled page with its result (``pending`` if none yet)."""
    out_dir = Path(out_dir)
    statuses = load_statuses(out_dir)
    rows = []
    for r in sample.itertuples(index=False):
        rec = statuses.get(r.id, {})
        status = rec.get("status", PENDING)
        raw = out_dir / "raw" / f"{r.id}.html"
        rendered = out_dir / "rendered" / f"{r.id}.html"
        rows.append(
            {
                "id": r.id,
                "url": r.url,
                "domain": r.domain,
                "raw_file": f"raw/{r.id}.html" if raw.exists() else "",
                "rendered_file": f"rendered/{r.id}.html"
                if status == OK and rendered.exists()
                else "",
                "status": status,
                "seconds": rec.get("seconds", ""),
                "raw_bytes": raw.stat().st_size if raw.exists() else 0,
                "rendered_bytes": rec.get("rendered_bytes", 0),
                "error": rec.get("error", ""),
            }
        )
    table = pd.DataFrame(rows, columns=INDEX_COLUMNS)
    path = out_dir / INDEX_NAME
    _atomic_write(path, table.to_csv(index=False, lineterminator="\n").encode("utf-8"))
    return path


# --- run -------------------------------------------------------------------------------------


def _eta(done: int, total: int, elapsed_s: float) -> str:
    if done <= 0 or elapsed_s <= 0:
        return "n/a"
    left = (total - done) * elapsed_s / done
    return f"{int(left // 3600)}h{int(left % 3600 // 60):02d}m"


def render_all(
    sample: pd.DataFrame,
    out_dir: Path,
    renderer: Callable[[str], Result],
    workers: int,
    retry_failed: bool = False,
    limit: int | None = None,
    registry: ProcessRegistry | None = None,
    printer: Callable[[str], None] = print,
) -> dict:
    """Render every sampled page without a result. Workers write only their own page's files;
    the index is written by this (main) thread at the end, also after Ctrl+C."""
    out_dir = Path(out_dir)
    registry = registry or ProcessRegistry()
    statuses = load_statuses(out_dir)
    todo = todo_ids(sample, statuses, retry_failed)
    if limit is not None:
        todo = todo[:limit]
    by_id = sample.set_index("id")
    total, before = len(sample), len(sample) - len(todo_ids(sample, statuses, False))
    printer(
        f"render: {total} pages in the sample, {before} done, {len(todo)} to render now "
        f"({workers} workers)"
    )
    counts: dict[str, int] = {}
    started = time.monotonic()

    def one(pid: str) -> dict | None:
        if registry.stop.is_set():
            return None
        url, domain = by_id.at[pid, "url"], by_id.at[pid, "domain"]
        res = renderer(url)
        if registry.stop.is_set():  # interrupted mid-page: no checkpoint, rerun renders it
            return None
        return save_result(out_dir, pid, url, domain, res)

    n_done = 0
    pool = cf.ThreadPoolExecutor(max_workers=max(1, int(workers)))
    pending = {pool.submit(one, pid) for pid in todo}
    try:
        while pending:
            # a short wait keeps Ctrl+C responsive on Windows
            done, pending = cf.wait(pending, timeout=0.5, return_when=cf.FIRST_COMPLETED)
            for fut in done:
                rec = fut.result()
                if rec is None:
                    continue
                n_done += 1
                counts[rec["status"]] = counts.get(rec["status"], 0) + 1
                tally = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
                pct = 100 * (before + n_done) / max(total, 1)
                printer(
                    f"render: {before + n_done}/{total} ({pct:.1f}%)"
                    f" | this run: {tally} | {rec['status']} {rec['seconds']:.1f}s {rec['domain']}"
                    f" | eta {_eta(n_done, len(todo), time.monotonic() - started)}"
                )
    except BaseException:
        registry.kill_all()
        pool.shutdown(wait=True, cancel_futures=True)
        build_index(out_dir, sample)
        raise
    pool.shutdown(wait=True)
    index = build_index(out_dir, sample)
    return {
        "sample": total,
        "done_before": before,
        "rendered_now": n_done,
        "status_now": counts,
        "index": str(index),
    }


def run(
    size: int | None = None,
    workers: int | None = None,
    limit: int | None = None,
    retry_failed: bool | None = None,
    browser: str | None = None,
    resample: bool = False,
    config_dir: Path | None = None,
) -> int:
    """``python -m collector render-ood``. Exit codes: 0 done, 1 refused (no browser, no input)."""
    from phishdrift.config import load_config, resolve

    cfg = load_config("render", config_dir)
    if size is not None:
        cfg["sample"]["size"] = size
    if browser:
        cfg["browser"]["executable"] = browser
    run_cfg = cfg["run"]
    workers = run_cfg["workers"] if workers is None else workers
    retry_failed = run_cfg["retry_failed"] if retry_failed is None else retry_failed
    in_dir, out_dir = resolve(cfg["paths"]["ood_html_dir"]), resolve(cfg["paths"]["out_dir"])
    if out_dir.resolve() == in_dir.resolve() or in_dir.resolve() in out_dir.resolve().parents:
        log.error("paths.out_dir must not be paths.ood_html_dir or inside it")
        return 1
    try:
        exe = find_browser(cfg["browser"])
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1
    log.info("render: browser %s", exe)

    def load() -> pd.DataFrame:
        pages = load_candidates(in_dir, cfg["sample"]["min_html_chars"])
        if not len(pages):
            raise FileNotFoundError(
                f"no stored HTML in {in_dir / 'pages'}: "
                "run scripts\\run_ood_crawl.ps1 -HtmlPass first"
            )
        return pages

    try:
        sample = plan(out_dir, cfg, load, resample)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1
    registry = ProcessRegistry()

    def renderer(url: str) -> Result:
        return render_with_browser(exe, url, cfg["browser"], registry)

    restore = _stop_signals_raise_interrupt()
    try:
        summary = render_all(
            sample, out_dir, renderer, workers, retry_failed, limit, registry, printer=log.info
        )
    finally:
        restore()
    log.info("render finished: %s", summary)
    return 0


def _raise_interrupt(signum, frame):  # noqa: ARG001 - signal handler signature
    raise KeyboardInterrupt


def _stop_signals_raise_interrupt() -> Callable[[], None]:
    """SIGTERM (kill) and SIGBREAK (Ctrl+Break, closing the console on Windows) take the same
    path as Ctrl+C, so the browsers are killed and the index written. Returns a restore call."""
    old = {}
    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        with contextlib.suppress(ValueError, OSError):  # not the main thread
            old[sig] = signal.signal(sig, _raise_interrupt)

    def restore() -> None:
        for sig, handler in old.items():
            signal.signal(sig, handler)

    return restore
