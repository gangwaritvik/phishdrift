"""Per-install feedback tokens: no user data, only a random install id signed by the server.

Token: ``<install_id>.<mac>``. ``install_id`` is 16 random bytes, urlsafe base64 without padding
(22 characters); ``mac`` is HMAC-SHA256(secret, install_id), urlsafe base64, first 22 characters.
The server keeps no list of issued tokens: a token is valid when its MAC matches.

The secret comes from the environment variable named by ``feedback.secret_env``. When that is
unset, a random secret is created once in ``<feedback dir>/.secret`` (mode 0600) and reused, so
tokens survive restarts. Stored feedback carries only ``reporter_key(install_id)``: the first 16 hex
characters of sha256(install_id), which counts distinct reporters but cannot be turned back into a
token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import stat
from pathlib import Path

log = logging.getLogger(__name__)

INSTALL_ID_BYTES = 16
MAC_CHARS = 22
MIN_SECRET_CHARS = 16
SECRET_FILE = ".secret"
_B64_22 = re.compile(r"^[A-Za-z0-9_-]{22}$")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def load_secret(env_name: str, feedback_dir: Path) -> bytes:
    """The HMAC secret: ``$env_name`` if set, else ``feedback_dir/.secret`` (created if missing)."""
    value = os.environ.get(env_name)
    if value is not None:
        if len(value.strip()) < MIN_SECRET_CHARS:
            raise ValueError(f"{env_name} must hold at least {MIN_SECRET_CHARS} characters")
        return value.strip().encode("utf-8")
    path = Path(feedback_dir) / SECRET_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(secrets.token_hex(32) + "\n")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        log.warning("feedback secret file was readable by others; setting mode 0600")
        os.chmod(path, 0o600)
    text = path.read_text(encoding="ascii").strip()
    if len(text) < MIN_SECRET_CHARS:
        raise ValueError(f"{path} is empty or too short; delete it to create a new secret")
    return text.encode("ascii")


class TokenSigner:
    """Issue and verify install tokens with one secret."""

    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def _mac(self, install_id: str) -> str:
        digest = hmac.new(self._secret, install_id.encode("ascii"), hashlib.sha256).digest()
        return _b64(digest)[:MAC_CHARS]

    def issue(self) -> str:
        install_id = _b64(secrets.token_bytes(INSTALL_ID_BYTES))
        return f"{install_id}.{self._mac(install_id)}"

    def verify(self, token: str | None) -> str | None:
        """The install id of a valid token, else None."""
        if not token or token.count(".") != 1:
            return None
        install_id, mac = token.split(".")
        if not _B64_22.match(install_id) or not _B64_22.match(mac):
            return None
        if not hmac.compare_digest(mac.encode("ascii"), self._mac(install_id).encode("ascii")):
            return None
        return install_id


def reporter_key(install_id: str) -> str:
    """Non-reversible reporter id stored with feedback: sha256(install_id) as hex, first 16."""
    return hashlib.sha256(install_id.encode("ascii")).hexdigest()[:16]
