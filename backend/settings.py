"""Backend settings: ``configs/backend.yaml`` plus the shared values from ``collector.yaml``."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from phishdrift.config import load_config, resolve


def _merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


@dataclass
class Settings:
    """``cfg`` is the backend config; ``collector`` the collector config it reuses."""

    cfg: dict[str, Any]
    collector: dict[str, Any]

    @classmethod
    def load(cls, overrides: dict | None = None, config_dir: Path | None = None) -> Settings:
        cfg = load_config("backend", config_dir)
        if overrides:
            _merge(cfg, copy.deepcopy(overrides))
        return cls(cfg=cfg, collector=load_config("collector", config_dir))

    @property
    def http_cfg(self) -> dict:
        """Collector HTTP settings with the backend's faster overrides."""
        return {**self.collector["http"], **self.cfg["lookup"]["http"]}

    @property
    def capture_cfg(self) -> dict:
        return self.collector["domain_capture"]

    @property
    def http_cache_dir(self) -> Path:
        return resolve(self.collector["paths"]["http_cache_dir"])

    @property
    def feedback_dir(self) -> Path:
        return resolve(self.cfg["feedback"]["dir"])

    @property
    def remote_config_path(self) -> Path:
        return resolve(self.cfg["remote_config"]["path"])

    @property
    def platforms_file(self) -> Path:
        return resolve(self.cfg["remote_config"]["platforms_file"])

    @property
    def lists_dir(self) -> Path:
        return resolve(self.cfg["lists"]["out_dir"])
