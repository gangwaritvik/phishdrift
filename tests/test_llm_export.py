"""The hosted LLM check (js/src/llm_check.js) runs on files exported from backend/llm.py."""

from backend.__main__ import export_llm_js
from backend.settings import Settings


def test_llm_js_files_are_current():
    for path, text in export_llm_js(Settings.load().cfg).items():
        assert path.read_text(encoding="utf-8") == text, (
            f"{path} is stale: run python -m backend export-llm-js"
        )
