from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures() -> Path:
    return FIXTURES


@pytest.fixture
def dedup_cfg() -> dict:
    return {
        "html_min_tokens": 20,
        "html_max_chars": 200_000,
        "shingle_size": 5,
        "simhash_max_hamming": 3,
        "near_dup_within_label_only": True,
    }
