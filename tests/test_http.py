def test_slow_download_is_cut_off(tmp_path, monkeypatch):
    import time

    import requests

    from phishdrift.http import HttpClient

    class SlowResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def raise_for_status(self):
            pass

        def iter_content(self, n):
            for _ in range(5):
                time.sleep(0.05)
                yield b"x"

    client = HttpClient(cache_dir=tmp_path, max_download_s=0.1, default_min_interval_s=0)
    monkeypatch.setattr(client._session, "get", lambda *a, **k: SlowResp())
    try:
        client.get("https://slow.example/")
    except requests.Timeout:
        return
    raise AssertionError("expected a Timeout")
