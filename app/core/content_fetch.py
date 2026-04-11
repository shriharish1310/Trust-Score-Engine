from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

import requests

from .content_features import extract_script_srcs


@dataclass
class FetchedContent:
    final_url: str
    html: str | None
    js_texts: list[str]


def _read_limited(response: requests.Response, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= max_bytes:
            break
    return b"".join(chunks)


def _is_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    return parsed.scheme in {"http", "https"}


def _fetch_text(url: str, max_bytes: int, timeout: float) -> str | None:
    resp = requests.get(
        url,
        headers={"User-Agent": "URLTrustScorer/0.1"},
        timeout=timeout,
        allow_redirects=True,
        stream=True,
    )
    resp.raise_for_status()
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if content_type and not any(
        marker in content_type for marker in ("text/html", "application/xhtml", "text/plain", "javascript")
    ):
        return None

    data = _read_limited(resp, max_bytes)
    encoding = resp.encoding or "utf-8"
    return data.decode(encoding, errors="ignore")


def fetch_content(
    url: str,
    *,
    timeout: float = 5.0,
    max_html_bytes: int = 1_000_000,
    fetch_external_js: bool = True,
    max_js_files: int = 5,
    max_js_bytes: int = 200_000,
) -> FetchedContent:
    if not _is_http_url(url):
        return FetchedContent(final_url=url, html=None, js_texts=[])

    try:
        resp = requests.get(
            url,
            headers={"User-Agent": "URLTrustScorer/0.1"},
            timeout=timeout,
            allow_redirects=True,
            stream=True,
        )
        resp.raise_for_status()
    except requests.RequestException:
        return FetchedContent(final_url=url, html=None, js_texts=[])

    final_url = resp.url or url
    content_type = (resp.headers.get("Content-Type") or "").lower()
    if content_type and not any(
        marker in content_type for marker in ("text/html", "application/xhtml", "text/plain")
    ):
        return FetchedContent(final_url=final_url, html=None, js_texts=[])

    html_bytes = _read_limited(resp, max_html_bytes)
    encoding = resp.encoding or "utf-8"
    html = html_bytes.decode(encoding, errors="ignore")

    js_texts: list[str] = []
    if fetch_external_js:
        script_srcs = extract_script_srcs(html)
        seen: set[str] = set()
        for src in script_srcs:
            if len(js_texts) >= max_js_files:
                break
            if not src:
                continue
            abs_url = urljoin(final_url, src)
            if not _is_http_url(abs_url):
                continue
            if abs_url in seen:
                continue
            seen.add(abs_url)
            try:
                js_text = _fetch_text(abs_url, max_js_bytes, timeout)
            except requests.RequestException:
                continue
            if js_text:
                js_texts.append(js_text)

    return FetchedContent(final_url=final_url, html=html, js_texts=js_texts)
