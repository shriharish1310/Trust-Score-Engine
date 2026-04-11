from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from html.parser import HTMLParser
import re
from typing import Iterable
from urllib.parse import urljoin, urlparse

import tldextract


CONTENT_KEYWORDS = (
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "signin",
    "confirm",
    "password",
)

_JS_EVAL_RE = re.compile(r"\beval\s*\(", re.IGNORECASE)
_JS_ATOB_RE = re.compile(r"\batob\s*\(", re.IGNORECASE)
_JS_UNESCAPE_RE = re.compile(r"\bunescape\s*\(", re.IGNORECASE)
_JS_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{100,}={0,2}")


@dataclass(frozen=True)
class ContentFeatureSpec:
    names: tuple[str, ...] = (
        "content_form_count",
        "content_password_input_count",
        "content_iframe_count",
        "content_external_script_ratio",
        "content_external_resource_domain_count",
        "content_keyword_title_hits",
        "content_keyword_body_hits",
        "content_js_eval_count",
        "content_js_atob_count",
        "content_js_unescape_count",
        "content_js_long_base64_count",
        "rel_form_action_mismatch_ratio",
        "rel_off_domain_resource_ratio",
        "rel_domain_title_similarity",
        "rel_domain_brand_similarity",
    )


CONTENT_SPEC = ContentFeatureSpec()


class _HTMLFeatureParser(HTMLParser):
    def __init__(self, max_text_chars: int = 20000, max_script_chars: int = 200000) -> None:
        super().__init__()
        self.form_count = 0
        self.password_input_count = 0
        self.iframe_count = 0
        self.script_srcs: list[str] = []
        self.resource_urls: list[str] = []
        self.form_actions: list[str] = []
        self.inline_scripts: list[str] = []
        self.title_chunks: list[str] = []
        self.body_chunks: list[str] = []

        self._in_script = False
        self._in_title = False
        self._in_style = False
        self._script_buffer: list[str] = []
        self._text_len = 0
        self._script_len = 0
        self._max_text_chars = max_text_chars
        self._max_script_chars = max_script_chars

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {k.lower(): v for k, v in attrs if k}

        if tag == "form":
            self.form_count += 1
            action = (attr.get("action") or "").strip()
            if action:
                self.form_actions.append(action)
            return

        if tag == "input":
            input_type = (attr.get("type") or "").lower()
            if input_type == "password":
                self.password_input_count += 1
            return

        if tag == "iframe":
            self.iframe_count += 1
            src = (attr.get("src") or "").strip()
            if src:
                self.resource_urls.append(src)
            return

        if tag == "script":
            src = (attr.get("src") or "").strip()
            if src:
                self.script_srcs.append(src)
                self.resource_urls.append(src)
            else:
                self._in_script = True
                self._script_buffer = []
                self._script_len = 0
            return

        if tag == "img":
            src = (attr.get("src") or "").strip()
            if src:
                self.resource_urls.append(src)
            return

        if tag == "link":
            href = (attr.get("href") or "").strip()
            if href:
                self.resource_urls.append(href)
            return

        if tag == "title":
            self._in_title = True
            return

        if tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self._in_script = False
            text = "".join(self._script_buffer).strip()
            if text:
                self.inline_scripts.append(text)
            self._script_buffer = []
            return

        if tag == "title":
            self._in_title = False
            return

        if tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if not data:
            return

        if self._in_script:
            if self._script_len >= self._max_script_chars:
                return
            remaining = self._max_script_chars - self._script_len
            chunk = data[:remaining]
            self._script_buffer.append(chunk)
            self._script_len += len(chunk)
            return

        if self._in_title:
            self.title_chunks.append(data)
            return

        if self._in_style:
            return

        if self._text_len >= self._max_text_chars:
            return
        remaining = self._max_text_chars - self._text_len
        chunk = data[:remaining]
        self.body_chunks.append(chunk)
        self._text_len += len(chunk)


def _registered_domain(host: str) -> str:
    if not host:
        return ""
    ext = tldextract.extract(host)
    parts = [ext.domain, ext.suffix]
    reg = ".".join([p for p in parts if p])
    return reg or host


def _normalize_text(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def _keyword_hits(text: str, keywords: Iterable[str]) -> float:
    lowered = (text or "").lower()
    return float(sum(1 for k in keywords if k in lowered))


def _count_regex(regex: re.Pattern, text: str) -> float:
    if not text:
        return 0.0
    return float(len(regex.findall(text)))


def extract_script_srcs(html: str) -> list[str]:
    parser = _HTMLFeatureParser()
    parser.feed(html or "")
    parser.close()
    return parser.script_srcs


def extract_content_features(
    url: str,
    html: str | None = None,
    js_texts: list[str] | None = None,
    brand: str | None = None,
) -> dict[str, float]:
    feats = {name: 0.0 for name in CONTENT_SPEC.names}

    base_url = url.strip()
    if base_url and "://" not in base_url:
        base_url = "http://" + base_url
    parsed = urlparse(base_url)
    base_host = (parsed.hostname or "").lower()
    base_reg = _registered_domain(base_host)

    brand_sim = _similarity(_normalize_text(base_reg), _normalize_text(brand or ""))
    feats["rel_domain_brand_similarity"] = brand_sim

    if not html:
        return feats

    parser = _HTMLFeatureParser()
    parser.feed(html)
    parser.close()

    form_count = float(parser.form_count)
    password_input_count = float(parser.password_input_count)
    iframe_count = float(parser.iframe_count)

    scripts_total = len(parser.script_srcs) + len(parser.inline_scripts)
    external_script_ratio = float(len(parser.script_srcs) / scripts_total) if scripts_total else 0.0

    title_text = " ".join(parser.title_chunks).strip()
    body_text = " ".join(parser.body_chunks).strip()

    keyword_title_hits = _keyword_hits(title_text, CONTENT_KEYWORDS)
    keyword_body_hits = _keyword_hits(body_text, CONTENT_KEYWORDS)

    mismatches = 0
    for action in parser.form_actions:
        action_url = urljoin(base_url, action)
        action_parsed = urlparse(action_url)
        if action_parsed.scheme not in {"http", "https"}:
            continue
        action_host = (action_parsed.hostname or "").lower()
        if not action_host:
            continue
        if _registered_domain(action_host) != base_reg:
            mismatches += 1
    form_action_mismatch_ratio = float(mismatches / form_count) if form_count else 0.0

    total_resources = 0
    external_resources = 0
    external_domains: set[str] = set()
    for res in parser.resource_urls:
        if not res:
            continue
        res_url = urljoin(base_url, res)
        res_parsed = urlparse(res_url)
        if res_parsed.scheme not in {"http", "https"}:
            continue
        total_resources += 1
        res_host = (res_parsed.hostname or "").lower()
        if not res_host:
            continue
        res_reg = _registered_domain(res_host)
        if res_reg and res_reg != base_reg:
            external_resources += 1
            external_domains.add(res_reg)

    off_domain_ratio = float(external_resources / total_resources) if total_resources else 0.0
    external_domain_count = float(len(external_domains))

    domain_title_similarity = _similarity(
        _normalize_text(base_reg),
        _normalize_text(title_text),
    )

    all_js_texts = list(parser.inline_scripts)
    if js_texts:
        all_js_texts.extend([t for t in js_texts if t])
    combined_js = "\n".join(all_js_texts)
    if len(combined_js) > 200000:
        combined_js = combined_js[:200000]

    feats.update(
        {
            "content_form_count": form_count,
            "content_password_input_count": password_input_count,
            "content_iframe_count": iframe_count,
            "content_external_script_ratio": external_script_ratio,
            "content_external_resource_domain_count": external_domain_count,
            "content_keyword_title_hits": keyword_title_hits,
            "content_keyword_body_hits": keyword_body_hits,
            "content_js_eval_count": _count_regex(_JS_EVAL_RE, combined_js),
            "content_js_atob_count": _count_regex(_JS_ATOB_RE, combined_js),
            "content_js_unescape_count": _count_regex(_JS_UNESCAPE_RE, combined_js),
            "content_js_long_base64_count": _count_regex(_JS_BASE64_RE, combined_js),
            "rel_form_action_mismatch_ratio": form_action_mismatch_ratio,
            "rel_off_domain_resource_ratio": off_domain_ratio,
            "rel_domain_title_similarity": domain_title_similarity,
        }
    )

    return {name: float(feats.get(name, 0.0)) for name in CONTENT_SPEC.names}
