from __future__ import annotations
from app.core.features import extract_features, vectorize, SPEC
from urllib.parse import urlparse, urlunparse

def canonicalize_url(url: str) -> str:
    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # strip common www
    if netloc.startswith("www."):
        netloc = netloc[4:]

    path = parsed.path.rstrip("/") or "/"

    return urlunparse((scheme, netloc, path, "", "", ""))

def test_extract_features_has_all_keys():
    url = "https://example.com/path?x=1&y=2"
    feats = extract_features(url)

    assert set(feats.keys()) == set(SPEC.names)
    for k in SPEC.names:
        assert isinstance(feats[k], float)


def test_vectorize_length_matches_spec():
    url = "https://example.com"
    vec = vectorize(url)
    assert len(vec) == len(SPEC.names)


def test_missing_scheme_is_handled():
    url = "example.com/login"
    feats = extract_features(url)  # should not crash
    assert feats["host_len"] > 0.0


def test_basic_flags():
    url = "http://192.168.1.1/login@evil"
    feats = extract_features(url)
    assert feats["has_ip_host"] in (0.0, 1.0)
    assert feats["has_at_symbol"] in (0.0, 1.0)
