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


def test_infra_features_from_metadata():
    url = "https://example.com"
    meta = {
        "infra": {
            "infra_domain_age_days": 100.0,
            "infra_domain_age_known": 1.0,
            "infra_dns_min_ttl": 300.0,
            "infra_dns_ttl_known": 1.0,
            "infra_tls_days_to_expiry": 60.0,
            "infra_tls_known": 1.0,
            "infra_tls_verified": 1.0,
        }
    }
    feats = extract_features(url, metadata=meta)
    assert feats["infra_domain_age_days"] == 100.0
    assert feats["infra_dns_min_ttl"] == 300.0
    assert feats["infra_tls_verified"] == 1.0


def test_content_features_basic():
    url = "https://example.com"
    html = """
    <html>
      <head><title>Verify Your Account</title></head>
      <body>
        <form action="https://evil.com/submit">
          <input type="password" />
        </form>
        <iframe src="https://cdn.example.net/frame"></iframe>
        <script>eval("x");</script>
        <script src="https://evil.com/app.js"></script>
      </body>
    </html>
    """
    feats = extract_features(url, html=html)
    assert feats["content_form_count"] == 1.0
    assert feats["content_password_input_count"] == 1.0
    assert feats["content_iframe_count"] == 1.0
    assert feats["content_external_script_ratio"] > 0.0
    assert feats["content_keyword_title_hits"] >= 1.0
    assert feats["content_js_eval_count"] >= 1.0
    assert feats["rel_form_action_mismatch_ratio"] == 1.0
