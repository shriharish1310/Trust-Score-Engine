from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone

import dns.resolver
import tldextract

try:
    import whois  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    whois = None  # type: ignore[assignment]


@dataclass(frozen=True)
class InfraFeatureSpec:
    names: tuple[str, ...] = (
        "infra_domain_age_days",
        "infra_domain_age_known",
        "infra_dns_min_ttl",
        "infra_dns_ttl_known",
        "infra_tls_days_to_expiry",
        "infra_tls_known",
        "infra_tls_verified",
    )


INFRA_SPEC = InfraFeatureSpec()

_IP_V4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _host_no_port(host: str) -> str:
    h = (host or "").strip().lower()
    if h.startswith("["):
        end = h.find("]")
        if end > 0:
            return h[1:end]
    if ":" in h and not _IP_V4.match(h):
        # could be host:port (not IPv6)
        return h.rsplit(":", 1)[0]
    return h


def _is_ip_literal(host: str) -> bool:
    raw = _host_no_port(host)
    if raw.startswith("["):
        raw = raw[1:-1] if raw.endswith("]") else raw[1:]
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    h = _host_no_port(host)
    try:
        ext = tldextract.extract(h)
    except Exception:
        ext = tldextract.extract("")
    return ".".join([p for p in [ext.domain, ext.suffix] if p])


def _parse_whois_dates(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, list):
        for v in value:
            dt = _parse_whois_dates(v)
            if dt is not None:
                return dt
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


def _domain_age_days(registered_domain: str, timeout: float) -> tuple[float, bool]:
    if not registered_domain or whois is None:
        return 0.0, False

    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        w = whois.whois(registered_domain)
    except Exception:
        return 0.0, False
    finally:
        socket.setdefaulttimeout(old_timeout)

    created = getattr(w, "creation_date", None) or getattr(w, "registered", None)
    dt = _parse_whois_dates(created)
    if dt is None:
        return 0.0, False

    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    days = max(0.0, float(delta.days))
    return min(days, 50000.0), True


def _dns_min_ttl(host: str, timeout: float) -> tuple[float, bool]:
    h = _host_no_port(host)
    if not h or _is_ip_literal(h):
        return 0.0, False

    lifetime = max(0.5, min(timeout, 30.0))
    try:
        ans = dns.resolver.resolve(h, "A", lifetime=lifetime)
    except Exception:
        try:
            ans = dns.resolver.resolve(h, "AAAA", lifetime=lifetime)
        except Exception:
            return 0.0, False

    try:
        ttl = float(ans.rrset.ttl) if ans.rrset is not None else 0.0
    except Exception:
        return 0.0, False

    if ttl <= 0:
        return 0.0, False
    return min(ttl, 2**31 - 1), True


def _cert_expiry_days(cert: dict) -> float | None:
    na = cert.get("notAfter")
    if not na:
        return None
    try:
        exp = ssl.cert_time_to_seconds(na)
    except (ValueError, TypeError):
        return None
    return max(0.0, (exp - time.time()) / 86400.0)


def _tls_days_verified(host: str, timeout: float) -> tuple[float, bool, bool]:
    """Returns (days_to_expiry, got_cert, verified_hostname)."""
    h = _host_no_port(host)
    if not h or _is_ip_literal(h):
        return 0.0, False, False

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((h, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                cert = ssock.getpeercert()
                days = _cert_expiry_days(cert)
                if days is None:
                    return 0.0, True, True
                return min(days, 10000.0), True, True
    except ssl.SSLError:
        pass
    except OSError:
        return 0.0, False, False

    try:
        ctx = ssl._create_unverified_context()  # noqa: SLF001
        with socket.create_connection((h, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=h) as ssock:
                cert = ssock.getpeercert()
                days = _cert_expiry_days(cert)
                if days is None:
                    return 0.0, True, False
                return min(days, 10000.0), True, False
    except Exception:
        return 0.0, False, False


def fetch_infrastructure(
    host: str,
    *,
    timeout: float = 5.0,
) -> dict[str, float]:
    """
    Resolve WHOIS domain age, DNS TTL (A/AAAA), and TLS certificate signals for `host`.
    Values are safe floats for the ML vector; use *_known flags when a lookup succeeded.
    """
    h = _host_no_port(host)
    if not h:
        return {name: 0.0 for name in INFRA_SPEC.names}

    per_task = max(1.0, min(timeout / 3.0, timeout))

    age_days, age_known = 0.0, False
    dns_ttl, dns_known = 0.0, False
    tls_days, tls_known, tls_verified = 0.0, False, False

    if not _is_ip_literal(h):
        rd = _registered_domain(h)

        def _age_job() -> tuple[float, bool]:
            if not rd:
                return 0.0, False
            return _domain_age_days(rd, per_task)

        def _dns_job() -> tuple[float, bool]:
            return _dns_min_ttl(h, per_task)

        def _tls_job() -> tuple[float, bool, bool]:
            return _tls_days_verified(h, per_task)

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_age = pool.submit(_age_job)
            f_dns = pool.submit(_dns_job)
            f_tls = pool.submit(_tls_job)
            try:
                age_days, age_known = f_age.result(timeout=per_task + 2.0)
            except Exception:
                pass
            try:
                dns_ttl, dns_known = f_dns.result(timeout=per_task + 2.0)
            except Exception:
                pass
            try:
                tls_days, tls_known, tls_verified = f_tls.result(timeout=per_task + 2.0)
            except Exception:
                pass
    else:
        tls_days, tls_known, tls_verified = _tls_days_verified(h, per_task)

    return {
        "infra_domain_age_days": float(age_days),
        "infra_domain_age_known": 1.0 if age_known else 0.0,
        "infra_dns_min_ttl": float(dns_ttl),
        "infra_dns_ttl_known": 1.0 if dns_known else 0.0,
        "infra_tls_days_to_expiry": float(tls_days),
        "infra_tls_known": 1.0 if tls_known else 0.0,
        "infra_tls_verified": 1.0 if tls_verified else 0.0,
    }


def extract_infra_features(metadata: dict | None) -> dict[str, float]:
    meta = metadata or {}
    src = meta.get("infra")
    if not isinstance(src, dict):
        return {name: 0.0 for name in INFRA_SPEC.names}
    out: dict[str, float] = {}
    for name in INFRA_SPEC.names:
        v = src.get(name, 0.0)
        try:
            out[name] = float(v)
        except (TypeError, ValueError):
            out[name] = 0.0
    return out
