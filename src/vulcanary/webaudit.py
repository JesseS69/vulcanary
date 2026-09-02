from __future__ import annotations

import ssl
import ipaddress
import socket
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .models import Finding, Severity
from .version import __version__


class _SameHostRedirects(HTTPRedirectHandler):
    def __init__(self, host: str) -> None:
        self.host = host

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).hostname != self.host:
            raise ValueError("web audit refused a redirect to a different host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _finding(rule: str, title: str, severity: Severity, target: str, remediation: str, evidence: str = "") -> Finding:
    return Finding(rule, title, title, severity, "dast", f"web-target/{urlparse(target).hostname}", 1, evidence, remediation, "vulcanary-web", {"target": target, "mode": "passive"})


def _resolved_addresses(host: str, port: int, allow_private: bool) -> frozenset[str]:
    try:
        addresses = frozenset(item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    except OSError as error:
        raise ValueError("web audit could not resolve the authorized hostname") from error
    if not addresses:
        raise ValueError("web audit could not resolve the authorized hostname")
    if not allow_private:
        for value in addresses:
            address = ipaddress.ip_address(value)
            if not address.is_global:
                raise ValueError("web audit refuses private, loopback, link-local, reserved, or otherwise non-public targets")
    return addresses


def audit_web_target(url: str, authorized_host: str, timeout: int = 20, allow_private: bool = False) -> list[Finding]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme not in {"http", "https"} or not host or parsed.username or parsed.password:
        raise ValueError("target must be an HTTP(S) URL without embedded credentials")
    if authorized_host.strip().lower() != host:
        raise ValueError("--authorize-target must exactly match the target hostname")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    initial_addresses = _resolved_addresses(host, port, allow_private)
    request = Request(url, headers={"User-Agent": f"Vulcanary/{__version__} passive-web-audit"}, method="GET")
    opener = build_opener(_SameHostRedirects(host), HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(request, timeout=max(1, min(timeout, 60))) as response:
        final_url = response.geturl()
        headers = response.headers
    if _resolved_addresses(host, port, allow_private) != initial_addresses:
        raise ValueError("web audit refused a hostname whose DNS addresses changed during the request")
    findings = []
    if urlparse(final_url).scheme != "https":
        findings.append(_finding("DAST-HTTPS", "Target does not enforce HTTPS", Severity.HIGH, final_url, "Redirect all HTTP traffic to HTTPS and disable plaintext service access."))
    normalized = {key.lower(): value for key, value in headers.items()}
    checks = [
        ("strict-transport-security", "DAST-HSTS", "HSTS header is missing", Severity.MEDIUM, "Add a reviewed Strict-Transport-Security policy after HTTPS is fully deployed."),
        ("content-security-policy", "DAST-CSP", "Content Security Policy is missing", Severity.MEDIUM, "Deploy a restrictive Content-Security-Policy and test it in report-only mode first."),
        ("x-content-type-options", "DAST-NOSNIFF", "X-Content-Type-Options is missing", Severity.LOW, "Set X-Content-Type-Options: nosniff."),
        ("x-frame-options", "DAST-FRAME", "Clickjacking protection header is missing", Severity.LOW, "Set frame-ancestors in CSP or an appropriate X-Frame-Options header."),
        ("referrer-policy", "DAST-REFERRER", "Referrer Policy is missing", Severity.LOW, "Set a privacy-preserving Referrer-Policy."),
    ]
    for header, rule, title, severity, remediation in checks:
        if header not in normalized:
            findings.append(_finding(rule, title, severity, final_url, remediation))
    for cookie in headers.get_all("Set-Cookie", []):
        lower = cookie.lower()
        cookie_name = cookie.split("=", 1)[0].strip() or "cookie"
        if "secure" not in lower:
            findings.append(_finding("DAST-COOKIE-SECURE", "Cookie lacks the Secure attribute", Severity.MEDIUM, final_url, "Mark session and sensitive cookies Secure.", cookie_name))
        if "httponly" not in lower:
            findings.append(_finding("DAST-COOKIE-HTTPONLY", "Cookie lacks the HttpOnly attribute", Severity.MEDIUM, final_url, "Mark cookies not required by JavaScript HttpOnly.", cookie_name))
        if "samesite=" not in lower:
            findings.append(_finding("DAST-COOKIE-SAMESITE", "Cookie lacks a SameSite policy", Severity.LOW, final_url, "Set an explicit SameSite policy appropriate for the application.", cookie_name))
    return sorted({item.fingerprint: item for item in findings}.values(), key=lambda item: (-int(item.severity), item.rule_id))
