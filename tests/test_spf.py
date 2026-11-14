from dmarc_analyzer import (
    _recommendation_items,
    diagnose_domain_dns,
    evaluate_spf_authorization,
)


def test_spf_pass_via_include_does_not_recommend_adding_ip(zone):
    zone.add(
        "example.com",
        "TXT",
        "v=spf1 a mx include:_spf.example.net ip4:120.138.21.110 ~all",
        "google-site-verification=x",
    )
    zone.add("_spf.example.net", "TXT", "v=spf1 ip4:120.138.21.73 ip6:2403:7000:8000:500::2d ~all")
    zone.add("example.com", "A", "203.0.113.10")
    zone.add("example.com", "MX", "mail.example.com.")
    zone.add("mail.example.com", "A", "203.0.113.11")
    zone.add("snipesoft._domainkey.example.com", "TXT", "v=DKIM1; p=abc")
    zone.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")

    result = evaluate_spf_authorization("example.com", "120.138.21.73")
    assert result["authorized"] is True
    assert result["via"] == "include:_spf.example.net"
    assert result["result"] == "pass"

    diag = diagnose_domain_dns(
        "example.com", "120.138.21.73", ["snipesoft"], authorize_source_ip=True
    )
    assert diag["spf"]["present"] is True
    assert diag["spf"]["ip_authorized"] is True
    assert diag["spf"]["recommendation"] is None
    items = _recommendation_items(
        diag,
        "120.138.21.73",
        True,
        {"ALERT_EMAIL_TO": "a@b.c", "FALLBACK_DKIM_SELECTORS": ["snipesoft"]},
    )
    spf = next(item for item in items if item["kind"] == "SPF")
    assert spf["action"] == "keep"
    assert spf["is_change"] is False


def test_spf_unrelated_ip_is_not_authorized(zone):
    zone.add("example.com", "TXT", "v=spf1 include:_spf.example.net ~all")
    zone.add("_spf.example.net", "TXT", "v=spf1 ip4:120.138.21.73 ~all")
    result = evaluate_spf_authorization("example.com", "8.8.8.8")
    assert result["authorized"] is False
    assert result["result"] == "softfail"


def test_include_timeout_is_temperror_not_an_spf_update(zone):
    zone.add("example.com", "TXT", "v=spf1 include:_spf.example.net ~all")
    zone.fail("_spf.example.net", "TXT", __import__("dns.exception", fromlist=["Timeout"]).Timeout())
    zone.add("snipesoft._domainkey.example.com", "TXT", "v=DKIM1; p=abc")
    zone.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")

    result = evaluate_spf_authorization("example.com", "120.138.21.73")
    assert result["authorized"] is False
    assert result["result"] == "temperror"

    diag = diagnose_domain_dns(
        "example.com", "120.138.21.73", ["snipesoft"], authorize_source_ip=True
    )
    assert diag["spf"]["present"] is True
    assert "Authorize sender IP" not in (diag["spf"]["recommendation"] or "")
    items = _recommendation_items(
        diag,
        "120.138.21.73",
        True,
        {"ALERT_EMAIL_TO": "a@b.c", "FALLBACK_DKIM_SELECTORS": ["snipesoft"]},
    )
    spf = next(item for item in items if item["kind"] == "SPF")
    assert spf["action"].startswith("check")
    assert "update (authorize" not in spf["action"]


def test_direct_ip4_mechanism_authorizes(zone):
    zone.add("example.com", "TXT", "v=spf1 ip4:192.0.2.0/24 ~all")
    result = evaluate_spf_authorization("example.com", "192.0.2.10")
    assert result["authorized"] is True
    assert result["via"] == "ip4:192.0.2.0/24"


def test_a_mechanism_authorizes_resolved_host(zone):
    zone.add("example.com", "TXT", "v=spf1 a ~all")
    zone.add("example.com", "A", "198.51.100.8")
    result = evaluate_spf_authorization("example.com", "198.51.100.8")
    assert result["authorized"] is True
    assert result["via"] == "a"
