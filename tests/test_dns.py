import dns.exception

from dmarc_analyzer import (
    _absolute_dns_name,
    _recommendation_items,
    _spf_txt_candidate,
    diagnose_domain_dns,
    dns_lookup_error,
    query_dns,
)


def test_absolute_dns_name_adds_trailing_dot():
    assert _absolute_dns_name("qualitycaraudio.co.nz") == "qualitycaraudio.co.nz."
    assert _absolute_dns_name("qualitycaraudio.co.nz.") == "qualitycaraudio.co.nz."


def test_spf_txt_candidate_ignores_verification_and_quotes():
    assert _spf_txt_candidate("google-site-verification=abc") is None
    assert _spf_txt_candidate('"v=spf1 ~all"') == "v=spf1 ~all"
    assert _spf_txt_candidate("  v=spf1 include:_spf.example.net ~all") == (
        "v=spf1 include:_spf.example.net ~all"
    )


def test_query_dns_uses_absolute_name_and_disables_search(zone):
    zone.add("example.com", "TXT", "v=spf1 ~all", "google-site-verification=x")
    records = query_dns("example.com", "TXT")
    assert "v=spf1 ~all" in records
    assert zone.calls == [("example.com.", "TXT", False)]


def test_query_dns_does_not_cache_timeout_as_empty(zone):
    zone.fail("example.com", "TXT", dns.exception.Timeout())
    assert query_dns("example.com", "TXT") == []
    assert dns_lookup_error("example.com", "TXT") == "Timeout"
    from dmarc_analyzer import DNS_CACHE

    assert ("TXT", "example.com") not in DNS_CACHE


def test_nxdomain_is_cached_as_empty_answer(zone):
    assert query_dns("missing.example", "TXT") == []
    assert dns_lookup_error("missing.example", "TXT") is None
    zone.add("missing.example", "TXT", "v=spf1 ~all")
    # Cached NXDOMAIN/empty must not be overwritten by later zone edits.
    assert query_dns("missing.example", "TXT") == []


def test_diagnose_timeout_does_not_recommend_adding_spf(zone):
    zone.fail("example.com", "TXT", dns.exception.Timeout())
    zone.add("snipesoft._domainkey.example.com", "TXT", "v=DKIM1; p=abc")
    zone.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")
    diag = diagnose_domain_dns(
        "example.com", "120.138.21.73", ["snipesoft"], authorize_source_ip=True
    )
    assert diag["spf"]["present"] is False
    assert diag["spf"].get("error") == "Timeout"
    assert "Add TXT" not in (diag["spf"]["recommendation"] or "")
    items = _recommendation_items(
        diag,
        "120.138.21.73",
        True,
        {"ALERT_EMAIL_TO": "a@b.c", "FALLBACK_DKIM_SELECTORS": ["snipesoft"]},
    )
    spf = next(item for item in items if item["kind"] == "SPF")
    assert spf["action"].startswith("check")
    assert "ip4:120.138.21.73" not in spf["value"]


def test_diagnose_missing_spf_still_recommends_add(zone):
    zone.add("example.com", "TXT", "google-site-verification=x")
    zone.add("default._domainkey.example.com", "TXT", "v=DKIM1; p=abc")
    zone.add("_dmarc.example.com", "TXT", "v=DMARC1; p=reject")
    diag = diagnose_domain_dns(
        "example.com", "120.138.21.73", ["default"], authorize_source_ip=True
    )
    assert diag["spf"]["present"] is False
    assert "Add TXT" in (diag["spf"]["recommendation"] or "")
    items = _recommendation_items(
        diag,
        "120.138.21.73",
        True,
        {"ALERT_EMAIL_TO": "a@b.c", "FALLBACK_DKIM_SELECTORS": ["default"]},
    )
    spf = next(item for item in items if item["kind"] == "SPF")
    assert spf["action"] == "add"
    assert spf["value"] == "v=spf1 ip4:120.138.21.73 ~all"


def test_noanswer_is_not_a_transient_error(zone):
    zone.records[zone._key("example.com", "TXT")] = []
    assert query_dns("example.com", "TXT") == []
    assert dns_lookup_error("example.com", "TXT") is None
