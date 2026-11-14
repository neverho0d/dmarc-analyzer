from dmarc_analyzer import format_viewer_report


def keep_diag(domain: str, source_ip: str = "120.138.21.73"):
    return {
        "domain": domain,
        "spf": {
            "present": True,
            "raw": f"v=spf1 ip4:{source_ip} ~all",
            "ip_authorized": True,
            "recommendation": None,
        },
        "dkim": {
            "checked_selectors": {"snipesoft": {"present": True, "raw": "v=DKIM1; p=abc"}},
            "recommendations": [],
        },
        "dmarc": {"present": True, "raw": "v=DMARC1; p=reject", "recommendation": None},
    }


def _report(records, policy_p="reject", policy_sp="reject", policy_pct="100"):
    return {
        "metadata": {
            "org_name": "google.com",
            "email": "noreply-dmarc-support@google.com",
            "report_id": "1",
            "policy_domain": "example.com",
            "policy_p": policy_p,
            "policy_sp": policy_sp,
            "policy_pct": policy_pct,
        },
        "records": records,
    }


def _record(source_ip="120.138.21.73", *, spf="pass", dkim="pass", count=2, disposition="none"):
    return {
        "source_ip": source_ip,
        "count": count,
        "disposition": disposition,
        "dkim_eval": dkim,
        "spf_eval": spf,
        "header_from": "example.com",
        "auth_dkim": [{"selector": "snipesoft", "result": "pass", "domain": "example.com"}],
    }


def test_keep_only_records_are_omitted_and_count_is_in_summary(monkeypatch, viewer_config):
    monkeypatch.setattr(
        "dmarc_analyzer.diagnose_domain_dns",
        lambda *args, **kwargs: keep_diag("example.com"),
    )
    text = format_viewer_report(
        _report([_record(), _record(count=7, spf="fail")]),
        viewer_config,
        env_path="/tmp/analyzer.env",
    )
    header, _, summary = text.partition(" SUMMARY — CHANGES TO APPLY")
    assert "Record Count" not in header
    assert "Record Count : 0 listed (2 in file; 2 omitted, no recommended changes)" in summary
    assert "No changes recommended for the current setup." in summary
    assert "--- [Record #" not in text


def test_unauthorized_spam_omitted_under_strict_dmarc(monkeypatch, viewer_config):
    monkeypatch.setattr(
        "dmarc_analyzer.diagnose_domain_dns",
        lambda *args, **kwargs: keep_diag("example.com"),
    )
    text = format_viewer_report(
        _report(
            [
                _record(),
                _record(source_ip="8.8.8.8", spf="fail", dkim="fail", disposition="reject", count=9),
            ]
        ),
        viewer_config,
    )
    assert "8.8.8.8" not in text
    assert "unauthorized IP under p=reject; sp=reject" in text
    assert "--- [Record #" not in text


def test_missing_spf_lists_record_and_summary_change(monkeypatch, viewer_config):
    def diagnose(domain, source_ip, selectors, config=None, authorize_source_ip=True):
        diag = keep_diag(domain, source_ip)
        diag["spf"] = {
            "present": False,
            "raw": None,
            "ip_authorized": False,
            "recommendation": f'Add TXT record for {domain}:\n  Value: "v=spf1 ip4:{source_ip} ~all"',
        }
        return diag

    monkeypatch.setattr("dmarc_analyzer.diagnose_domain_dns", diagnose)
    text = format_viewer_report(_report([_record()]), viewer_config)
    assert "--- [Record #1]" in text
    assert "Action: add" in text
    assert "Record Count : 1 listed (1 in file)" in text


def test_weak_dmarc_lists_unauthorized_spam_with_notice(monkeypatch, viewer_config):
    def diagnose(domain, source_ip, selectors, config=None, authorize_source_ip=True):
        diag = keep_diag(domain, source_ip)
        if not authorize_source_ip:
            diag["dmarc"] = {
                "present": True,
                "raw": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
                "recommendation": "update (raise policy; spam is allowed under p=none)",
            }
        return diag

    monkeypatch.setattr("dmarc_analyzer.diagnose_domain_dns", diagnose)
    text = format_viewer_report(
        _report([_record(source_ip="8.8.8.8", spf="fail", dkim="fail")], policy_p="none", policy_sp="", policy_pct="100"),
        viewer_config,
    )
    assert "8.8.8.8" in text
    assert "This spam is allowed due to the weak DMARC policy - p=none" in text
    assert "External source: do not publish this IP in your SPF record." in text
    assert "unauthorized spam listed" in text
