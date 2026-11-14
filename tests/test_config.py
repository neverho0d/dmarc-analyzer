from dmarc_analyzer import (
    dmarc_policy_is_strict,
    domain_covered,
    load_config_bundle,
    published_policy_label,
    select_profile,
)


def test_parse_env_profiles(tmp_path):
    path = tmp_path / "analyzer.env"
    path.write_text(
        "\n".join(
            [
                "# comment",
                "TARGET_DOMAINS=example.com,shop.example.com",
                "AUTHORIZED_SERVER_NETS=127.0.0.1",
                "REPORT_AUTHORIZED_ONLY=true",
                "ALERT_EMAIL_TO=postmaster@example.com",
                "PROFILE_4JOB_TARGET_DOMAINS=4job.co",
                "PROFILE_4JOB_AUTHORIZED_SERVER_NETS=120.138.18.240/28",
                "PROFILE_4JOB_ALERT_EMAIL_TO=postmaster@4job.co",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    bundle = load_config_bundle(str(path))
    assert bundle["profiles"]["default"]["TARGET_DOMAINS"] == ["example.com", "shop.example.com"]
    named = bundle["profiles"]["4job"]
    assert named["TARGET_DOMAINS"] == ["4job.co"]
    assert named["AUTHORIZED_SERVER_NETS"] == ["120.138.18.240/28"]
    assert named["ALERT_EMAIL_TO"] == "postmaster@4job.co"
    assert named["REPORT_AUTHORIZED_ONLY"] is True


def test_select_profile_prefers_longest_matching_domain(tmp_path):
    path = tmp_path / "analyzer.env"
    path.write_text(
        "TARGET_DOMAINS=example.com\n"
        "PROFILE_SHOP_TARGET_DOMAINS=shop.example.com\n",
        encoding="utf-8",
    )
    bundle = load_config_bundle(str(path))
    name, config, match = select_profile(bundle, "shop.example.com")
    assert name == "SHOP"
    assert config["TARGET_DOMAINS"] == ["shop.example.com"]
    assert "shop.example.com" in match

    name, config, match = select_profile(bundle, "www.example.com")
    assert name == "default"
    assert config["TARGET_DOMAINS"] == ["example.com"]


def test_domain_covered_includes_subdomains():
    assert domain_covered("mail.example.com", ["example.com"])
    assert domain_covered("example.com", ["example.com"])
    assert not domain_covered("example.org", ["example.com"])


def test_dmarc_policy_strictness_and_label():
    reject = {"policy_p": "reject", "policy_sp": "reject", "policy_pct": "100"}
    assert dmarc_policy_is_strict(reject)
    assert published_policy_label(reject) == "p=reject; sp=reject"

    weak = {"policy_p": "none", "policy_sp": "", "policy_pct": "100"}
    assert not dmarc_policy_is_strict(weak)
    assert published_policy_label(weak) == "p=none"

    partial = {"policy_p": "reject", "policy_sp": "", "policy_pct": "50"}
    assert not dmarc_policy_is_strict(partial)
    assert published_policy_label(partial) == "p=reject; pct=50"
