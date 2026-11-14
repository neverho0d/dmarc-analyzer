import gzip
import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

from dmarc_analyzer import extract_xml_payload, parse_dmarc_report

FIXTURE = Path(__file__).parent / "fixtures" / "report.xml"


def test_parse_dmarc_report_extracts_policy_and_records():
    report = parse_dmarc_report(FIXTURE.read_bytes())
    assert report["metadata"]["org_name"] == "google.com"
    assert report["metadata"]["policy_domain"] == "example.com"
    assert report["metadata"]["policy_p"] == "reject"
    assert len(report["records"]) == 2
    first, second = report["records"]
    assert first["source_ip"] == "120.138.21.73"
    assert first["auth_dkim"][0]["selector"] == "snipesoft"
    assert second["source_ip"] == "8.8.8.8"
    assert second["disposition"] == "reject"


def test_extract_xml_from_raw_gzip():
    raw = gzip.compress(FIXTURE.read_bytes())
    xml = extract_xml_payload(raw, 20 * 1024 * 1024)
    assert xml is not None
    assert parse_dmarc_report(xml)["metadata"]["report_id"] == "1"


def test_extract_xml_from_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("google.com!example.com!1!2.xml", FIXTURE.read_bytes())
    xml = extract_xml_payload(buf.getvalue(), 20 * 1024 * 1024)
    assert parse_dmarc_report(xml)["metadata"]["policy_domain"] == "example.com"


def test_extract_xml_from_rfc822_attachment():
    msg = EmailMessage()
    msg["Subject"] = "Report Domain: example.com Submitter: google.com Report-ID: 1"
    msg["From"] = "noreply-dmarc-support@google.com"
    msg["To"] = "dmarc@example.com"
    msg.set_content("aggregate report")
    msg.add_attachment(
        gzip.compress(FIXTURE.read_bytes()),
        maintype="application",
        subtype="gzip",
        filename="report.xml.gz",
    )
    xml = extract_xml_payload(msg.as_bytes(), 20 * 1024 * 1024)
    assert parse_dmarc_report(xml)["records"][0]["count"] == 2


def test_extract_xml_rejects_unrelated_payload():
    assert extract_xml_payload(b"hello world", 1024) is None
