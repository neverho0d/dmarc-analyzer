"""Shared fixtures. Tests never talk to the real network."""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.resolver
import pytest

from dmarc_analyzer import clear_dns_cache


class _Txt:
    def __init__(self, text: str | bytes):
        if isinstance(text, bytes):
            self.strings = (text,)
        else:
            self.strings = (text.encode("utf-8"),)


class _Addr:
    def __init__(self, address: str):
        self.address = address


class _Mx:
    def __init__(self, exchange: str):
        self.exchange = exchange


@dataclass
class FakeZone:
    """In-memory DNS used by patching dns.resolver.resolve."""

    records: dict = field(default_factory=dict)
    calls: list = field(default_factory=list)

    def _key(self, name: str, rdtype: str) -> tuple[str, str]:
        return (rdtype.upper(), name.rstrip(".").lower() + ".")

    def add(self, name: str, rdtype: str, *values: str) -> None:
        self.records.setdefault(self._key(name, rdtype), []).extend(values)

    def fail(self, name: str, rdtype: str, exc: BaseException) -> None:
        self.records[self._key(name, rdtype)] = exc

    def resolve(self, qname, qtype, search=None):
        name = str(qname)
        rtype = str(qtype).upper()
        self.calls.append((name, rtype, search))
        if search is not False:
            raise AssertionError(f"expected search=False, got {search!r}")
        if not name.endswith("."):
            raise AssertionError(f"expected absolute name, got {name!r}")
        key = self._key(name, rtype)
        if key not in self.records:
            raise dns.resolver.NXDOMAIN
        payload = self.records[key]
        if isinstance(payload, BaseException):
            raise payload
        if not payload:
            raise dns.resolver.NoAnswer
        answers = []
        for value in payload:
            if rtype == "TXT":
                answers.append(_Txt(value))
            elif rtype == "MX":
                answers.append(_Mx(value))
            else:
                answers.append(_Addr(value))
        return answers


@pytest.fixture
def zone(monkeypatch):
    fake = FakeZone()
    monkeypatch.setattr(dns.resolver, "resolve", fake.resolve)
    return fake


@pytest.fixture(autouse=True)
def _isolate_dns_cache():
    clear_dns_cache()
    yield
    clear_dns_cache()


@pytest.fixture
def viewer_config():
    return {
        "AUTHORIZED_SERVER_NETS": ["120.138.21.73"],
        "REPORT_AUTHORIZED_ONLY": True,
        "TARGET_DOMAINS": ["example.com"],
        "ALERT_EMAIL_TO": "dmarc@example.com",
        "FALLBACK_DKIM_SELECTORS": ["default"],
    }
