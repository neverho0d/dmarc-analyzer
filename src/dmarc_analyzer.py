#!/usr/bin/env python3
"""
DMARC Report Analyzer and Alert Dispatcher

Accepts DMARC reports piped via STDIN (RFC 5322 email, .xml, .gz, or .zip)
or specified via --file. Analyzes delivery failures from authorized sending IPs,
verifies DNS records (SPF, DKIM, DMARC), suggests fixes, and emails the results.
"""

import sys
import os
import io
import copy
import re
import gzip
import zipfile
import argparse
import ipaddress
import email
from collections import defaultdict
from email import policy
from email.message import EmailMessage
import subprocess
import smtplib
from typing import List, Dict, Tuple, Set, Optional
import xml.etree.ElementTree as ET

try:
    import dns.exception
    import dns.resolver
except ImportError:
    sys.exit("Error: 'dnspython' package is required. Install via: pip install dnspython")

# ==============================================================================
# DEFAULT CONFIGURATION
# ==============================================================================
DEFAULT_CONFIG = {
    # The sending domain(s) you own and want to monitor
    "TARGET_DOMAINS": ["example.com", "4job.co"],
    
    # Authorized outbound mail server IPs or subnets (CIDR notation supported)
    "AUTHORIZED_SERVER_NETS": [
        "95.217.200.86/32",
        "120.138.18.240/28",
        "127.0.0.1/32"
    ],
    
    # Default selectors to probe if the DMARC report omits selector metadata
    "FALLBACK_DKIM_SELECTORS": ["default", "s1", "srs", "mail"],
    
    # Alert destination
    "ALERT_EMAIL_TO": "postmaster@example.com",
    "ALERT_EMAIL_FROM": "dmarc-analyzer@example.com",
    
    # Dispatch method: "sendmail" (local Postfix/sendmail) or "smtp"
    "DISPATCH_METHOD": "sendmail",
    "SMTP_HOST": "127.0.0.1",
    "SMTP_PORT": 25,
    
    # Max allowed uncompressed payload size (protection against decompression bombs)
    "MAX_PAYLOAD_SIZE": 20 * 1024 * 1024,  # 20 MB

    # Viewer: skip records whose source IP is outside AUTHORIZED_SERVER_NETS
    "REPORT_AUTHORIZED_ONLY": True,
}

# In-memory DNS cache: (qtype, query_name) -> List[str]
DNS_CACHE: Dict[Tuple[str, str], List[str]] = {}
# Transient lookup failures are not stored as empty answers.
DNS_LOOKUP_ERRORS: Dict[Tuple[str, str], str] = {}
SPF_DNS_LOOKUP_LIMIT = 10
_DNS_TRANSIENT = (dns.resolver.NoNameservers, dns.exception.Timeout)


def clear_dns_cache() -> None:
    """Drop cached DNS answers and lookup errors (used by tests)."""
    DNS_CACHE.clear()
    DNS_LOOKUP_ERRORS.clear()

_LIST_KEYS = ("TARGET_DOMAINS", "AUTHORIZED_SERVER_NETS", "FALLBACK_DKIM_SELECTORS")
_STR_KEYS = ("ALERT_EMAIL_TO", "ALERT_EMAIL_FROM", "DISPATCH_METHOD", "SMTP_HOST")
_INT_KEYS = ("SMTP_PORT", "MAX_PAYLOAD_SIZE")
_BOOL_KEYS = ("REPORT_AUTHORIZED_ONLY",)
_PROFILE_KEYS = (*_LIST_KEYS, *_STR_KEYS, *_INT_KEYS, *_BOOL_KEYS)
_PROFILE_KEY_SUFFIXES = tuple(sorted(_PROFILE_KEYS, key=len, reverse=True))
_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}


def _parse_bool(raw: str) -> Optional[bool]:
    value = raw.strip().lower()
    if value in _BOOL_TRUE:
        return True
    if value in _BOOL_FALSE:
        return False
    return None


def parse_env_file(path: str) -> Dict[str, str]:
    """Parse KEY=VALUE lines from an analyzer.env-style file."""
    parsed: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                value = value[1:-1]
            parsed[key] = value
    return parsed


def _apply_config_values(config: Dict, values: Dict[str, str]) -> None:
    for key in _LIST_KEYS:
        raw = values.get(key, "").strip()
        if raw:
            config[key] = [item.strip() for item in raw.split(",") if item.strip()]
    for key in _STR_KEYS:
        raw = values.get(key, "").strip()
        if raw:
            config[key] = raw
    for key in _INT_KEYS:
        raw = values.get(key, "").strip()
        if raw:
            config[key] = int(raw)
    for key in _BOOL_KEYS:
        raw = values.get(key, "").strip()
        if raw:
            parsed = _parse_bool(raw)
            if parsed is not None:
                config[key] = parsed


def _merge_env_values(env_file: Optional[str] = None) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    if env_file:
        merged.update(parse_env_file(env_file))
    for key, value in os.environ.items():
        if key in _PROFILE_KEYS or key.startswith("PROFILE_"):
            raw = value.strip()
            if raw:
                merged[key] = raw
    return merged


def _split_profile_key(key: str) -> Optional[Tuple[str, str]]:
    """Map PROFILE_4JOB_TARGET_DOMAINS -> ('4JOB', 'TARGET_DOMAINS')."""
    if not key.startswith("PROFILE_"):
        return None
    rest = key[len("PROFILE_"):]
    for known in _PROFILE_KEY_SUFFIXES:
        suffix = f"_{known}"
        if rest.endswith(suffix) and rest != known:
            name = rest[: -len(suffix)]
            if name:
                return name, known
    return None


def _normalize_domain(value: str) -> str:
    return (value or "").strip().lower().rstrip(".")


def domain_covered(candidate: str, owned_domains: List[str]) -> bool:
    """True if candidate is an owned domain or a subdomain of one."""
    cand = _normalize_domain(candidate)
    if not cand:
        return False
    for owned in owned_domains:
        own = _normalize_domain(owned)
        if own and (cand == own or cand.endswith(f".{own}")):
            return True
    return False


def load_config_bundle(env_file: Optional[str] = None) -> Dict:
    """Load the default profile plus any PROFILE_<name>_* overrides.

    Unprefixed keys are the default profile. Named profiles inherit those
    values and override the keys they set. MAX_PAYLOAD_SIZE stays global.
    """
    merged = _merge_env_values(env_file)
    default_values = {key: value for key, value in merged.items() if not key.startswith("PROFILE_")}
    default = copy.deepcopy(DEFAULT_CONFIG)
    _apply_config_values(default, default_values)

    overrides: Dict[str, Dict[str, str]] = defaultdict(dict)
    labels: Dict[str, str] = {}
    for key, value in merged.items():
        split = _split_profile_key(key)
        if not split:
            continue
        label, cfg_key = split
        ident = label.lower()
        labels[ident] = label
        overrides[ident][cfg_key] = value

    profiles = {"default": default}
    for ident, values in overrides.items():
        cfg = copy.deepcopy(default)
        _apply_config_values(cfg, values)
        profiles[ident] = cfg

    return {"profiles": profiles, "labels": {"default": "default", **labels}, "env_file": env_file}


def select_profile(bundle: Dict, policy_domain: str) -> Tuple[str, Dict, str]:
    """Choose a profile from policy_published/domain.

    Prefer an exact match, then the longest covering parent domain. A named
    profile wins over default when the covered domain is the same length.
    """
    profiles: Dict[str, Dict] = bundle["profiles"]
    labels: Dict[str, str] = bundle.get("labels") or {}
    policy = _normalize_domain(policy_domain)
    if not policy:
        return "default", copy.deepcopy(profiles["default"]), "no policy_published domain; using default profile"

    best: Optional[Tuple[int, int, str]] = None
    for ident, cfg in profiles.items():
        for owned in cfg.get("TARGET_DOMAINS") or []:
            own = _normalize_domain(owned)
            if not own:
                continue
            if policy == own or policy.endswith(f".{own}"):
                rank = (len(own), 0 if ident == "default" else 1, ident)
                if best is None or rank[:2] > best[:2]:
                    best = rank

    if best is None:
        return (
            "default",
            copy.deepcopy(profiles["default"]),
            f"no profile matched policy domain {policy}; using default profile",
        )

    ident = best[2]
    label = labels.get(ident, ident)
    cfg = copy.deepcopy(profiles[ident])
    owned = ", ".join(cfg.get("TARGET_DOMAINS") or [])
    return label, cfg, f"matched policy domain {policy} to {owned}"


def load_config(env_file: Optional[str] = None) -> Dict:
    """Return the default profile (built-in defaults, env file, then process environment)."""
    return copy.deepcopy(load_config_bundle(env_file)["profiles"]["default"])


# ==============================================================================
# INPUT INGESTION & DECOMPRESSION
# ==============================================================================
def read_input_stream(source_file: Optional[str] = None) -> bytes:
    """Reads input data from a specified file or directly from stdin buffer."""
    if source_file:
        with open(source_file, "rb") as f:
            return f.read()
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    return b""


def extract_xml_payload(raw_data: bytes, max_size: int) -> Optional[bytes]:
    """
    Identifies whether raw_data is a raw email (RFC 5322), gzip, zip, or XML,
    and returns uncompressed XML bytes safely.
    """
    if not raw_data:
        return None

    # 1. Direct GZIP check (Magic bytes: 1f 8b)
    if raw_data[:2] == b"\x1f\x8b":
        with gzip.GzipFile(fileobj=io.BytesIO(raw_data)) as gz:
            return gz.read(max_size)

    # 2. Direct ZIP check (Magic bytes: 50 4b 03 04)
    if raw_data[:4] == b"PK\x03\x04":
        with zipfile.ZipFile(io.BytesIO(raw_data)) as zf:
            for name in zf.namelist():
                if name.endswith(".xml"):
                    with zf.open(name) as f:
                        return f.read(max_size)

    # 3. Direct XML check
    trimmed = raw_data.lstrip()
    if trimmed.startswith(b"<?xml") or trimmed.startswith(b"<feedback"):
        return raw_data

    # 4. RFC 5322 Email Message: search MIME parts for attachments
    try:
        msg = email.message_from_bytes(raw_data, policy=policy.default)
        for part in msg.walk():
            filename = part.get_filename() or ""
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)

            if not payload:
                continue

            # Check attachment extensions or MIME signatures
            if (filename.endswith(".gz") or content_type in ("application/gzip", "application/x-gzip")
                    or payload[:2] == b"\x1f\x8b"):
                with gzip.GzipFile(fileobj=io.BytesIO(payload)) as gz:
                    return gz.read(max_size)

            if filename.endswith(".zip") or content_type in ("application/zip", "application/x-zip-compressed"):
                with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                    for name in zf.namelist():
                        if name.endswith(".xml"):
                            with zf.open(name) as f:
                                return f.read(max_size)

            if filename.endswith(".xml") or content_type in ("text/xml", "application/xml") or payload.lstrip().startswith(b"<?xml"):
                return payload
    except Exception:
        pass

    return None


# ==============================================================================
# REPORT PARSER & FAILURE AGGREGATION
# ==============================================================================
def parse_dmarc_report(xml_bytes: bytes) -> Dict:
    """Parses DMARC XML feedback report and returns metadata and row records."""
    root = ET.fromstring(xml_bytes)

    report_metadata = {
        "org_name": root.findtext("report_metadata/org_name", default="Unknown"),
        "email": root.findtext("report_metadata/email", default="Unknown"),
        "report_id": root.findtext("report_metadata/report_id", default="Unknown"),
        "policy_domain": root.findtext("policy_published/domain", default=""),
        "policy_p": root.findtext("policy_published/p", default="none"),
        "policy_sp": root.findtext("policy_published/sp", default=""),
        "policy_pct": root.findtext("policy_published/pct", default=""),
    }

    records = []
    for rec in root.findall("record"):
        row = rec.find("row")
        source_ip = row.findtext("source_ip", default="").strip()
        count = int(row.findtext("count", default="1"))

        policy_eval = row.find("policy_evaluated")
        disposition = policy_eval.findtext("disposition", default="none").strip()
        dkim_eval = policy_eval.findtext("dkim", default="pass").strip()
        spf_eval = policy_eval.findtext("spf", default="pass").strip()

        header_from = rec.findtext("identifiers/header_from", default="").strip()

        # Auth details
        auth_dkim_selectors = []
        for dkim_entry in rec.findall("auth_results/dkim"):
            selector = dkim_entry.findtext("selector")
            result = dkim_entry.findtext("result")
            domain = dkim_entry.findtext("domain")
            if selector:
                auth_dkim_selectors.append({"selector": selector, "result": result, "domain": domain})

        records.append({
            "source_ip": source_ip,
            "count": count,
            "disposition": disposition,
            "dkim_eval": dkim_eval,
            "spf_eval": spf_eval,
            "header_from": header_from,
            "auth_dkim": auth_dkim_selectors
        })

    return {"metadata": report_metadata, "records": records}


# ==============================================================================
# IP & POLICY VERIFICATION
# ==============================================================================
def parse_ip_network(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    """Parse a CIDR or a bare host address (/32 IPv4, /128 IPv6)."""
    text = value.strip()
    if "/" not in text:
        addr = ipaddress.ip_address(text)
        text = f"{addr}/32" if addr.version == 4 else f"{addr}/128"
    return ipaddress.ip_network(text, strict=False)


def parse_authorized_networks(
    cidrs: List[str],
) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [parse_ip_network(network) for network in cidrs]


def is_ip_in_networks(ip_str: str, networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    """Validates if an IP falls within the authorized sending CIDRs."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in networks)
    except ValueError:
        return False


# ==============================================================================
# LIVE DNS DIAGNOSTICS & RECORD RECOMMENDATIONS
# ==============================================================================
def _absolute_dns_name(name: str) -> str:
    """FQDN with a trailing dot so resolv.conf search suffixes are not applied."""
    cleaned = (name or "").strip().rstrip(".")
    return f"{cleaned}." if cleaned else cleaned


def _rdata_txt(rdata) -> str:
    parts = []
    for part in rdata.strings:
        if isinstance(part, (bytes, bytearray)):
            parts.append(part.decode("utf-8", errors="replace"))
        else:
            parts.append(str(part))
    return "".join(parts)


def _spf_txt_candidate(txt: str) -> Optional[str]:
    cleaned = (txt or "").strip().strip('"').lstrip("\ufeff")
    if cleaned.lower().startswith("v=spf1"):
        return cleaned
    return None


def dns_lookup_error(name: str, rdtype: str) -> Optional[str]:
    """Return a cached transient DNS error, if the last lookup did not complete."""
    return DNS_LOOKUP_ERRORS.get((rdtype.upper(), (name or "").lower().rstrip(".")))


def query_dns(name: str, rdtype: str) -> List[str]:
    """Cached DNS lookup returning string values for TXT, A, AAAA, or MX.

    Names are queried as absolute FQDNs (search=False) so a resolv.conf
    ``search`` suffix such as ``lan`` cannot turn example.com into
    example.com.lan. Timeouts and SERVFAIL are not cached as empty answers.
    """
    qtype = rdtype.upper()
    qname = (name or "").lower().rstrip(".")
    cache_key = (qtype, qname)
    if cache_key in DNS_CACHE:
        return DNS_CACHE[cache_key]
    if cache_key in DNS_LOOKUP_ERRORS:
        return []

    last_error: Optional[BaseException] = None
    for _attempt in range(2):
        try:
            answers = dns.resolver.resolve(_absolute_dns_name(qname), qtype, search=False)
            results: List[str] = []
            for rdata in answers:
                if qtype == "TXT":
                    results.append(_rdata_txt(rdata))
                elif qtype == "MX":
                    results.append(str(rdata.exchange).rstrip("."))
                else:
                    results.append(getattr(rdata, "address", str(rdata)))
            DNS_CACHE[cache_key] = results
            return results
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            DNS_CACHE[cache_key] = []
            return []
        except _DNS_TRANSIENT as exc:
            last_error = exc
            continue
        except dns.exception.DNSException as exc:
            last_error = exc
            break

    DNS_LOOKUP_ERRORS[cache_key] = type(last_error).__name__ if last_error else "DNSException"
    return []


def query_txt_records(target_domain: str) -> List[str]:
    """Queries and caches TXT records for a given domain/subdomain."""
    return query_dns(target_domain, "TXT")


def _spf_record_for(domain: str) -> Optional[str]:
    for txt in query_txt_records(domain):
        candidate = _spf_txt_candidate(txt)
        if candidate:
            return candidate
    return None


def _parse_spf_terms(record: str) -> List[Tuple[str, str, str, str]]:
    """Return (kind, name, value, qualifier) for each SPF term after v=spf1."""
    terms: List[Tuple[str, str, str, str]] = []
    for raw in record.split():
        if raw.lower().startswith("v=spf1"):
            continue
        qualifier = "+"
        body = raw
        if body[:1] in "+-?~":
            qualifier = body[0]
            body = body[1:]
        lower = body.lower()
        if lower.startswith("redirect=") or lower.startswith("exp="):
            name, _, value = body.partition("=")
            terms.append(("mod", name.lower(), value, qualifier))
            continue
        if lower.startswith("ip6:"):
            terms.append(("mech", "ip6", body[4:], qualifier))
            continue
        if ":" in body:
            name, _, value = body.partition(":")
            terms.append(("mech", name.lower(), value, qualifier))
            continue
        terms.append(("mech", body.lower(), "", qualifier))
    return terms


def _spf_count_lookup(state: Dict) -> bool:
    state["lookups"] += 1
    if state["lookups"] > SPF_DNS_LOOKUP_LIMIT:
        state["limit_exceeded"] = True
        return False
    return True


def _spf_split_dual_cidr(value: str) -> Tuple[str, Optional[int], Optional[int]]:
    parts = (value or "").split("/")
    host = parts[0]
    prefix4 = int(parts[1]) if len(parts) > 1 and parts[1] else None
    prefix6 = int(parts[2]) if len(parts) > 2 and parts[2] else prefix4
    return host, prefix4, prefix6


def _spf_host_addresses_match(
    source: ipaddress.IPv4Address | ipaddress.IPv6Address,
    host: str,
    prefix4: Optional[int],
    prefix6: Optional[int],
) -> bool:
    if source.version == 4:
        addresses = query_dns(host, "A")
        prefix = prefix4
    else:
        addresses = query_dns(host, "AAAA")
        prefix = prefix6
    for address in addresses:
        try:
            network = (
                parse_ip_network(f"{address}/{prefix}")
                if prefix is not None
                else parse_ip_network(address)
            )
        except ValueError:
            continue
        if source in network:
            return True
    return False


def _spf_check(
    domain: str,
    source: ipaddress.IPv4Address | ipaddress.IPv6Address,
    state: Dict,
) -> str:
    domain = domain.lower().rstrip(".")
    if domain in state["stack"]:
        return "permerror"
    record = _spf_record_for(domain)
    if not record:
        if dns_lookup_error(domain, "TXT"):
            return "temperror"
        return "none"

    state["stack"].append(domain)
    try:
        redirect_to = None
        for kind, name, value, qualifier in _parse_spf_terms(record):
            if state["limit_exceeded"]:
                return "permerror"
            result = None
            matched_via = None
            if kind == "mod":
                if name == "redirect" and value:
                    redirect_to = value
                continue

            if name in ("include", "a", "mx", "ptr", "exists") and not _spf_count_lookup(state):
                return "permerror"

            if name == "all":
                result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
                matched_via = "all"
            elif name == "ip4" or name == "ip6":
                try:
                    network = parse_ip_network(value)
                except ValueError:
                    continue
                if source in network:
                    result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
                    matched_via = f"{name}:{value}"
            elif name == "include":
                if not value:
                    return "permerror"
                nested = _spf_check(value, source, state)
                if nested in ("permerror", "temperror"):
                    return nested
                if nested == "pass":
                    result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
                    matched_via = f"include:{value}"
            elif name == "a":
                host, prefix4, prefix6 = _spf_split_dual_cidr(value)
                host = host or domain
                if _spf_host_addresses_match(source, host, prefix4, prefix6):
                    result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
                    matched_via = f"a:{host}" if value else "a"
            elif name == "mx":
                host, prefix4, prefix6 = _spf_split_dual_cidr(value)
                host = host or domain
                for mx_host in query_dns(host, "MX")[:10]:
                    if _spf_host_addresses_match(source, mx_host, prefix4, prefix6):
                        result = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
                        matched_via = f"mx:{host}"
                        break
            # ptr / exists are ignored for IP-list authorization

            if result is not None:
                if result == "pass":
                    state["via"] = matched_via
                return result

        if redirect_to:
            if not _spf_count_lookup(state):
                return "permerror"
            nested = _spf_check(redirect_to, source, state)
            if nested == "pass" and not state.get("via"):
                state["via"] = f"redirect:{redirect_to}"
            return nested
        return "neutral"
    finally:
        state["stack"].pop()


def evaluate_spf_authorization(domain: str, source_ip: str) -> Dict:
    """Resolve include/a/mx/ip4/ip6 and report whether source_ip would SPF-pass."""
    state = {"lookups": 0, "limit_exceeded": False, "via": None, "stack": []}
    try:
        source = ipaddress.ip_address(source_ip)
    except ValueError:
        return {
            "authorized": False,
            "via": None,
            "lookups": 0,
            "limit_exceeded": False,
            "result": "permerror",
        }
    result = _spf_check(domain, source, state)
    return {
        "authorized": result == "pass",
        "via": state["via"],
        "lookups": state["lookups"],
        "limit_exceeded": state["limit_exceeded"],
        "result": result,
    }


def _spf_ip_mechanism(source_ip: str) -> str:
    try:
        version = ipaddress.ip_address(source_ip).version
    except ValueError:
        return f"ip4:{source_ip}"
    return f"ip6:{source_ip}" if version == 6 else f"ip4:{source_ip}"


def _spf_value_with_ip(existing: str, source_ip: str) -> str:
    mechanism = _spf_ip_mechanism(source_ip)
    if mechanism in existing:
        return existing
    for token in (" ~all", " -all", " ?all", " +all", " all"):
        if token in existing:
            return existing.replace(token, f" {mechanism}{token}", 1)
    return f"{existing} {mechanism}".strip()


def diagnose_domain_dns(
    domain: str,
    source_ip: str,
    selectors: List[str],
    config: Optional[Dict] = None,
    authorize_source_ip: bool = True,
) -> Dict:
    """Performs DNS verification for SPF, DKIM, and DMARC, generating remediation advice."""
    domain = domain.lower()
    rua = (config or {}).get("ALERT_EMAIL_TO") or f"dmarc-reports@{domain}"
    diag = {
        "domain": domain,
        "spf": {"present": False, "raw": None, "ip_authorized": False, "recommendation": None},
        "dkim": {"checked_selectors": {}, "recommendations": []},
        "dmarc": {"present": False, "raw": None, "recommendation": None}
    }

    # 1. SPF Inspection (follow include/a/mx down to IP networks)
    domain_txts = query_txt_records(domain)
    spf_lookup_error = dns_lookup_error(domain, "TXT")
    for txt in domain_txts:
        candidate = _spf_txt_candidate(txt)
        if candidate:
            diag["spf"]["present"] = True
            diag["spf"]["raw"] = candidate
            spf_eval = evaluate_spf_authorization(domain, source_ip)
            diag["spf"]["ip_authorized"] = spf_eval["authorized"]
            diag["spf"]["authorized_via"] = spf_eval["via"]
            diag["spf"]["lookup_count"] = spf_eval["lookups"]
            diag["spf"]["lookup_limit_exceeded"] = spf_eval["limit_exceeded"]
            diag["spf"]["spf_result"] = spf_eval["result"]
            break

    if spf_lookup_error and not diag["spf"]["present"]:
        diag["spf"]["error"] = spf_lookup_error
        diag["spf"]["recommendation"] = (
            f"Could not read TXT records for {domain} ({spf_lookup_error}). "
            "Not recommending SPF changes until DNS succeeds."
        )
    elif not diag["spf"]["present"]:
        if authorize_source_ip:
            diag["spf"]["recommendation"] = (
                f"Add TXT record for {domain}:\n"
                f'  Value: "v=spf1 {_spf_ip_mechanism(source_ip)} ~all"'
            )
        else:
            diag["spf"]["recommendation"] = (
                f"Add TXT record for {domain}:\n"
                f'  Value: "v=spf1 ~all"'
            )
    elif authorize_source_ip and not diag["spf"]["ip_authorized"]:
        spf_result = diag["spf"].get("spf_result")
        if spf_result in ("temperror", "permerror"):
            diag["spf"]["error"] = spf_result
            diag["spf"]["recommendation"] = (
                f"Could not fully resolve SPF for {domain} ({spf_result}). "
                "Not recommending SPF changes until DNS succeeds."
            )
        else:
            suggested = _spf_value_with_ip(diag["spf"]["raw"], source_ip)
            diag["spf"]["recommendation"] = (
                f"Authorize sender IP in existing SPF record for {domain}:\n"
                f"  Current: \"{diag['spf']['raw']}\"\n"
                f"  Suggested: \"{suggested}\""
            )

    # 2. DKIM Inspection
    valid_dkim_found = False
    dkim_lookup_errors: List[str] = []
    for selector in selectors:
        dkim_subdomain = f"{selector}._domainkey.{domain}"
        dkim_records = query_txt_records(dkim_subdomain)
        dkim_error = dns_lookup_error(dkim_subdomain, "TXT")
        if dkim_error:
            dkim_lookup_errors.append(f"{selector}: {dkim_error}")
        found = False
        for rec in dkim_records:
            if "v=DKIM1" in rec or "p=" in rec:
                diag["dkim"]["checked_selectors"][selector] = {"present": True, "raw": rec}
                valid_dkim_found = True
                found = True
                break
        if not found:
            diag["dkim"]["checked_selectors"][selector] = {"present": False, "raw": None}

    if not valid_dkim_found:
        if dkim_lookup_errors:
            diag["dkim"]["error"] = "; ".join(dkim_lookup_errors)
            diag["dkim"]["recommendations"].append(
                f"Could not read DKIM TXT for {domain} ({diag['dkim']['error']}). "
                "Not recommending a new DKIM key until DNS succeeds."
            )
        else:
            primary_sel = selectors[0] if selectors else "default"
            diag["dkim"]["recommendations"].append(
                f"No active DKIM key found under probed selector(s): {', '.join(selectors)}.\n"
                f"  1. Generate a 2048-bit key on your mail server: opendkim-genkey -b 2048 -s {primary_sel} -d {domain}\n"
                f"  2. Publish the public key TXT record at {primary_sel}._domainkey.{domain}:\n"
                f'     Value: "v=DKIM1; k=rsa; p=<PUBLIC_KEY>"'
            )

    # 3. DMARC Inspection
    dmarc_subdomain = f"_dmarc.{domain}"
    dmarc_records = query_txt_records(dmarc_subdomain)
    dmarc_lookup_error = dns_lookup_error(dmarc_subdomain, "TXT")
    for txt in dmarc_records:
        if txt.startswith("v=DMARC1"):
            diag["dmarc"]["present"] = True
            diag["dmarc"]["raw"] = txt
            break

    if dmarc_lookup_error and not diag["dmarc"]["present"]:
        diag["dmarc"]["error"] = dmarc_lookup_error
        diag["dmarc"]["recommendation"] = (
            f"Could not read TXT records for _dmarc.{domain} ({dmarc_lookup_error}). "
            "Not recommending DMARC changes until DNS succeeds."
        )
    elif not diag["dmarc"]["present"]:
        diag["dmarc"]["recommendation"] = (
            f"Add TXT record for _dmarc.{domain}:\n"
            f'  Value: "v=DMARC1; p=none; rua=mailto:{rua}; sp=none;"'
        )

    return diag


# ==============================================================================
# ALERT FORMATTER & DISPATCHER
# ==============================================================================
def _dns_finding_lines(diag: Dict) -> List[str]:
    """Same SPF, DKIM, and DMARC finding lines used by mail alerts and the viewer."""
    lines = []
    if diag["spf"]["recommendation"]:
        lines.append(f"  [!] SPF Deficiency:\n      {diag['spf']['recommendation']}")
    else:
        spf_ok = f"  [✓] SPF Record OK ({diag['spf']['raw']})"
        via = diag["spf"].get("authorized_via")
        if via:
            spf_ok += f"; sender authorized via {via}"
        lines.append(spf_ok)
    if diag["spf"].get("lookup_limit_exceeded"):
        lines.append(
            "  [!] SPF DNS lookup limit (10) exceeded while resolving include/a/mx."
        )

    if diag["dkim"]["recommendations"]:
        for recommendation in diag["dkim"]["recommendations"]:
            lines.append(f"  [!] DKIM Deficiency:\n      {recommendation}")
    else:
        lines.append("  [✓] DKIM Active for verified selectors.")

    if diag["dmarc"]["recommendation"]:
        lines.append(f"  [!] DMARC Deficiency:\n      {diag['dmarc']['recommendation']}")
    else:
        lines.append(f"  [✓] DMARC Record OK ({diag['dmarc']['raw']})")
    return lines


def published_policy_label(meta: Dict) -> str:
    """Compact policy_published string, e.g. p=none or p=reject; sp=reject; pct=50."""
    policy_p = (meta.get("policy_p") or "none").strip() or "none"
    parts = [f"p={policy_p}"]
    policy_sp = (meta.get("policy_sp") or "").strip()
    if policy_sp:
        parts.append(f"sp={policy_sp}")
    policy_pct = (meta.get("policy_pct") or "").strip()
    if policy_pct and policy_pct != "100":
        parts.append(f"pct={policy_pct}")
    return "; ".join(parts)


def dmarc_policy_is_strict(meta: Dict) -> bool:
    """True when published policy already quarantines or rejects (full pct)."""
    policy_p = (meta.get("policy_p") or "none").strip().lower()
    if policy_p not in ("quarantine", "reject"):
        return False
    policy_pct = (meta.get("policy_pct") or "100").strip() or "100"
    try:
        return int(policy_pct) >= 100
    except ValueError:
        return True


def _record_has_delivery_issue(record: Dict) -> bool:
    return (
        record["disposition"] in ("quarantine", "reject")
        or record["dkim_eval"] == "fail"
        or record["spf_eval"] == "fail"
    )


def _selectors_for_record(record: Dict, config: Dict) -> List[str]:
    selectors = [entry["selector"] for entry in record["auth_dkim"] if entry.get("selector")]
    for fallback in config["FALLBACK_DKIM_SELECTORS"]:
        if fallback not in selectors:
            selectors.append(fallback)
    return selectors


def build_report_body(report_meta: Dict, issues: List[Dict]) -> str:
    """Formats findings and suggestions into a structured text report."""
    lines = [
        "==================================================================",
        " DMARC DELIVERY ISSUE & DNS DIAGNOSTIC ALERT",
        "==================================================================",
        f"Reporter Org : {report_meta.get('org_name')}",
        f"Reporter Mail: {report_meta.get('email')}",
        f"Report ID    : {report_meta.get('report_id')}",
        f"Policy Domain: {report_meta.get('policy_domain')} (Published Policy: p={report_meta.get('policy_p')})",
        f"Failed Events: {len(issues)}",
        "==================================================================\n"
    ]

    for idx, item in enumerate(issues, 1):
        rec = item["record"]
        diag = item["diagnostic"]
        lines.append(f"--- [Failure Issue #{idx}] ------------------------------------------")
        lines.append(f"Domain Under Evaluation : {rec['header_from']}")
        lines.append(f"Originating Server IP   : {rec['source_ip']} (Authorized Infrastructure: YES)")
        lines.append(f"Impacted Messages Count : {rec['count']}")
        lines.append(f"Disposition Applied     : {rec['disposition'].upper()}")
        lines.append(f"Evaluated SPF / DKIM    : SPF={rec['spf_eval'].upper()} | DKIM={rec['dkim_eval'].upper()}")

        if rec["auth_dkim"]:
            for d in rec["auth_dkim"]:
                lines.append(f"  Auth Result DKIM      : selector={d.get('selector')} result={d.get('result')}")

        lines.append("\nDNS Diagnostics & Actionable Fixes:")
        lines.extend(_dns_finding_lines(diag))
        lines.append("\n")

    lines.append("------------------------------------------------------------------")
    lines.append("Automated Notification Generated by Postfix DMARC Analyzer")
    return "\n".join(lines)


def _dmarc_is_enforcing(raw: Optional[str]) -> bool:
    text = (raw or "").lower()
    return "p=quarantine" in text or "p=reject" in text


def _dmarc_raise_to_quarantine(raw: Optional[str], rua: str) -> str:
    if raw:
        updated, count = re.subn(r"p\s*=\s*none", "p=quarantine", raw, count=1, flags=re.I)
        if count:
            return updated
        return raw
    return f"v=DMARC1; p=quarantine; rua=mailto:{rua}; sp=none;"


def _recommendation_items(
    diag: Dict,
    source_ip: str,
    authorized: bool,
    config: Dict,
    *,
    raise_weak_dmarc: bool = False,
) -> List[Dict]:
    """SPF/DKIM/DMARC items for a record. is_change is false for keep-only rows."""
    domain = diag["domain"]
    rua = config.get("ALERT_EMAIL_TO") or f"dmarc-reports@{domain}"
    items: List[Dict] = []

    if diag["spf"].get("error") and (
        not diag["spf"]["present"] or diag["spf"].get("spf_result") in ("temperror", "permerror")
    ):
        spf_value = diag["spf"].get("raw") or "(unavailable)"
        spf_action = f"check (DNS lookup failed: {diag['spf']['error']})"
    elif not diag["spf"]["present"]:
        spf_value = f"v=spf1 {_spf_ip_mechanism(source_ip)} ~all" if authorized else "v=spf1 ~all"
        spf_action = "add" if authorized else "add (do not include this external source IP)"
    elif authorized and not diag["spf"]["ip_authorized"]:
        spf_value = _spf_value_with_ip(diag["spf"]["raw"], source_ip)
        spf_action = f"update (authorize {source_ip})"
    else:
        spf_value = diag["spf"]["raw"]
        spf_action = "keep"
        if not authorized and not diag["spf"]["ip_authorized"]:
            spf_action = "keep (external source; do not add this IP)"
    items.append({
        "kind": "SPF",
        "host": domain,
        "value": spf_value,
        "action": spf_action,
        "is_change": not spf_action.startswith("keep"),
    })

    dkim_selector = None
    dkim_value = None
    for selector, info in diag["dkim"]["checked_selectors"].items():
        if info.get("present") and info.get("raw"):
            dkim_selector = selector
            dkim_value = info["raw"]
            break
    if dkim_selector is None:
        dkim_selector = next(iter(diag["dkim"]["checked_selectors"]), None) or (
            config.get("FALLBACK_DKIM_SELECTORS") or ["default"]
        )[0]
        if diag["dkim"].get("error"):
            dkim_value = "(unavailable)"
            dkim_action = f"check (DNS lookup failed: {diag['dkim']['error']})"
        else:
            dkim_value = "v=DKIM1; k=rsa; p=<PUBLIC_KEY>"
            dkim_action = f"add (publish key for selector {dkim_selector})"
    else:
        dkim_action = "keep"
    items.append({
        "kind": "DKIM",
        "host": f"{dkim_selector}._domainkey.{domain}",
        "value": dkim_value,
        "action": dkim_action,
        "is_change": not dkim_action.startswith("keep"),
    })

    if diag["dmarc"]["present"] and diag["dmarc"]["raw"]:
        if raise_weak_dmarc and not _dmarc_is_enforcing(diag["dmarc"]["raw"]):
            dmarc_value = _dmarc_raise_to_quarantine(diag["dmarc"]["raw"], rua)
            dmarc_action = "update (raise policy; spam is allowed under p=none)"
        else:
            dmarc_value = diag["dmarc"]["raw"]
            dmarc_action = "keep"
    elif diag["dmarc"].get("error"):
        dmarc_value = "(unavailable)"
        dmarc_action = f"check (DNS lookup failed: {diag['dmarc']['error']})"
    else:
        dmarc_value = f"v=DMARC1; p=none; rua=mailto:{rua}; sp=none;"
        dmarc_action = "add"
        if raise_weak_dmarc:
            dmarc_value = _dmarc_raise_to_quarantine(None, rua)
            dmarc_action = "add (p=quarantine; spam is allowed under the current policy)"
    items.append({
        "kind": "DMARC",
        "host": f"_dmarc.{domain}",
        "value": dmarc_value,
        "action": dmarc_action,
        "is_change": not dmarc_action.startswith("keep"),
    })
    return items


def _format_recommendation_items(items: List[Dict], indent: str = "  ") -> List[str]:
    lines = []
    width = max(len(item["kind"]) for item in items)
    for item in items:
        kind = item["kind"].ljust(width)
        lines.append(f"{indent}{kind} Host : {item['host']}  (TXT)")
        lines.append(f'{indent}{" " * width} Value: "{item["value"]}"')
        lines.append(f'{indent}{" " * width} Action: {item["action"]}')
    return lines


def _change_summary_lines(change_items: List[Dict], record_count: str) -> List[str]:
    """Deduped add/update actions only; keep-only records are omitted."""
    lines = [
        "==================================================================",
        " SUMMARY — CHANGES TO APPLY",
        "==================================================================",
        f"Record Count : {record_count}",
    ]
    unique: List[Dict] = []
    seen = set()
    for item in change_items:
        key = (item["kind"], item["host"], item["value"], item["action"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    if not unique:
        lines.append("No changes recommended for the current setup.")
        lines.append("")
        return lines
    lines.extend(_format_recommendation_items(unique, indent=""))
    lines.append("")
    return lines


def format_viewer_report(
    report: Dict,
    config: Dict,
    env_path: Optional[str] = None,
    profile_name: Optional[str] = None,
    profile_match: Optional[str] = None,
) -> str:
    """Plain-text analysis plus SPF/DKIM/DMARC record recommendations."""
    meta = report["metadata"]
    records = report.get("records") or []
    server_networks = parse_authorized_networks(config["AUTHORIZED_SERVER_NETS"])
    authorized_only = bool(config.get("REPORT_AUTHORIZED_ONLY", True))
    policy_strict = dmarc_policy_is_strict(meta)
    policy_label = published_policy_label(meta)

    shown: List[Tuple[Dict, bool]] = []
    omitted_records = 0
    omitted_messages = 0
    included_weak_spam = 0
    for rec in records:
        authorized = is_ip_in_networks(rec["source_ip"], server_networks)
        if authorized_only and not authorized:
            if policy_strict:
                omitted_records += 1
                omitted_messages += int(rec.get("count") or 0)
                continue
        shown.append((rec, authorized))

    change_items: List[Dict] = []
    record_blocks: List[str] = []
    skipped_no_change = 0
    listed = 0

    for rec, authorized in shown:
        domain = rec["header_from"].lower()
        raise_weak_dmarc = bool(not authorized and authorized_only and not policy_strict)
        items: List[Dict] = []
        diagnostics = None
        if domain:
            diagnostics = diagnose_domain_dns(
                domain,
                rec["source_ip"],
                _selectors_for_record(rec, config),
                config=config,
                authorize_source_ip=authorized,
            )
            items = _recommendation_items(
                diagnostics,
                rec["source_ip"],
                authorized,
                config,
                raise_weak_dmarc=raise_weak_dmarc,
            )
        changes = [item for item in items if item["is_change"]]
        if not changes:
            skipped_no_change += 1
            continue

        listed += 1
        if not authorized:
            included_weak_spam += 1
        block = [
            f"--- [Record #{listed}] ------------------------------------------------",
            f"Domain Under Evaluation : {rec['header_from']}",
            (
                f"Originating Server IP   : {rec['source_ip']} "
                f"(authorized={'yes' if authorized else 'no'})"
            ),
            f"Impacted Messages Count : {rec['count']}",
            f"Disposition Applied     : {rec['disposition'].upper()}",
            (
                f"Evaluated SPF / DKIM    : SPF={rec['spf_eval'].upper()} "
                f"| DKIM={rec['dkim_eval'].upper()}"
            ),
        ]

        if rec["auth_dkim"]:
            for d in rec["auth_dkim"]:
                block.append(
                    f"  Auth Result DKIM      : selector={d.get('selector')} result={d.get('result')}"
                )

        if not authorized:
            if raise_weak_dmarc:
                block.append(
                    f"This spam is allowed due to the weak DMARC policy - {policy_label}"
                )
            block.append("External source: do not publish this IP in your SPF record.")
        elif not _record_has_delivery_issue(rec):
            block.append("This record passed SPF, DKIM, and disposition checks.")

        block.append("")
        block.append("DNS Diagnostics:")
        block.extend(_dns_finding_lines(diagnostics))
        block.append("")
        block.append("Recommended DNS records:")
        block.extend(_format_recommendation_items(items))
        block.append("")
        change_items.extend(changes)
        record_blocks.extend(block)

    parts = [f"{listed} listed ({len(records)} in file"]
    if omitted_records:
        parts.append(f"{omitted_records} omitted, unauthorized IP under {policy_label}")
    if skipped_no_change:
        parts.append(f"{skipped_no_change} omitted, no recommended changes")
    record_count = "; ".join(parts) + ")"

    lines = [
        "==================================================================",
        " DMARC REPORT ANALYSIS",
        "==================================================================",
        f"Reporter Org : {meta.get('org_name')}",
        f"Reporter Mail: {meta.get('email')}",
        f"Report ID    : {meta.get('report_id')}",
        f"Policy Domain: {meta.get('policy_domain')} (Published Policy: p={meta.get('policy_p')})",
        f"Config file  : {env_path or 'built-in defaults'}",
        f"Profile      : {profile_name or 'default'}",
        f"Profile match: {profile_match or 'default profile'}",
        f"Target domains: {', '.join(config.get('TARGET_DOMAINS') or []) or '(any)'}",
        f"Authorized nets: {', '.join(config.get('AUTHORIZED_SERVER_NETS') or [])}",
        (
            f"Authorized only: {'yes' if authorized_only else 'no'}"
            + (
                f" (unauthorized spam listed; DMARC is not strict: {policy_label})"
                if authorized_only and included_weak_spam
                else ""
            )
        ),
        "==================================================================\n",
    ]

    if authorized_only and omitted_records and not shown:
        lines.append(
            "No records from authorized senders.\n"
            f"Omitted {omitted_records} records ({omitted_messages} messages) "
            "from IPs outside AUTHORIZED_SERVER_NETS.\n"
            f"Published DMARC is already {policy_label}, so that spam is not listed. "
            "Set REPORT_AUTHORIZED_ONLY=false to include those sources anyway.\n"
        )

    lines.extend(_change_summary_lines(change_items, record_count))
    lines.extend(record_blocks)
    return "\n".join(lines)


def analyze_viewer_path(
    path: str,
    config: Optional[Dict] = None,
    env_path: Optional[str] = None,
) -> str:
    """Load a report file and return viewer text, including short error messages."""
    env_file = env_path if env_path and os.path.isfile(env_path) else None
    bundle = load_config_bundle(env_file)
    if config is None:
        config = copy.deepcopy(bundle["profiles"]["default"])
    try:
        with open(path, "rb") as handle:
            raw_data = handle.read()
    except OSError as exc:
        return f"Could not read file: {exc}"

    try:
        xml_data = extract_xml_payload(raw_data, config["MAX_PAYLOAD_SIZE"])
    except Exception:
        return "This file does not contain a DMARC report."

    if not xml_data:
        return "This file does not contain a DMARC report."

    try:
        report = parse_dmarc_report(xml_data)
    except ET.ParseError:
        return "Could not parse DMARC XML."

    profile_name, config, profile_match = select_profile(bundle, report["metadata"].get("policy_domain", ""))
    return format_viewer_report(
        report,
        config,
        env_path=env_path,
        profile_name=profile_name,
        profile_match=profile_match,
    )


def send_alert_email(subject: str, body: str, config: Dict) -> None:
    """Dispatches the alert message using local sendmail pipe or direct SMTP."""
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["ALERT_EMAIL_FROM"]
    msg["To"] = config["ALERT_EMAIL_TO"]
    msg.set_content(body)

    if config["DISPATCH_METHOD"] == "sendmail":
        try:
            proc = subprocess.Popen(
                ["/usr/sbin/sendmail", "-t", "-oi"],
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate(msg.as_bytes())
            if proc.returncode != 0:
                print(f"Warning: sendmail exited with code {proc.returncode}: {stderr.decode()}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to dispatch via sendmail: {e}", file=sys.stderr)
    elif config["DISPATCH_METHOD"] == "smtp":
        try:
            with smtplib.SMTP(config["SMTP_HOST"], config["SMTP_PORT"], timeout=10) as server:
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to dispatch via SMTP: {e}", file=sys.stderr)


# ==============================================================================
# MAIN PROCESSING ROUTINE
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Analyze DMARC reports and alert on delivery issues.")
    parser.add_argument("--file", help="Path to report file (eml, xml, gz, zip). Default reads stdin.")
    parser.add_argument("--to", help="Override alert recipient email address.")
    parser.add_argument("--from-addr", help="Override alert sender email address.")
    parser.add_argument("--dry-run", action="store_true", help="Print report to stdout without sending email.")
    args = parser.parse_args()

    bundle = load_config_bundle()
    default_config = bundle["profiles"]["default"]

    raw_stream = read_input_stream(args.file)
    if not raw_stream:
        # Exit cleanly if stdin is empty (prevents mail loops)
        sys.exit(0)

    xml_data = extract_xml_payload(raw_stream, default_config["MAX_PAYLOAD_SIZE"])
    if not xml_data:
        # Piped data was unrelated email, spam, or non-DMARC payload
        sys.exit(0)

    try:
        report = parse_dmarc_report(xml_data)
    except ET.ParseError:
        # Unparseable XML
        sys.exit(0)

    _profile_name, config, _profile_match = select_profile(
        bundle, report["metadata"].get("policy_domain", "")
    )
    if args.to:
        config["ALERT_EMAIL_TO"] = args.to
    if args.from_addr:
        config["ALERT_EMAIL_FROM"] = args.from_addr

    # Compile network subnets
    server_networks = parse_authorized_networks(config["AUTHORIZED_SERVER_NETS"])
    target_domains = config.get("TARGET_DOMAINS") or []

    detected_issues = []

    for record in report["records"]:
        source_ip = record["source_ip"]
        domain = record["header_from"].lower()

        # Only evaluate domains this profile owns (exact or subdomain)
        if target_domains and not domain_covered(domain, target_domains):
            continue

        # Evaluate if the failure occurred on authorized server IPs
        if not is_ip_in_networks(source_ip, server_networks):
            continue

        if _record_has_delivery_issue(record):
            candidate_selectors = _selectors_for_record(record, config)
            diagnostics = diagnose_domain_dns(domain, source_ip, candidate_selectors, config=config)

            # Check if any record is missing or flawed
            spf_issue = (not diagnostics["spf"]["present"]) or (not diagnostics["spf"]["ip_authorized"])
            dkim_issue = len(diagnostics["dkim"]["recommendations"]) > 0
            dmarc_issue = not diagnostics["dmarc"]["present"]

            if spf_issue or dkim_issue or dmarc_issue:
                detected_issues.append({
                    "record": record,
                    "diagnostic": diagnostics
                })

    if detected_issues:
        alert_body = build_report_body(report["metadata"], detected_issues)
        alert_subject = f"[DMARC Alert] Delivery failures detected for {report['metadata'].get('policy_domain')}"

        if args.dry_run:
            print(f"Subject: {alert_subject}\n")
            print(alert_body)
        else:
            send_alert_email(alert_subject, alert_body, config)


if __name__ == "__main__":
    main()
