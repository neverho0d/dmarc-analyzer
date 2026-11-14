# Architecture

Ingestion stages, DNS diagnostics, and Postfix pipe design. Build, install, and usage are in the [README](../README.md).

## 1. Ingestion Architecture & Mail Pipe Flow

```text
┌────────────────────────────────────────────────────────┐
│ Incoming Email or Direct File piped via STDIN          │
│ (Postfix pipe transport, /etc/aliases, or manual pipe) │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 1. Stream Format Detection                             │
│    - Check initial magic bytes / text headers          │
│    - Branch: Raw Email (RFC 5322) vs Raw File          │
│      (raw .xml, .gz, or .zip)                          │
└──────────────┬───────────────────────────┬─────────────┘
               │ (Raw Email)               │ (Direct Report File)
               ▼                           │
┌─────────────────────────────────┐        │
│ 2. DMARC Verification & Filter  │        │
│    - Validate Content-Type /    │        │
│      Subject keywords           │        │
│    - Extract & sanitize payload │        │
│    - Decompress attachment      │        │
└──────────────┬──────────────────┘        │
               │                           │
               ▼                           ▼
┌────────────────────────────────────────────────────────┐
│ 3. DMARC XML Parse & Failure Aggregation               │
│    - Extract: source_ip, count, policy_evaluated       │
│    - Check: disposition != 'none' OR auth/align fail   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 4. Authoritative Server CIDR Evaluation                │
│    - Match source_ip against SERVER_NETWORKS via       │
│      ipaddress.ip_network                              │
│    - Discard external relays / spoofers from DNS check │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│ 5. Cached Live DNS Diagnostics & Recommendation Engine │
│    - Cached lookups for SPF, DKIM (selector), DMARC    │
│    - Check 10-lookup SPF limit                         │
│    - Generate specific remediation records & dispatch  │
└────────────────────────────────────────────────────────┘
```

## 2. Component Breakdown & Execution Stages

## Stage 1: Dual-Mode stdin Detection

The script reads bytes from `sys.stdin.buffer` and determines whether it was piped an RFC 5322 email message or a direct report file:

- **Direct File Check:**
  - **Gzip:** Magic bytes `1f 8b`
  - **Zip:** Magic bytes `50 4b 03 04`
  - **Raw XML:** ASCII/UTF-8 prefix `<?xml` or `<feedback`
- **Raw Email Processing:** Handed off to Python’s standard email library (`email.message_from_bytes`).

## Stage 2: Email Filtering & Anti-Spam / Anti-Bomb Screening

Because the MTA script accepts public email traffic for the dedicated rua report mailbox, it must cleanly filter spam, invalid attachments, and mailbombs:

- **Header & Type Validation:**
  - Check `Content-Type`: Accept `multipart/mixed`, `multipart/report`, `application/zip`, `application/gzip`, or `application/octet-stream`.
  - Validate Subject: Legitimate reports (Google, Yahoo, Microsoft) standardly format subjects as: `Report Domain: <domain> Submitter: <reporter> Report-ID: <id>`.
- **Attachment Extraction & Bomb Protection:**
  - Traverse MIME parts to locate `.xml.gz`, `.zip`, or `.xml` attachments.
  - **Size Bounds:** Set an uncompressed memory limit (e.g., 20 MB) to prevent zip-bomb / gzip-decompression attacks from exhausting server memory.
  - Discard messages that do not contain valid DMARC archive payloads with zero exit code (to prevent mail bounces from cycling back into Postfix).

## Stage 3: XML Ingestion & Issue Detection

- Parse XML safely using `defusedxml.ElementTree` or `xml.etree.ElementTree`.
- **Extract:**
  - `<policy_published><domain>` and `<header_from>`.
  - `<source_ip>` and `<count>`.
  - `<policy_evaluated>`: `<disposition>`, `<dkim>`, and `<spf>`.
  - `<auth_results>`: Detailed underlying results and DKIM `<selector>`.
- **Detection Trigger:** Flag an issue if:
  - `disposition in ('quarantine', 'reject')`
  - `policy_evaluated.dkim == 'fail'` or `policy_evaluated.spf == 'fail'`
  - SPF/DKIM authentication passed, but DMARC alignment failed (domain in `header_from` does not match the authenticated identity).

## Stage 4: Subnet Matching via `ipaddress`

- Configure mail servers as CIDRs or individual IPs (e.g., `["95.217.200.86/32", "120.138.18.240/28"]`).
- Parse configurations into a list of `ipaddress.ip_network` objects.
- Convert report `<source_ip>` to `ipaddress.ip_address`.
- **Rule:** Proceed to DNS diagnostics only if the sending IP falls within one of the authoritative networks. If the IP is external, log or alert as unaligned relay/spoof attempt without recommending DNS updates for your own infrastructure.

## Stage 5: Live DNS Diagnostics & Caching

- **Caching:** Use an in-memory dictionary keyed by `(query_type, domain)` to avoid repetitive DNS round-trips for multi-record reports.
- **Checks via dnspython:**
  - **SPF** (TXT on target domain):
    - Verify presence of `v=spf1`.
    - Verify whether the sending IP or its parent CIDR is authorized (directly or via `ip4:`, `a`, or `include:`).
    - Count DNS terms to warn if the 10-lookup limit is exceeded.
  - **DKIM** (TXT on `<selector>._domainkey.<domain>`):
    - Extract selector dynamically from `<auth_results><dkim><selector>` (falling back to a configurable list if blank).
    - Verify `v=DKIM1;` and public key tag `p=`.
  - **DMARC** (TXT on `_dmarc.<domain>`):
    - Verify `v=DMARC1;` and report URI `rua=`.

## Stage 6: Actionable Record Remediation Engine

- **Missing/Incomplete SPF:**
  - Generate the record string: `v=spf1 ip4:<source_ip> ~all` (or provide the updated string appending `ip4:<source_ip>` into the existing record).
- **Missing DKIM:**
  - Output template for selector `<selector>`:

    ```text
    Host: <selector>._domainkey.<domain>
    Value: "v=DKIM1; k=rsa; p=<PUBLIC_KEY>"
    ```

  - Note key-generation instructions for OpenDKIM (`opendkim-genkey`).
- **Missing DMARC:**
  - Provide safe baseline policy:

    ```text
    Host: _dmarc.<domain>
    Value: "v=DMARC1; p=none; rua=mailto:<alert_email>; sp=none;"
    ```

## 3. Postfix Pipe Integration Specification

The analyzer runs in a disposable container so Python and `dnspython` are not installed on the host, and the image does not contain an MTA. Alerts go out by SMTP to the host MTA at `127.0.0.1:25`. `--network host` reaches that listener and the host resolver without changing Postfix's `mynetworks`.

1. Build the image from this directory:

   ```bash
   docker build -t dmarc-analyzer .
   ```

2. Copy `config/analyzer.env.example` to `/etc/dmarc/analyzer.env` and set the site domains, authorized networks, and alert addresses. The container reads those names from the environment.

3. Install `contrib/dmarc-analyzer-pipe` as `/usr/local/bin/dmarc-analyzer-pipe` (`sudo make install-pipe`). That wrapper is the only host-side addition. It runs `docker run --rm` as a non-root, read-only process and removes the container when the report finishes. The pipe user must be allowed to talk to the Docker socket.

4. Define in `/etc/postfix/master.cf`:

   ```text
   dmarc-pipe  unix  -       n       n       -       -       pipe
     flags=Rq user=dmarc-runner argv=/usr/local/bin/dmarc-analyzer-pipe
   ```

5. Route in `/etc/postfix/aliases` or `/etc/postfix/virtual`:

   ```text
   dmarc-reports@yourdomain.com    dmarc-pipe:
   ```

## 4. CLI Interfaces

Run the image instead of a host Python install:

```bash
# Direct email piped from the shell
cat incoming_email.eml | docker run --rm -i --network host dmarc-analyzer

# Direct XML / GZ / ZIP report piped from the shell
cat report.xml.gz | docker run --rm -i --network host dmarc-analyzer

# Direct file argument mode (mount the report read-only)
docker run --rm -i --network host \
  -v /var/log/dmarc:/reports:ro \
  dmarc-analyzer --file /reports/google.com!example.com!1781222400!1781308799.xml.gz

# Print the alert instead of sending it
cat report.xml.gz | docker run --rm -i --network host dmarc-analyzer --dry-run
```

With Compose, the same entrypoint is:

```bash
cat report.xml.gz | docker compose run --rm -T analyzer --dry-run
```
