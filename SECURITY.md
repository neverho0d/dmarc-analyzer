# Security

- Treat `analyzer.env` as a secret. It lists your mail domains, sending IPs, and alert addresses. It is gitignored; never commit a filled-in copy.
- The mail pipe accepts public rua traffic. Non-DMARC payloads, oversized archives, and unparseable XML exit 0 so Postfix does not bounce and loop.
- Uncompressed report size is capped (`MAX_PAYLOAD_SIZE`, default 20 MiB).
- The pipe container runs read-only, drops capabilities, and uses `--security-opt no-new-privileges`.
- Unauthorized source IPs are not recommended for your SPF record.

To report a vulnerability, open a private GitHub security advisory on this repository, or email the maintainer listed in the git history. Do not file a public issue for undisclosed vulnerabilities.
