# DMARC Analyzer

Ingest a DMARC aggregate report, check live SPF / DKIM / DMARC DNS, and tell you which TXT records to add or update. Authorized senders are diagnosed for missing or incomplete authentication. Unauthorized sources (spam, spoofing) are not written into your SPF record; tightening DMARC is what stops that mail.

Two ways to use it:

| Product | What it is |
| --- | --- |
| **Desktop viewer** | Standalone Linux executable. Open an `.xml`, `.xml.gz`, `.zip`, or `.eml` and read a plain-text analysis. |
| **Mail pipe** | Docker image fed by Postfix (or `cat … \| docker run`). Alerts go out over SMTP when authorized mail is failing SPF/DKIM/DMARC. |

Python and `dnspython` stay inside containers. The host only needs Docker for the pipe, and the viewer binary for the desktop app.

## Features

- Accepts RFC 5322 mail, raw XML, gzip, or zip, including common rua attachments
- Size-limited decompression so a zip bomb cannot fill memory
- Profiles selected from `<policy_published><domain>` (exact match, then longest parent)
- Authorized networks as CIDR or bare IPv4/IPv6 (`/32` and `/128` if you omit the prefix)
- Recursive SPF evaluation (`include:`, `a`, `mx`, `ip4:`, `ip6:`, `redirect=`) so an IP already covered by an include is not recommended again
- Viewer summary lists only DNS **add** / **update** actions; keep-only records are omitted
- `REPORT_AUTHORIZED_ONLY` hides unauthorized rows when published DMARC is already `p=quarantine` or `p=reject` at `pct=100`

Design notes for the ingestion stages live in [docs/architecture.md](docs/architecture.md).

## Requirements

- **Viewer build:** Docker (Fedora-based image with Tkinter and PyInstaller)
- **Pipe:** Docker, plus a local MTA listening on `127.0.0.1:25` if you dispatch alerts
- **Optional host Python:** 3.10+ and `pip install -r requirements.txt` for `--dry-run` without Docker

## Quick start (desktop viewer)

```bash
git clone https://github.com/<you>/dmarc-analyzer.git
cd dmarc-analyzer
make viewer
```

That writes `dist/dmarc-viewer` and, on the first build only, copies `config/analyzer.env.example` to `dist/analyzer.env`. Edit that file with your domains and sending IPs, then:

```bash
./dist/dmarc-viewer /path/to/google.com!example.com!….xml.gz
```

Or run the window and use **Open**. **Config** opens `dist/analyzer.env` in your default editor.

To register an “Open With” handler for XML / gzip / zip / `.eml`:

```bash
make desktop
```

`make uninstall-desktop` removes it.

## Configuration

Copy the example and edit it. Do not commit a filled-in `analyzer.env`.

```bash
cp config/analyzer.env.example dist/analyzer.env   # viewer (done by make viewer)
# or
sudo mkdir -p /etc/dmarc
sudo cp config/analyzer.env.example /etc/dmarc/analyzer.env   # mail pipe
```

| Variable | Purpose |
| --- | --- |
| `TARGET_DOMAINS` | Domains this profile owns (comma-separated) |
| `AUTHORIZED_SERVER_NETS` | Your outbound IPs or CIDRs. Bare IPv4 is `/32`, bare IPv6 is `/128`. |
| `REPORT_AUTHORIZED_ONLY` | `true`: list authorized senders; list unauthorized rows only when DMARC is still weak |
| `FALLBACK_DKIM_SELECTORS` | Selectors to probe when a report omits them |
| `ALERT_EMAIL_TO` / `ALERT_EMAIL_FROM` | Pipe alerts, and `rua=` in a recommended DMARC record |
| `DISPATCH_METHOD` | `smtp` (container) or `sendmail` (host MTA) |
| `SMTP_HOST` / `SMTP_PORT` | Used when `DISPATCH_METHOD=smtp` |

Unprefixed keys are the **default** profile. Extra domains use `PROFILE_<name>_KEY`:

```bash
PROFILE_4JOB_TARGET_DOMAINS=4job.co
PROFILE_4JOB_AUTHORIZED_SERVER_NETS=120.138.18.240/28
PROFILE_4JOB_ALERT_EMAIL_TO=postmaster@4job.co
```

The viewer and the pipe pick a profile from `<policy_published><domain>` in the report. `header_from` is not used for that choice.

Override the env file path with `DMARC_ANALYZER_ENV=/path/to/analyzer.env`.

## Build

```bash
make help
make viewer          # dist/dmarc-viewer
make image           # Docker image dmarc-analyzer
make all             # both
make check           # byte-compile sources
```

The viewer is built in a Fedora container so the host does not need Tkinter or PyInstaller. `make clean` removes the binary and build stamps and **leaves** `dist/analyzer.env` in place.

## Mail pipe (Postfix)

1. Build the image and install the wrapper (needs write access to `/usr/local/bin` and `/etc/dmarc`):

   ```bash
   make image
   sudo make install-pipe
   sudo edit /etc/dmarc/analyzer.env
   ```

   The wrapper is `contrib/dmarc-analyzer-pipe`. It runs `docker run --rm` as a read-only, non-root container with `--network host` so SMTP to `127.0.0.1:25` and DNS on the host resolver work. The pipe user must be allowed to talk to the Docker socket. Override the image or env path with `DMARC_ANALYZER_IMAGE` and `DMARC_ANALYZER_ENV`.

2. In `/etc/postfix/master.cf`:

   ```text
   dmarc-pipe  unix  -       n       n       -       -       pipe
     flags=Rq user=dmarc-runner argv=/usr/local/bin/dmarc-analyzer-pipe
   ```

3. Route rua mail in `/etc/postfix/aliases` or `/etc/postfix/virtual`:

   ```text
   dmarc-reports@yourdomain.com    dmarc-pipe:
   ```

4. `postalias` / `postfix reload` as usual.

Manual runs without Postfix:

```bash
# Print the alert instead of sending it
cat report.xml.gz | docker run --rm -i --network host dmarc-analyzer --dry-run

# Email message from the shell
cat incoming_email.eml | docker run --rm -i --network host --env-file dist/analyzer.env dmarc-analyzer --dry-run

# Mount a report file
docker run --rm -i --network host \
  -v /var/log/dmarc:/reports:ro \
  dmarc-analyzer --file /reports/google.com!example.com!1781222400!1781308799.xml.gz --dry-run
```

Compose uses the same image:

```bash
cat report.xml.gz | docker compose run --rm -T analyzer --dry-run
```

Host Python (no Docker) for a one-off dry run:

```bash
pip install -r requirements.txt
PYTHONPATH=src python3 src/dmarc_analyzer.py --file report.xml.gz --dry-run
```

## Viewer report

The header identifies the reporter, policy domain, config file, and selected profile. The summary then shows how many records were listed or omitted, followed only by DNS changes that need applying. Per-record detail is included only when there is something to change.

## Development

```text
.
├── src/                  Analyzer and Tkinter viewer
├── config/               analyzer.env.example
├── contrib/              Postfix pipe wrapper and .desktop file
├── docs/                 Architecture notes
├── Dockerfile            Pipe image
├── Dockerfile.viewer     PyInstaller build
└── Makefile
```

`make check` byte-compiles both modules. GitHub Actions runs that compile step and builds the pipe image.

Keep live configuration out of git. `dist/`, `analyzer.env`, and `*.env` are gitignored on purpose.

## License

MIT. See [LICENSE](LICENSE).
