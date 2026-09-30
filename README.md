# NETRA / SecureMailScope

NETRA is SecureMailScope's offline, passive analyzer for email-transport packet captures.
It reconstructs SMTP, IMAP and POP3 sessions and reports TLS, certificate and upgrade risks with packet evidence.
Observed risk and evidence coverage are separate scores, and missing or encrypted evidence remains explicitly unknown.

## Install

Run the commands below from the root of your clone. Python **3.12** is required.
The setup and validation commands were exercised in a fresh virtual environment
using only the files selected for this release, on macOS with Apple Silicon.

Provide these system prerequisites before running setup:

| Prerequisite | Purpose |
|---|---|
| Python 3.12, available as `python3.12` | Creates the local `.venv` |
| Pango and its font/rendering libraries, with a usable system font | WeasyPrint PDF export and PDF tests |
| Wireshark command-line tool `tshark` on `PATH` | Offline parser differential and packet-filter tests |
| Node.js, available as `node` | JavaScript presentation/filter tests |
| Wireshark `mergecap` | Only needed if rebuilding the haystack benchmark; its capture and truth file already ship |

Install the prerequisites through your operating system's package manager or
vendor installer. This validation used Python 3.12.14, Pango 1.58.2, TShark 4.6.8
and Node.js 26.8.2. Other operating systems were not exercised during this release check.

```sh
./setup.sh
```

The script checks the command-line prerequisites, creates `.venv` if needed,
installs the engine, server and test dependencies from [requirements.txt](requirements.txt),
runs `pip check`, and checks that PDF and API test imports work. Package installation
may need internet access; analysis uses local files and makes no external network requests.
All required captures, public certificate fixtures and the numeric ML baseline are
included in Git. No capture or certificate generation is needed for the commands below.

## Analyze a shipped capture

```sh
.venv/bin/python -m sms.cli analyse tests/fixtures/real_mail.pcap --no-ml --json out/readme-real-mail.json --html out/readme-real-mail.html
```

This reads the recorded mail fixture and writes JSON and a self-contained HTML
report under ignored output paths. The validated capture contains 1,323 frames,
37 retained sessions and 29 sessions identified as mail by payload grammar.
The example disables the optional anomaly layer; ordinary analysis enables it
when the shipped numeric baseline is available. AUTH arguments and mail bodies
are redacted in reports.

## Start the server and UI

```sh
.venv/bin/python -m server.app
```

Open **http://127.0.0.1:8000/** in a browser. The service binds to loopback and
serves the checked-in UI and its same-origin API. The library exposes ten built-in
entries, including an intentionally unsupported capture. Select a capture to
analyze it; stop the service with `Ctrl-C`. No frontend build or CDN is needed.

## System dependencies (Linux)

`requirements.txt` covers the Python packages. Three things must come from the
operating system. Verified on Ubuntu 26.04.

**PDF export** needs Pango, which WeasyPrint loads at import time. Without it,
six test modules fail to collect:

    sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
        libffi-dev shared-mime-info

**tshark** is needed by the differential oracle and the Wireshark-filter tests.
The engine itself does not need it:

    sudo DEBIAN_FRONTEND=noninteractive apt install -y tshark

**AppArmor** confines tshark on Ubuntu and denies reads under `/home`, which
makes those tests fail with an empty result rather than an error. Either put
the profile in complain mode:

    sudo apt install -y apparmor-utils
    sudo aa-complain /usr/bin/tshark

or keep enforcement and add a local override:

    echo "owner /home/*/** r," | sudo tee -a /etc/apparmor.d/local/usr.bin.tshark
    sudo apparmor_parser -r /etc/apparmor.d/usr.bin.tshark

On macOS these arrive with Homebrew and none of the above applies.




## Shipped captures

The eight captures used by the broad regression/evidence checks are:

| Path | Purpose | Analyzed sessions |
|---|---|---:|
| `out/sample.pcap` | Six-session demonstration and self-test | 6 |
| `out/anomaly_demo.pcap` | Certificate-swap anomaly corpus | 41 |
| `out/multiclient.pcap` | Multi-client server-policy correlation | 18 |
| `out/baseline.pcap` | Synthetic baseline corpus | 240 |
| `out/haystack.pcap` | Mail sessions embedded in non-mail traffic | 24 |
| `tests/fixtures/real_mail.pcap` | Recorded mail traffic | 37 |
| `tests/fixtures/mixed_enterprise.pcap` | Current enterprise scenario; served by the API | 25 |
| `tests/fixtures/recorded_mail_ethernet.pcapng` | Recorded Ethernet/pcapng coverage | 4 |

Haystack and enterprise intentionally contain capture limitations and report
`partial` capture health. A successful analysis does not mean the capture is
complete or the transport is safe.

Additional shipped inputs are:

| Path | Purpose |
|---|---|
| `demo_captures/clean_tls13.pcap` | One clean TLS 1.3 session in the UI library |
| `demo_captures/legacy_downgrade.pcap` | One deprecated-TLS downgrade session |
| `demo_captures/cleartext_auth.pcap` | One synthetic cleartext-authentication session |
| `demo_captures/strip_attack.pcap` | One suspected STARTTLS-stripping session |
| `demo_captures/expired_cert.pcap` | One expired-certificate session |
| `demo_captures/pq_ready.pcap` | One hybrid post-quantum key-exchange session |
| `demo_captures/anomaly_certswap.pcap` | UI/library-test copy of `out/anomaly_demo.pcap` |
| `demo_captures/real_mail.pcap` | Library-test copy of the recorded mail fixture |
| `demo_captures/mixed_enterprise.pcap` | **Legacy six-session fixture required by library tests** |
| `tests/fixtures/unsupported_linktype_258.pcapng` | Unsupported-input health reporting; zero analyzed sessions |
| `out/haystack_background.pcap` | Non-mail source recorded in the benchmark provenance |
| `out/m7_baseline/benign_101.pcap` | Synthetic source capture for the numeric ML baseline |
| `out/m7_baseline/benign_102.pcap` | Synthetic source capture for the numeric ML baseline |
| `out/m7_baseline/benign_103.pcap` | Synthetic source capture for the numeric ML baseline |
| `out/m7_baseline/benign_104.pcap` | Synthetic source capture for the numeric ML baseline |

`out/haystack.truth.json` supplies the benchmark's answer key. Local uploads and
unlisted recordings remain ignored. Some fixture copies are deliberately retained
because different test and API paths read them; deduplication would change those paths.

### Two different files named mixed_enterprise.pcap

**Do not exchange or rename these files.**

| Exact path | Bytes | Reader and meaning |
|---|---:|---|
| `demo_captures/mixed_enterprise.pcap` | 5,335 | `tests/test_demo_library.py` reads this legacy **six-session** capture through the library-relative path. |
| `tests/fixtures/mixed_enterprise.pcap` | 278,350 | `server/app.py` explicitly serves this current **25-session** capture; `lab/build_demo_library.py` measures it for registry metadata. |

The manifest's enterprise metadata describes the 25-session fixture. The library
test deliberately keeps its older library-relative path and six-session expectation.
The builder does not recreate that legacy copy, so both are tracked for a fresh clone.

## Tests and self-test

Run the full root suite, including `tests/` and `ml/`:

```sh
.venv/bin/python -m pytest -q --tb=short
```

TShark and Node.js must be present for all integration checks to run. Some
regression cases are explicitly marked as expected failures; they are not
new failures introduced by release cleanup.

Run the six-session answer-key comparison:

```sh
.venv/bin/python -m sms.cli analyse out/sample.pcap --self-test
```

Expected result: `s1` through `s6` pass, followed by HNDL expected/observed `83`.
The immutable answer key is `tests/ground_truth.json`.

The regression suite checks packet ingestion, protocol and TLS parsing,
risk and evidence coverage, and report redaction. Capture benchmarks and
resource measurements are recorded in [benchmark results](docs/BENCHMARKS.json).

See [the API contract](docs/API_CONTRACT.md) for report and endpoint semantics,
and [the live UI notes](web/README.md) for frontend behavior.

## About this repository

This is a clean, single-commit release of NETRA v1.6.1. The full development
history — the incremental build, the independent review passes, and the fixes
that came out of them — is kept in the team's working repository and can be
shown on request.

The engine in this release has been through an adversarial review of its core
logic, followed by replay verification across 19 captures in which every
changed output was attributed to the specific fix that caused it. Calibration
records for the anomaly layer, including a failure found on real traffic and
the measurements taken after fixing it, are in
[the calibration notes](docs/M7_CALIBRATION.md) and
[benchmark results](docs/BENCHMARKS.json).
