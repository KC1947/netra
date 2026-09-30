# SecureMailScope — 60-second demo script

## Setup (before judges arrive)
```
python lab/certs_build.py && python lab/generate_pcap.py
python -m sms.cli analyse out/sample.pcap --json out/report.json --html out/report.html
python -m sms.cli analyse out/sample.pcap --self-test   # expect 6/6 PASS + hndl PASS
open out/report.html                                    # offline, no internet needed
```

## The script (~60 seconds)

1. **Session list.** Open `out/report.html`. Point at the session table: protocol,
   transition verdict, TLS version, downgrade-delta, cert status, confidence band —
   every session, one row, nothing hidden.

2. **HNDL banner.** Read the number at the top: *"83% of 6 observable sessions exposed
   (0 not observable)"* — 5 of 6 sessions have no hybrid post-quantum
   key exchange, so all of that traffic is decryptable retroactively by a future
   quantum computer. Only s6 (hybrid X25519MLKEM768) is safe from that.

3. **Open s4 — the STARTTLS-strip session.** Expand its findings.
   - Verdict: **suspected** (never "attacker" — this tool only asserts what it saw).
   - The mangled capability: server said `250-XSNVVQRW` instead of `250-STARTTLS`
     (same 8 letters, not a real SMTP keyword) — frame-cited, byte-cited.
   - The client then sent `AUTH PLAIN ...` in the clear. That argument is shown as
     `AUTH argument redacted`, never the decoded credential.
   - Severity: Critical. Risk floor: 90 (cleartext AUTH with no successful upgrade).

4. **Open s1 — the clean TLS 1.3 session.** Cert status: **NOT_OBSERVABLE** — TLS 1.3
   encrypts the Certificate message, so a passive capture genuinely cannot see it.
   That's honesty, not a bug. Version, cipher, group (x25519), and forward secrecy
   are all still reported from the visible parts of the handshake.

5. **"Fix before lunch" list.** Scroll to the bottom table: every finding across the
   capture, sorted by remediation effort — `one_line_reload` items first (cipher
   order, disabling static-RSA), then `cert_reissue`, then `software_upgrade`
   (disabling legacy TLS versions). Export `out/report.json` — that's the same data,
   byte-identical on every re-run of the same PCAP.

## Two numbers, never one grade
Every session shows **observed_risk** (0-100, what we saw) and **evidence_coverage**
(0-100, how much of the session we could actually inspect) side by side. A TLS 1.3
session's unobservable certificate lowers its coverage; it never raises its risk.

## Talking point if asked "why not just block on TLS 1.0?"
Because s2's server *did* speak TLS 1.0 — the point of `downgrade_delta` (offered
TLS 1.3, negotiated TLS 1.0 → delta 3) is that this capture proves it was available
to negotiate higher and didn't, which is a stronger, evidence-backed claim than "an
old server."
