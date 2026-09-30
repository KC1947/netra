# API CONTRACT v1 — SecureMailScope (frontend ↔ backend)

This is the ONLY interface between `web/` (frontend) and `server/` + `sms/` (backend).
If you change it, update this file in both places first, then change the code.

Base URL: `http://127.0.0.1:8000`. The backend serves the frontend from `web/` at `/`, and the API at `/api/*`.

## Endpoints

| # | Method | Path | Request | Response |
|---|---|---|---|---|
| 1 | GET | `/api/health` | – | `{"status":"ok","engine":"securemailscope","version":"0.2","ml_available":true}` |
| 2 | GET | `/api/captures` | – | `Capture[]` |
| 3 | POST | `/api/captures/upload` | multipart, field `file` (.pcap/.pcapng, max 200 MB) | `Capture` with `"source":"uploaded"` · 400 `{"error":"..."}` if not a valid pcap |
| 4 | POST | `/api/analyses` | `{"capture_id":"strip_attack","ml":true}` | `{"analysis_id":"a_000001"}` |
| 5 | GET | `/api/analyses/{id}/events` | – | `text/event-stream` of `StageEvent`s |
| 6 | GET | `/api/analyses/{id}/report` | – | the engine's canonical report JSON (+ `ml`, `ml_summary`) · 409 while still running |
| 7 | GET | `/api/analyses/{id}/sessions/{sid}/packets` | – | `PacketView` · 409 `{"error":"capture file has changed since analysis…"}` if the file no longer matches the report's `capture.sha256` |
| 8 | GET | `/api/analyses/{id}/export?format=json`, `format=html`, `format=cbom`, or `format=pdf` | – | canonical report, HTML report, CycloneDX 1.6 CBOM, or PDF download |

## Capture
```json
{"id":"strip_attack","file":"strip_attack.pcap","title":"STARTTLS stripping attempt",
 "description":"Server capability STARTTLS replaced in transit; client falls back to cleartext AUTH",
 "source":"synthetic","expected":["verdict: suspected","CLEARTEXT-AUTH critical"],
 "sha256":"9f2c0e…","size_bytes":4096,"packets":7}
```
`source` is one of `"synthetic"`, `"real"`, `"fixture"` or `"uploaded"`.
Every API capture also carries `category`, `frames`, `sessions`, and
`analysis_status`. Frame and session counts are measured by the passive engine
against the registered file (cached per file revision), not asserted by UI copy.
Categories are registry supplied: `constructed`, `recorded`, `unsupported`, or
`enterprise`; clients must render unfamiliar categories generically as well.
`description` is registry-owned prose and must not be replaced in the frontend.
The `real_mail` API identity resolves to `tests/fixtures/real_mail.pcap`, not
an older locally recorded copy under `demo_captures/` or `out/`.
The deliberate `pktap_unsupported` capture entry serves
`tests/fixtures/unsupported_linktype_258.pcapng`, a genuine pcapng whose
interface declares link type 258. Clients can therefore exercise the
unsupported-input path without uploading a file.

## HNDL
```json
{"exposed_sessions":5,"quantum_safe_sessions":1,"total_sessions":6,
 "unobservable_sessions":0,"unobservable_sessions_excluded":0,"percent":83}
```
`total_sessions` is the number of observable sessions: cleartext mail plus TLS
sessions where the key exchange can be observed. `unobservable_sessions` covers
unknown, mid-stream, and no-handshake captures; they are excluded from both
the numerator and denominator. Cleartext sessions are always exposed.
`quantum_safe_sessions` counts a negotiated group the offline registry classifies
`PQ_HYBRID` — every RFC 10024 hybrid group, i.e. SecP256r1MLKEM768 (0x11EB),
X25519MLKEM768 (0x11EC) and SecP384r1MLKEM1024 (0x11ED). Classification comes
from `rules/algorithms.yaml`, never from a group name, so adding a future hybrid
code point to the registry is sufficient. The groups obsoleted by RFC 10024
(0x6399, 0x639A) are classified `PQ_OBSOLETE_DRAFT` and count as exposed, as do
classical groups and any code point the registry cannot classify.
The invariant is `exposed_sessions + quantum_safe_sessions == total_sessions`.
`unobservable_sessions_excluded` is the explicit count outside that sum;
`unobservable_sessions` remains its compatibility alias.

`summary.encrypted`, `summary.cleartext` and `summary.not_observable` are
disjoint and sum to `summary.sessions_total`. `encrypted` counts sessions whose
TLS negotiation was established from a captured ServerHello; `cleartext` counts
sessions whose mail grammar was observed and whose transport never upgraded (the
same predicate HNDL uses); everything else, such as an incomplete handshake or
mid-stream encrypted traffic, is `not_observable`. An absent observation is never
counted as cleartext.

## Capture health
`capture_health` is a top-level report block describing what the passive ingest
observed, skipped, or could not retain:
```json
{"file_format":"pcap","snaplen":65535,"truncated":false,
 "frames_decoded_pct":100.0,"analysis_status":"complete",
 "frames":37,"tcp_segments":37,"ipv4":37,"ipv6":0,
 "ipv4_fragments":0,"linktypes":{"1":37},"skipped":{},
 "flows_evicted":0,"flows_truncated":0,"padding_bytes_trimmed":0,
 "sessions_with_holes":0,"sessions_with_conflicting_overlaps":0,
 "sessions_incomplete":0,"total_flows":6,"candidate_flows":6,
 "confirmed_mail_sessions":6,
 "midstream_sessions":{"s1":true,"s2":true,"s3":true,"s4":true,"s5":true,"s6":true},
 "unsupported_packets":{"count":0,"breakdown":{"link_type":0,"malformed":0,
   "non_tcp":0,"truncated_header":0}}}
```
- `file_format`: detected container format, one of `"pcap"`, `"pcapng"`, or
  `"unknown"` when the capture header cannot be identified.
- `snaplen`: the capture-length limit from the pcap header or first pcapng
  interface description block. `truncated` is true when any packet block's
  captured length is smaller than its original wire length.
- `frames_decoded_pct`: numeric `100 * tcp_segments / frames`, rounded to two
  decimal places; an empty capture reports zero rather than claiming coverage.
- `analysis_status`: `complete`, `partial`, `unsupported`, or `unreadable`.
  `summary.findings_assessed` is false for the latter two, so an empty findings
  list is never a clean verdict for input the engine could not analyse.
- `frames`: capture records read; `tcp_segments`: decoded TCP segments retained
  for ingest.
- `ipv4` and `ipv6`: decoded IP packet counts; `ipv4_fragments`: IPv4 fragment
  count (fragments are counted but not reassembled).
- `linktypes`: frame counts keyed by numeric capture link type, encoded as JSON
  object keys; `skipped`: frame or capture-record counts keyed by skip reason.
- `flows_evicted`: flows removed to enforce the flow-table limit;
  `flows_truncated`: flows whose byte or segment budget was exceeded.
- `padding_bytes_trimmed`: link/IP padding bytes excluded from TCP payloads.
- `sessions_with_holes`: sessions containing uncaptured TCP byte ranges;
  `sessions_with_conflicting_overlaps`: sessions with retransmissions that
  disagree on overlapping bytes.
- `sessions_incomplete`: sessions marked incomplete for eviction, truncation,
  holes, or conflicting overlaps.
- `total_flows`: TCP flow generations seen by the lightweight first pass;
  `candidate_flows`: flows admitted by a conventional mail port or the first
  payload bytes `220 `, `* OK`, `+OK`, or TLS record prefix `16 03`.
- `confirmed_mail_sessions`: candidate sessions retained after protocol
  identification with a non-`unknown` protocol. Indeterminate captures on
  conventional mail ports remain visible as report sessions, but are not
  counted as confirmed.
- `midstream_sessions`: a session-id-to-boolean map. True means the first
  packet captured for that TCP flow was not an initial SYN, so the capture may
  have begun after the conversation.
- `unsupported_packets.count`: packets the decoder could not admit;
  `breakdown` always has `link_type`, `malformed`, `non_tcp`, and
  `truncated_header` counters. Numeric link types and their frame counts remain
  available in `linktypes`.
Every field above is a property of the capture file, so the block is
byte-reproducible for a given capture. **`elapsed_time_ms` and
`peak_memory_bytes` were removed from this block** and no longer appear in the
canonical report, the HTML report or the PDF. They are properties of a run, not
of a capture, and a wall-clock value inside the report made the byte-identical
guarantee impossible to hold — the earlier decimal-magnitude
bucketing did not fix that, it only moved the variation to a cliff at 100 ms.
They are still measured: `IngestStats.elapsed_time_ms` and
`IngestStats.peak_memory_bytes` carry the precise values, the `M1` `done`
StageEvent reports them as diagnostic transport metadata, and
`docs/BENCHMARKS.json` remains the measurement of record with median-of-three
elapsed time and isolated-process peak RSS per capture. Clients must not expect
the two keys and must not treat StageEvent timings as report data.

The first pass retains only flow-generation metadata and at most four opening
payload bytes per direction. Full payload retention, TCP reassembly, and the
deeper protocol/TLS/rule stages run only for candidate flows.

## Reproducible benchmark

Run `lab/scripts/build_haystack.sh` before `python bench/run_benchmark.py`.
The builder uses `mergecap` to combine the lab captures with an annotated
zero-mail background capture. When none is supplied, it explicitly generates
deterministic synthetic non-mail traffic. `out/haystack.truth.json` lists every
injected TCP endpoint pair, so haystack precision and recall are exact set
comparisons rather than estimates. The benchmark writes `docs/BENCHMARKS.json`
with three-run median elapsed time, throughput, isolated-process peak RSS, and
mail-session counts for all four standard captures.

## TLS registry and offer fields

Every report includes top-level `registry_version`, identifying the offline
`rules/algorithms.yaml` knowledge used for algorithm names and classifications.
Registry `2026.09.2` adds the 24 cipher suites that appear in the shipped
captures but were previously unregistered; an unregistered suite is reported as
`UNKNOWN_0xNNNN` and its properties stay unknown rather than defaulting to
false.
Each session's `tls` object retains the compatibility fields and also includes:

```json
{"offered_ciphers":[4865,49199,47],"offered_versions":[772,771],
 "offered_groups":[29],"has_fallback_scsv":false,
 "client_hello_frame":6,"server_hello_frame":7,
 "downgrade_sentinel":null,"psk_selected":false,
 "is_hello_retry_request":false,"ocsp_stapling":"not_requested",
 "status_request_sent":false,"psk_offered":false,
 "ech_offered":false,"early_data_offered":false,
 "forward_secrecy":true,"forward_secrecy_status":"YES",
 "downgrade_anomaly":false,"downgrade_legacy_client":false}
```

The three offer arrays contain numeric TLS code points in wire order after
exact RFC 8701 GREASE filtering. `offered_version` remains the compatibility
display field derived from the maximum filtered offered-version code point.
`forward_secrecy` is the v1 field: `true` for `YES`, `false` for `NO`, and `null`
for `UNKNOWN` -- an unknown is never reported as absent forward secrecy.
`forward_secrecy_status` preserves the tri-state `YES | NO | UNKNOWN` signal.
`downgrade_delta` is the offered-minus-negotiated version gap, and `null` when
either the offered or the negotiated version is unknown -- never `0`.

## Session identity

Each session carries `tcp_stream`: Wireshark's `tcp.stream` index for its TCP
flow, counted by M1 over every flow in the capture, including a new index for
a port reused after RST (which Wireshark also splits). It is `null` only when
the index could not be established. Two sessions may share a `five_tuple`
after port reuse, so `id` -- not the five-tuple -- identifies a session.

## Findings

Every finding carries `tier`. `OBSERVED` and `DEDUCED` are the tiers admitted to
`observed_risk`, which makes them claims about specific captured bytes, so the
engine will not issue one without `evidence[]`: a finding whose provenance could
not be preserved is emitted at `NOT_OBSERVABLE` instead, lowering
`evidence_coverage` and contributing no risk, with a
`fact_reason_codes["finding.<RULE-ID>"]` entry recording why. A client may
therefore rely on the pairing: a risk-bearing finding always has at least one
`{frame, field, byte_offset, byte_length}` evidence item.

## Epistemic tiers and coverage

Every fact admitted to scoring is labelled `OBSERVED`, `DEDUCED`, `INFERRED`,
or `NOT_OBSERVABLE` in the session's `fact_tiers` map; findings carry their
own `tier`. Missing or unknown tiers are engine errors and abort scoring.

Every entry whose tier is `NOT_OBSERVABLE` also appears in the session's
`fact_reason_codes` map. Serialization rejects missing or unknown codes. The
closed vocabulary is `tls13_encrypted_certificate`, `midstream_capture`,
`ech_enabled`, `not_present_in_capture`, `unsupported_link_type`,
`malformed_certificate`, and `unsupported_algorithm`. The final two deliberately
cover a captured certificate that cannot be parsed and an unsupported public-key
algorithm; neither condition is silently collapsed into a generic unknown.

Each session exposes four independent scores:

- `observed_risk`: risk from `OBSERVED` and `DEDUCED` findings only.
- `evidence_coverage`: the share of applicable scoring facts directly observed.
- `deduced_coverage`: the share established through deterministic deduction.
- `inferred_coverage`: the share inferred rather than observed or deduced.

`NOT_OBSERVABLE` facts contribute only to the coverage denominator. They never
lower risk. The report repeats all four score names at top level. Report-level
`observed_risk` runs the same risk function once over the capture-wide finding
set; it is not a mean of session risks. Report-level `evidence_coverage`,
`deduced_coverage`, and `inferred_coverage` are pooled ratios: their numerators
and applicable-check denominators are summed across sessions before rounding.
Clients must not derive, average, or combine these values.

## CBOM export

`format=cbom` returns a schema-valid CycloneDX 1.6 document named
`{analysis_id}.cdx.json`. Its metadata records the offline algorithm
`registry_version`. Only support-matrix facts tiered `OBSERVED` or `DEDUCED`
can contribute components; `INFERRED`, `NOT_OBSERVABLE`, excluded, and
undetermined capabilities are omitted. An observed but unidentified cipher is
retained as `UNKNOWN_0xNNNN`, with `netra:unidentified_ciphers` on its TLS
protocol component because CycloneDX does not allow properties on individual
`cipherSuite` objects.

## PDF export

`format=pdf` returns `{analysis_id}.pdf`, rendered offline by WeasyPrint from
the same canonical report JSON and Jinja HTML template as the HTML export. The
document presents the capture health passport, correlated servers and support
matrices, every finding with its tier and exact frame references, and the
evidence-coverage caveat in that order. PDF export performs no additional
analysis and cannot change findings or scores.

## Correlated servers
`servers` is a top-level report block produced by P3 after the per-session rule
engine. Each entry groups sessions by the observed `(server_ip, server_port)`
endpoint plus TLS SNI, or an SMTP greeting hostname when SNI is unavailable.
An identity without either hostname keeps the stable `IP:port` label. A named
identity is labelled `hostname@IP:port`; IPv6 endpoints use brackets.

```json
{
  "server_id":"mail.example.com@10.0.0.20:25",
  "sessions":["s1","s3","s4"],
  "identity_evidence":[
    {"session":"s1","source":"smtp_banner","tier":"OBSERVED",
     "hostname":"mail.example.com","name_observed":true,"reason":null,
     "endpoint":"10.0.0.20:25",
     "evidence":[{"frame":1,"field":"smtp.banner.hostname",
                  "byte_offset":58,"byte_length":16,"display":"mail.example.com"}]}
  ],
  "preference_mode":"unknown",
  "preference_mode_evidence":{"reason":"no pair rules out the alternative explanation"},
  "support_matrix":{
    "version:0x0304":{"state":"DEMONSTRATED","tier":"OBSERVED","positive_evidence":["s1"],
                      "negative_evidence":[],
                      "establishing_evidence":[{"session":"s1","frame":7,
                        "byte_offset":107,"byte_length":2,"kind":"selected"}]}
  },
  "contradictions":[],
  "deduced_coverage":{"settled":1,"applicable":4,"percent":25}
}
```

- `identity_evidence.source` is `tls_sni`, `smtp_banner`,
  `endpoint_sni_association`, or `network_endpoint`. The directly observed
  hostname sources carry exact packet evidence. When exactly one SNI is
  observed for an IP:port anywhere in the capture, sessions at that endpoint
  with no observed name are grouped under it with tier `DEDUCED`,
  `name_observed:false`, and a plain-English `reason`. An endpoint that never
  presents SNI remains bare with a reason stating that no server name was
  observed; the engine never fabricates a name.
- `preference_mode` is `server_order`, `client_order`, or `unknown`.
  `server_order` is emitted only when an alternative shared suite has been
  separately demonstrated; opposite client orderings alone are insufficient.
- Support states are exactly four: `DEMONSTRATED`, `EXCLUDED_FIRM`,
  `CONTRADICTED`, or `UNDETERMINED`. Matrix construction gathers all evidence
  before deriving states, so session arrival order cannot hide contradictions.
  There is no weak-exclusion state. An earlier `EXCLUDED_LIKELY` was **removed**:
  the engine records a negative observation only where the exclusion is firm —
  under server or unknown cipher ordering, a suite the server passed over proves
  nothing, so nothing is recorded — which left the state unreachable. Clients
  must not expect it and should treat any unfamiliar state generically.
- Every non-`UNDETERMINED` cell has `establishing_evidence`. A `selected` item
  identifies the ServerHello field; an `offered` item identifies the unselected
  ClientHello offer. `CONTRADICTED` carries both. If the engine cannot preserve
  a frame and byte offset, the cell is `UNDETERMINED` instead of making an
  unsupported capability assertion. `positive_evidence` and `negative_evidence`
  retain their existing session-id lists.
- An `UNDETERMINED` cell has `reason_code: "not_present_in_capture"`, matching
  the closed `NOT_OBSERVABLE` vocabulary.
- `deduced_coverage` counts firmly settled TLS versions over the four applicable
  versions (TLS 1.0 through TLS 1.3), never over only the cells seen.

When a certificate is visible on one session for a resolved server identity,
an encrypted session for that same identity can include contextual association:

```json
"certificate_seen_on_service":[
  {"fingerprint":"a42f…","source_session":"s1","source_frame":3,
   "tier":"DEDUCED","relation":"same service identity; NOT proof for this session"}
],
"certificate_ambiguous":false
```

This never changes the encrypted session's own `certificate.status`, which
remains `NOT_OBSERVABLE`. Multiple distinct fingerprints set
`certificate_ambiguous` to `true`; the association entries retain every
fingerprint and its actual source session/frame. Variation may reflect rotation,
load-balanced backends, SNI, or RSA/ECDSA certificate selection.

## StageEvent
Each SSE message is one line, `data: <json>`, followed by a blank line.
```json
{"stage":"M3","label":"STARTTLS state machine","status":"done","detail":"6 sessions: 4 upgraded, 1 not_used, 1 suspected","t_ms":42}
```
- The stages, in order:
  - M1 "Ingest & TCP reassembly"
  - M2 "Protocol identification"
  - M3 "STARTTLS state machine"
  - M4 "TLS handshake analysis"
  - M5 "X.509 certificate checks"
  - M6 "Rule engine"
  - P3 "Server correlation"
  - M7 "AI anomaly layer"
  - M8 "Scoring & HNDL"
  - M9 "Report"
- Each stage sends `"status":"start"` and then `"status":"done"`. M7 sends `"status":"skipped"` when ML is off.
- The stream ends with one of:
  - `{"stage":"DONE","status":"done","analysis_id":"a_000001","t_ms":180}`
  - `{"stage":"ERROR","status":"error","message":"..."}`
- Events are REAL module boundaries, never timers.

## ML fields inside the report
```json
"ml": {"model":"IsolationForest+HBOS","schema_version":"ml-v1","baseline_sessions":192,
       "anomaly_score":5.73,"anomaly_percentile":100.0,"is_anomaly":true,
       "top_factors":[{"feature":"cert_fp_share_for_server","value":0.024,"baseline_typical":1.0,"baseline_share_pct":0.4}],
       "disagrees_with_rules":true}
"ml_summary": {"enabled":true,"model":"IsolationForest+HBOS","baseline_sessions":192,"anomalies":1,"threshold_percentile":99}
```
`ml` lives on each session. `ml_summary` sits at the report's top level. When ML is off: `ml: null` and `ml_summary.enabled: false`.
`anomaly_score` is the maximum robust z-score from active Isolation Forest/HBOS
components, standardised on held-out calibration captures. Zero-MAD components
are disabled, and constant/unobserved reference features contribute nothing.
`anomaly_percentile` is retained
for display compatibility and is calculated against calibration only; it does
not drive ranking or the anomaly decision.

M7 calibration adds `ml.abstained`, `ml.abstention_reason`, and `ml.explanation`.
An abstention has null score and percentile, `is_anomaly:false`, and no factors.
Reasons are `degenerate_calibration`, `no_observed_varying_features`, or
`capture_identity_unavailable`. `top_factors` contains zero to three entries,
each with observed reference-bin frequency `baseline_share_pct <= 5.0`; it is
never padded with common features. If none qualify, `explanation` states that
the ranking reflects a combination without a single qualifying rare factor.
`ml_summary` adds `abstentions`, `calibration_sessions`, `rarity_share_pct`, and
`calibration` provenance (source hashes, disjoint capture splits, active
components and scoring-capture exclusion). All additions remain exclusively
inside the existing ML namespaces. The feature schema stays `ml-v1`; the new
numeric baseline artifact is `m7-baseline-v2`.

## PacketView
```json
{"session_id":"s4","client":"10.0.0.10:40004","server":"10.0.0.20:25","protocol":"smtp",
 "frames":[
   {"frame":24,"t_ms":0,"dir":"s2c","len":30,"layer":"smtp","summary":"S: 220 mail.example.com ESMTP","evidence_rules":[]},
   {"frame":25,"t_ms":10,"dir":"c2s","len":24,"layer":"smtp","summary":"C: EHLO client.example.com","evidence_rules":[]},
   {"frame":26,"t_ms":20,"dir":"s2c","len":58,"layer":"smtp","summary":"S: 250 XSNVVQRW  (capability line)","evidence_rules":["STARTTLS-STRIP-SUSPECTED"]},
   {"frame":27,"t_ms":30,"dir":"c2s","len":37,"layer":"smtp","summary":"C: AUTH PLAIN [REDACTED]","evidence_rules":["CLEARTEXT-AUTH"]},
   {"frame":28,"t_ms":40,"dir":"s2c","len":37,"layer":"smtp","summary":"S: 235 2.7.0 Authentication successful","evidence_rules":[]}],
 "evidence":[
   {"rule_id":"STARTTLS-STRIP-SUSPECTED","frame":26,"field":"smtp.capability","byte_offset":96,"byte_length":8,
    "hex_window":"58 53 4e 56 56 51 52 57","ascii_window":"XSNVVQRW","highlight":[0,8],"redacted":false,"withheld_bytes":0},
   {"rule_id":"CLEARTEXT-AUTH","frame":27,"field":"cleartext-auth","byte_offset":54,"byte_length":37,
    "hex_window":"","ascii_window":"AUTH PLAIN [REDACTED]","highlight":[0,0],"redacted":true,"withheld_bytes":37}],
 "wireshark_filter":"tcp.stream eq 3 && frame.number == 26"}
```
- `wireshark_filter` pairs `tcp.stream` with `frame.number`. The stream is
  Wireshark's own index, assigned by M1 over **every** TCP flow in the capture
  and carried on the session as `tcp_stream`; it is not the session's position
  in `sessions[]`, which counts only retained mail flows and diverges on any
  capture containing other traffic. Clients must use the emitted string or
  rewrite only its `frame.number` clause, never rebuild the stream clause.
  When `tcp_stream` is absent the filter degrades to `frame.number` alone
  rather than naming a stream it cannot establish.
- A `PacketView` is served only when the capture on disk still hashes to the
  report's `capture.sha256`. If it does not, the endpoint returns **409** with
  an `error` naming both digests: the report's frame numbers do not address
  the same packets in a different file, so no bytes are shown. Clients should
  surface that message and offer to re-run the analysis, never retry.
- `dir` is `"c2s"` (client to server) or `"s2c"` (server to client).
- `layer` is one of `"smtp"`, `"imap"`, `"pop3"`, `"tls"` or `"tcp"`.
- `highlight` is `[start, end)`, measured in bytes inside `hex_window`.
- Evidence windows never extend past the cited span: no neighbouring bytes
  are copied. What is shown depends only on the evidence `field`, never on the
  rule: binary TLS handshake fields are shown in full (key-share material
  excepted); `smtp.capability` and `smtp.banner.hostname` are shown only if
  the span still matches keyword/hostname grammar; a cited `protocol.line`
  shows only its leading reply code or command verb from a fixed set; AUTH
  lines and every unrecognised field are withheld entirely. `withheld_bytes`
  counts the cited bytes not shown, and `redacted` is `true` whenever it is
  non-zero.
- TLS frames are summarised by type, e.g. `C: TLS ClientHello (offers TLS1.3, TLS1.2)`, `S: TLS ServerHello (TLS1.0, TLS_RSA_WITH_AES_128_CBC_SHA)`, `S: TLS Certificate (1 cert)`, `TLS Application Data (48 bytes)`.
- The frame numbers and the stream index above are illustrative. Both come
  from the capture; `tcp.stream eq 3` here happens to equal the session's
  position only because every flow in that example capture is mail.

## Privacy (both sides)
- Never send credential values, AUTH arguments, message bodies or key material.
- AUTH lines are always `[REDACTED]`, with an empty `hex_window`.
- Message bodies are shown as `C: [message body, N bytes, not displayed]`.
- The frontend must display the redaction exactly as it arrives and never try to reconstruct it.
