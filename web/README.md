# NETRA live UI

Local service command (repository root): `.venv/bin/python -m server.app`.
Service address: http://127.0.0.1:8000. The cream/navy UI is served from this directory.
The discarded standalone UI snapshot was removed during release cleanup; this is the maintained UI.

All requests are same-origin `/api` requests in `js/api.js`. There is no mock
mode or fallback report. `js/model.js` maps canonical report fields; views
consume that model. Scores, HNDL counts, capture health, fact reason codes,
preference modes and support evidence are engine-owned.

The Library renders every registry entry, grouped by its category. Descriptions
and measured frame/session counts come from `/api/captures`. Selecting a card
or uploading a capture starts analysis. AI changes trigger a fresh analysis;
they never locally edit findings or scores.

Exports download unchanged engine artifacts. CBOM/PDF are disabled until a
report is loaded. Unsupported inputs retain a NOT ANALYSED state and never
show empty findings as proof of safety.

See [API_CONTRACT.md](API_CONTRACT.md) for the synchronized backend contract.
