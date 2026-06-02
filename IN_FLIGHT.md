# IN_FLIGHT — bsv-brc-python
_Sist oppdatert: 2026-06-02_

## Mål
OSS-fundament for å bygge sosiale apper på overlay (open-source peck.to). `examples/social_feed.py` = referanse-frøet. Modell (overlay.social): chain-anchor + overlay read-layer (GASP-sync + per-topic Merkle-roots, IKKE SHIP/SLAP) + BRC-100-identitet + 3 skrivekanaler + BRC-77.

## Sist gjort (0.3.0, bygget — IKKE pushet)
- **Komplett, produksjonsklar overlay-node**: BRC-22 /submit, BRC-24 /lookup, `OverlayEngine` (admit+spend+events), `create_overlay_app`. **BEEF-backed JSON-svar** (Accept: application/json). **`SqliteOverlayStorage`** + in-mem. `[overlay]` extra.
- Integrasjon: `build_brc_app` (auth+pay), BRC-29-verifier, PathPricing. brc104 released. py.typed.
- Eksempler: `full_app.py`, `social_feed.py` (smoke-testet E2E).
- **HERDET via adversarisk review-workflow (11/11 funn fikset + regresjonstester)**: komma-X-Topics (py-sdk-interop var KNUST), coins_to_retain spendes nå korrekt, submit atomisk (asyncio.Lock), SQLite read-lås, body-cap (413), ingen exception-lekkasje, 32-byte txid-validering, to docstring-fikser. Nytt: `src/bsv_brc/_asgi.py` (delt capped body-reader).
- **BRC-87** (`bsv_brc.brc87`): tm_/ls_ navnevalidator. Master-regler verifisert mot spec.
- **Per-topic state root GATE ÅPNET**: leste peck-overlay-schema/src/server.ts (spec §3.2) — root = `sha256` av deduped, sortert `"txid:vout"`-sett join'et med `\n` (tom=sha256('')). Skrev om `overlay/topic_root.py` (`state_root`/`outpoint_string`/`EMPTY_STATE_ROOT`) + `OverlayEngine.topic_root/topic_roots` til å MATCHE eksakt. **Live-verifisert** mot overlay.peck.to/state (tom-root e3b0c442... = tm_peck-cat-funding count=0).
- **bsv-sdk bumpet 2.0.0b1→2.1.3** (pin + installert), alle tester grønne, ingen shim-breakage.
- **2 py-sdk-bug-rapporter** i `docs/upstream/` — begge bekreftet i 2.1.3 + HEAD, ingen eksisterende issue. Klare til filing.
- **`GET /state`-endepunkt** lagt til `create_overlay_app` (`make_state_route` + `OverlayEngine.topic_state/topic_states`) — samme verifiserbare kontrakt som overlay.peck.to (`{status, topics:[{topic,count,stateRoot}]}`). social_feed-noden eksponerer det nå.
- **184 tester grønne** (.venv2). Wheel rent.

## Live overlay-API (overlay.peck.to, sondert 2026-06-02)
- `/state` → per-topic stateRoot (spec §3.2). `/listTopicManagers` + `/listLookupServiceProviders` (peck-schema, tm_peck-bio-profile/-handle, tm_peck-cat/-funding).
- `/lookup` med `{}`-query gir JSON-feil "lookupResult.map is not a function" — mulig bug i peck-overlay-schema lookup-handler ELLER feil query-form (verdt å sjekke). Peck svarer JSON, ikke binær.
- peck-schema-root dekker KUN ekte-BEEF /submit (deres /submit-tx bypasser engine→outputs).

## Avklart denne økta
- DROPP BRC-88/SHIP-SLAP — ikke i overlay.social-modellen (GASP/Merkle i stedet), Thomas har det ikke selv.
- py-sdk HAR allerede BRC-77 (`bsv.signed_message`) + UHRP (`bsv.storage`) → ikke dupliser.
- Infra-bootstrap-vinkel: OSS-libs kan default-e til peck-endepunkter. overlay.peck.to live; storage.peck.to/headers.peck.to IKKE i domenekart ennå — bekreft før default.

## Neste (Thomas velger)
- Sosial-data-lag (3 kanaler / Bitcoin-Schema-hybrid) = UTSATT, arkitektur i bevegelse. Sannsynlig egen lib.
- Kandidater: GASP-sync + on-chain root-anchoring (når root-format verifisert mot live overlay); infra-bootstrap-preset (krever live-endepunkt-bekreftelse); BRC-35 (interop-gate); bump bsv-sdk 2.0.0b1→2.1.3 (egen sak, fikser IKKE bugene). (BRC-87 + per-topic Merkle-root FERDIG.)
- Fil de 2 py-sdk-bug-rapportene i `docs/upstream/` til github.com/bsv-blockchain/py-sdk (Thomas / via BSV Association). Begge bekreftet i 2.1.3 + HEAD.

## Blokkert / venter på
- 0.3.0-push venter Thomas' OK. GASP/BEEF-binær-format/BRC-35 venter interop-verifisering mot overlay.peck.to.
