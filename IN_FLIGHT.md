# IN_FLIGHT — bsv-brc-python
_Sist oppdatert: 2026-06-02_

## Status: 0.3.0 PUSHET + TAGGET (origin/master ec7fbcb, tag v0.3.0) 2026-06-03
py-sdk-bugene FILET: py-sdk#158 (lookup-parser), #159 (internalize-BEEF). peck-overlay-schema /lookup-fix DEPLOYET av Thomas (rev 126) — `/lookup` funker live nå (returnerer output-list+AtomicBEEF).
**Full interop-bevis FERDIG**: vår `state_root` over de 4 live tm_peck-bio-profile-outpoint-ene = overlay.peck.to sin publiserte root `b26b1c65...` byte-for-byte (pinnet som offline regresjonstest). Tom-root `e3b0c442` også live-matchet. Topic-root-gaten HELT lukket. 185 tester.
**PyPI: PUBLISERT 2026-06-03** — 0.3.0 lastet opp av Thomas (https://pypi.org/project/bsv-brc/0.3.0/). `pip install bsv-brc` gir nå hele verktøykassa. (PyPI JSON-API cacher ~noen min, så /pypi/bsv-brc/json kan vise 0.2.0 en stund — ufarlig.)

## Sist gjort (2026-06-03, etter PyPI 0.3.0)
- **Monorepo adopsjons-survey** (workflow): kart over hvor bsv-brc kan dogfood-es — se minne [bsv-brc adopsjons-kart]. peck-web bruker ALLEREDE bsv_brc auth.
- **Overlay-KLIENT bygget** (`bsv_brc.overlay.OverlayClient`, committet d42f38a master, UNRELEASED→0.4.0): submit/lookup/state/verify_state, default overlay.peck.to, dependency-fri (urllib) + rene parsere for async. **Live-verifisert mot overlay.peck.to**. 193 tester. CHANGELOG [Unreleased].
- **Bitcom/Bitcoin-Schema-bygger bygget** (`bsv_brc.bitcom`, committet 85b63e0): B/MAP/AIP op_return-bygger (pipe=0x01 0x7c, fikser raw-0x7c-bug) + parser (speiler overlay.peck.to) + AIP via BSM. 210 tester.
- Adopsjons-rekkefølge (Thomas: "alle, men start på 1"): [x] overlay-klient, [x] OP_RETURN/Bitcoin-Schema-bygger. Neste roadmap-gap: paymail-modul (3× ~600-linjers hand-rull), typed peck-anchor-klient, headers.peck.to ChainTracker, HKDF-salt v2 identitets-helper. ELLER quick dogfood-wins (peck-certifier brc052-swap + re-eksport-fiks, merdata AES).

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
- peck-overlay /lookup-fix (f122089) venter DEPLOY av Thomas. Etter deploy: smoke-test `POST /lookup {"service":"ls_peck-bio-profile","query":{}}` → skal gi output-list, ikke .map-feil.
- Valgfritt: tag v0.3.0 + PyPI-publisering (ikke gjort). GASP/BEEF-binær-format/BRC-35 venter videre interop-verifisering.
