"""Tests for the overlay node: BRC-24 lookup, engine, wire format, ASGI."""

from __future__ import annotations

import base64
import json

import pytest
from starlette.testclient import TestClient

from bsv.overlay_tools.lookup_resolver import LookupQuestion
from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionInput, TransactionOutput
from bsv.utils.reader import Reader

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF

from bsv_brc.brc22.topic_manager import TopicManager
from bsv_brc.brc24 import LookupService, OutputRef, ResolvedOutput, serialize_output_list
from bsv_brc.brc24.wire import output_list_to_json
from bsv_brc.overlay import (
    OverlayEngine,
    SqliteOverlayStorage,
    UnknownServiceError,
    UnknownTopicError,
)
from bsv_brc.overlay.adapters.asgi import (
    create_overlay_app,
    make_lookup_route,
    process_lookup,
)
from bsv_brc.overlay.client import (
    NoAdmissionError,
    OverlayClient,
    OverlayHTTPError,
    build_submit_headers,
    parse_lookup_answer,
    parse_state,
    parse_steak,
)


# --- helpers -------------------------------------------------------------


def _tx_one_output(marker: bytes = b"post") -> Transaction:
    tx = Transaction()
    tx.add_output(
        TransactionOutput(
            locking_script=Script(b"\x6a" + bytes([len(marker)]) + marker),
            satoshis=1,
        )
    )
    return tx


class AdmitOutputZero(TopicManager):
    def identify_admissible_outputs(self, beef, previous_coins):
        return AdmittanceInstructions(
            outputs_to_admit=[0], coins_to_retain=list(previous_coins)
        )


class RecencyIndex(LookupService):
    """Indexes every admitted output and returns them newest-first."""

    def __init__(self, topic: str = "tm_posts") -> None:
        self.topic = topic
        self.items: list[OutputRef] = []
        self.spent: list[tuple[str, int]] = []

    def output_admitted(self, topic, txid, output_index, locking_script, satoshis):
        if topic != self.topic:
            return
        # Stash the locking script as context so the client gets content.
        self.items.insert(0, OutputRef(txid, output_index, context=locking_script))

    def output_spent(self, topic, txid, output_index):
        self.spent.append((txid, output_index))

    def lookup(self, question):
        limit = (question.query or {}).get("limit", 10)
        return self.items[:limit]


# --- wire format (proves interop with py-sdk's intended binary reader) ---


def _parse_output_list_fixed(data: bytes):
    """Decode with the corrected reader (read_var_int_num).

    py-sdk 2.0.0b1 uses read_var_int (returns bytes) here, which is a
    bug; this mirrors the format py-sdk intends so we prove the bytes
    are well-formed.
    """
    r = Reader(data)
    n = r.read_var_int_num()
    out = []
    for _ in range(n):
        txid = r.read(32).hex()
        idx = r.read_var_int_num()
        clen = r.read_var_int_num()
        ctx = bytes(r.read(clen)) if clen > 0 else None
        out.append((txid, idx, ctx))
    return out


def test_serialize_output_list_roundtrips():
    txid = "ab" * 32
    refs = [OutputRef(txid, 0, b"hello"), OutputRef(txid, 5, None)]
    decoded = _parse_output_list_fixed(serialize_output_list(refs))
    assert decoded == [(txid, 0, b"hello"), (txid, 5, None)]


def test_serialize_empty_output_list():
    assert _parse_output_list_fixed(serialize_output_list([])) == []


def test_serialize_rejects_non_32_byte_txid():
    # A wrong-length txid would silently desync the whole binary stream.
    with pytest.raises(ValueError, match="32 bytes"):
        serialize_output_list([OutputRef("11" * 33, 0, b"x")])
    with pytest.raises(ValueError, match="32 bytes"):
        serialize_output_list([OutputRef("11" * 16, 0, None)])


def test_serialize_rejects_negative_output_index():
    with pytest.raises(ValueError, match="non-negative"):
        serialize_output_list([OutputRef("ab" * 32, -1, None)])


def test_output_list_to_json_b64_encodes_context():
    out = output_list_to_json([OutputRef("ab" * 32, 1, b"\x00\x01")])
    assert out["type"] == "output-list"
    assert out["outputs"][0]["outputIndex"] == 1
    assert out["outputs"][0]["context"] == "AAE="  # base64 of \x00\x01


# --- engine: submit -> admit -> event -> lookup --------------------------


def _engine():
    return OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        lookup_services={"ls_posts": RecencyIndex("tm_posts")},
    )


@pytest.mark.asyncio
async def test_submit_admits_and_indexes_then_lookup_returns_it():
    engine = _engine()
    tx = _tx_one_output(b"first")
    steak = await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    assert steak["tm_posts"].outputs_to_admit == [0]

    refs = await engine.lookup(LookupQuestion(service="ls_posts", query={}))
    assert len(refs) == 1
    assert refs[0].txid == tx.txid()
    assert refs[0].output_index == 0


@pytest.mark.asyncio
async def test_lookup_unknown_service_raises():
    engine = _engine()
    with pytest.raises(UnknownServiceError):
        await engine.lookup(LookupQuestion(service="ls_nope", query={}))


@pytest.mark.asyncio
async def test_engine_requires_a_topic_manager():
    with pytest.raises(ValueError):
        OverlayEngine(topic_managers={})


@pytest.mark.asyncio
async def test_recency_ordering_newest_first():
    engine = _engine()
    txa = _tx_one_output(b"aaa")
    txb = _tx_one_output(b"bbb")
    await engine.submit(TaggedBEEF(beef=txa.to_beef(), topics=["tm_posts"]))
    await engine.submit(TaggedBEEF(beef=txb.to_beef(), topics=["tm_posts"]))
    refs = await engine.lookup(LookupQuestion(service="ls_posts", query={"limit": 5}))
    assert [r.txid for r in refs] == [txb.txid(), txa.txid()]


@pytest.mark.asyncio
async def test_spend_detection_marks_previous_coin_and_fires_event():
    # Even when the manager lists a coin in coins_to_retain, a coin the
    # transaction actually spends on-chain is consumed: it must be marked
    # spent and fire output_spent. Retention is a history concern, not
    # liveness (matches canonical @bsv/overlay).
    index = RecencyIndex("tm_posts")
    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},  # retains previous coins
        lookup_services={"ls_posts": index},
    )
    tx1 = _tx_one_output(b"original")
    await engine.submit(TaggedBEEF(beef=tx1.to_beef(), topics=["tm_posts"]))
    assert engine.storage.is_unspent("tm_posts", tx1.txid(), 0)

    # Second tx spends tx1:0 — it becomes a "previous coin". Attach tx1
    # as the source transaction so BEEF can be built (tx1 has no inputs,
    # so it needs no proof of its own).
    tx2 = Transaction()
    tx2.add_input(
        TransactionInput(
            source_transaction=tx1, source_txid=tx1.txid(), source_output_index=0
        )
    )
    tx2.add_output(
        TransactionOutput(locking_script=Script(b"\x6a\x03new"), satoshis=1)
    )
    await engine.submit(TaggedBEEF(beef=tx2.to_beef(), topics=["tm_posts"]))

    # The retained coin is spent on-chain, so it is retired and output_spent fired.
    assert not engine.storage.is_unspent("tm_posts", tx1.txid(), 0)
    assert (tx1.txid(), 0) in index.spent


@pytest.mark.asyncio
async def test_spend_when_manager_does_not_retain():
    class AdmitButDropCoins(TopicManager):
        def identify_admissible_outputs(self, beef, previous_coins):
            return AdmittanceInstructions(outputs_to_admit=[0], coins_to_retain=[])

    index = RecencyIndex("tm_posts")
    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitButDropCoins()},
        lookup_services={"ls_posts": index},
    )
    tx1 = _tx_one_output(b"original")
    await engine.submit(TaggedBEEF(beef=tx1.to_beef(), topics=["tm_posts"]))

    tx2 = Transaction()
    tx2.add_input(
        TransactionInput(
            source_transaction=tx1, source_txid=tx1.txid(), source_output_index=0
        )
    )
    tx2.add_output(TransactionOutput(locking_script=Script(b"\x6a\x01\x00"), satoshis=1))
    await engine.submit(TaggedBEEF(beef=tx2.to_beef(), topics=["tm_posts"]))

    assert not engine.storage.is_unspent("tm_posts", tx1.txid(), 0)
    assert (tx1.txid(), 0) in index.spent


# --- ASGI: /lookup + create_overlay_app ----------------------------------


@pytest.mark.asyncio
async def test_process_lookup_returns_binary():
    engine = _engine()
    tx = _tx_one_output(b"x")
    await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    status, ctype, body = await process_lookup(
        method="POST",
        body=json.dumps({"service": "ls_posts", "query": {}}).encode(),
        engine=engine,
    )
    assert status == 200
    assert ctype == "application/octet-stream"
    assert _parse_output_list_fixed(body)[0][0] == tx.txid()


@pytest.mark.asyncio
async def test_process_lookup_rejects_get():
    status, _, _ = await process_lookup(method="GET", body=b"", engine=_engine())
    assert status == 405


def test_create_overlay_app_serves_submit_and_lookup():
    engine = _engine()
    app = create_overlay_app(engine)
    client = TestClient(app)

    tx = _tx_one_output(b"viaweb")
    submit = client.post(
        "/submit",
        content=tx.to_beef(),
        headers={"x-topics": json.dumps(["tm_posts"])},
    )
    assert submit.status_code == 200
    assert submit.json()["tm_posts"]["outputsToAdmit"] == [0]

    lookup = client.post("/lookup", json={"service": "ls_posts", "query": {}})
    assert lookup.status_code == 200
    assert lookup.headers["content-type"].startswith("application/octet-stream")
    assert _parse_output_list_fixed(lookup.content)[0][0] == tx.txid()


# --- per-topic state root (matches overlay.peck.to /state) ---------------


def test_empty_state_root_matches_live_overlay():
    # overlay.peck.to GET /state returns this for a topic with count==0
    # (tm_peck-cat-funding), i.e. sha256("") — verified live 2026-06-02.
    from bsv_brc.overlay.topic_root import EMPTY_STATE_ROOT

    assert EMPTY_STATE_ROOT == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_state_root_matches_live_overlay_nonempty_vector():
    # A real cross-implementation vector captured from overlay.peck.to:
    # these were the 4 live tm_peck-bio-profile outpoints, and the overlay
    # published this exact stateRoot for that set (GET /state, 2026-06-02).
    # Our state_root reproduces it byte-for-byte — confirming the algorithm,
    # the "txid:vout" form, and the txid (display) orientation all match.
    from bsv_brc.overlay.topic_root import state_root

    outpoints = [
        "73aef9349d4261e59385ba2b2cc4024fe2cdcb6867466510fda7b824845d6c81:2",
        "79dbf52539937025a12d763f2c17b8e50a98e392a2b389112a9dca772c2548ba:2",
        "e7dad209a5db3b1f04882c777de024ad5272402921ddb10d302018e90002bfa7:1",
        "f2afde6b1c6f5849834a00325e43fd61d28b7e234a8a5853b810df3ed75d2b4f:0",
    ]
    assert state_root(outpoints) == (
        "b26b1c650c55fc800cca7c5ad9eac87fb58a98d56874383da10d1b87b16a1b94"
    )


def test_state_root_known_answer_and_dedupe():
    import hashlib

    from bsv_brc.overlay.topic_root import state_root

    expected = hashlib.sha256(b"a:0\nb:1").hexdigest()
    assert state_root(["b:1", "a:0"]) == expected  # sorted, joined with \n
    assert state_root(["a:0", "b:1", "a:0"]) == expected  # deduped


def test_outpoint_string_lowercases_txid():
    from bsv_brc.overlay.topic_root import outpoint_string

    assert outpoint_string("ABCD", 3) == "abcd:3"


@pytest.mark.asyncio
async def test_topic_root_empty_topic():
    from bsv_brc.overlay.topic_root import EMPTY_STATE_ROOT

    engine = _engine()
    assert engine.topic_root("tm_posts") == EMPTY_STATE_ROOT


@pytest.mark.asyncio
async def test_topic_root_single_output_matches_spec():
    import hashlib

    engine = _engine()
    tx = _tx_one_output(b"solo")
    await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    out = next(o for o in engine.storage.outputs("tm_posts"))
    expected = hashlib.sha256(
        f"{out.txid.lower()}:{out.output_index}".encode("utf-8")
    ).hexdigest()
    assert engine.topic_root("tm_posts") == expected


@pytest.mark.asyncio
async def test_topic_root_is_order_independent():
    txs = [_tx_one_output(m) for m in (b"a", b"bb", b"ccc")]

    e1 = _engine()
    for tx in txs:
        await e1.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))

    e2 = _engine()
    for tx in reversed(txs):
        await e2.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))

    assert e1.topic_root("tm_posts") == e2.topic_root("tm_posts")
    assert len(e1.topic_root("tm_posts")) == 64  # sha256 hex


@pytest.mark.asyncio
async def test_topic_root_changes_with_membership():
    engine = _engine()
    root0 = engine.topic_root("tm_posts")

    tx1 = _tx_one_output(b"one")
    await engine.submit(TaggedBEEF(beef=tx1.to_beef(), topics=["tm_posts"]))
    root1 = engine.topic_root("tm_posts")
    assert root1 != root0

    tx2 = Transaction()
    tx2.add_input(
        TransactionInput(
            source_transaction=tx1, source_txid=tx1.txid(), source_output_index=0
        )
    )
    tx2.add_output(TransactionOutput(locking_script=Script(b"\x6a\x02hi"), satoshis=1))
    await engine.submit(TaggedBEEF(beef=tx2.to_beef(), topics=["tm_posts"]))
    assert engine.topic_root("tm_posts") != root1


@pytest.mark.asyncio
async def test_topic_root_excludes_spent_outputs():
    class AdmitNoNewState(TopicManager):
        def __init__(self):
            self.calls = 0

        def identify_admissible_outputs(self, beef, previous_coins):
            self.calls += 1
            admit = [0] if self.calls == 1 else []
            return AdmittanceInstructions(outputs_to_admit=admit, coins_to_retain=[])

    from bsv_brc.overlay.topic_root import EMPTY_STATE_ROOT

    engine = OverlayEngine(topic_managers={"tm_posts": AdmitNoNewState()})
    tx1 = _tx_one_output(b"only")
    await engine.submit(TaggedBEEF(beef=tx1.to_beef(), topics=["tm_posts"]))
    assert engine.topic_root("tm_posts") != EMPTY_STATE_ROOT

    tx2 = Transaction()
    tx2.add_input(
        TransactionInput(
            source_transaction=tx1, source_txid=tx1.txid(), source_output_index=0
        )
    )
    tx2.add_output(TransactionOutput(locking_script=Script(b"\x6a\x01\x00"), satoshis=1))
    await engine.submit(TaggedBEEF(beef=tx2.to_beef(), topics=["tm_posts"]))
    assert engine.topic_root("tm_posts") == EMPTY_STATE_ROOT  # all spent


@pytest.mark.asyncio
async def test_topic_root_sqlite_matches_inmemory():
    txs = [_tx_one_output(m) for m in (b"x", b"yy", b"zzz", b"wwww")]
    mem = _engine()
    sql = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        lookup_services={"ls_posts": RecencyIndex("tm_posts")},
        storage=SqliteOverlayStorage(":memory:"),
    )
    for tx in txs:
        beef = tx.to_beef()
        await mem.submit(TaggedBEEF(beef=beef, topics=["tm_posts"]))
        await sql.submit(TaggedBEEF(beef=beef, topics=["tm_posts"]))
    assert mem.topic_root("tm_posts") == sql.topic_root("tm_posts")


@pytest.mark.asyncio
async def test_topic_roots_covers_all_hosted():
    engine = _engine()
    roots = engine.topic_roots()
    assert set(roots) == {"tm_posts"}
    assert all(len(r) == 64 for r in roots.values())


@pytest.mark.asyncio
async def test_topic_state_count_and_root():
    engine = _engine()
    assert engine.topic_state("tm_posts") == {
        "count": 0,
        "stateRoot": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    tx = _tx_one_output(b"one")
    await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    st = engine.topic_state("tm_posts")
    assert st["count"] == 1
    assert len(st["stateRoot"]) == 64


def test_state_endpoint_matches_live_overlay_shape():
    # GET /state -> {"status":"ok","topics":[{"topic","count","stateRoot"}]}
    engine = _engine()
    client = TestClient(create_overlay_app(engine))
    resp = client.get("/state")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["topics"] == [
        {
            "topic": "tm_posts",
            "count": 0,
            "stateRoot": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        }
    ]


@pytest.mark.asyncio
async def test_topic_root_unknown_topic_raises():
    engine = _engine()
    with pytest.raises(UnknownTopicError):
        engine.topic_root("tm_nope")


def test_lookup_unknown_service_is_400_over_http():
    app = create_overlay_app(_engine())
    client = TestClient(app)
    resp = client.post("/lookup", json={"service": "ls_nope", "query": {}})
    assert resp.status_code == 400


def test_lookup_does_not_leak_service_exception_text():
    class LeakyService(LookupService):
        def lookup(self, question):
            raise RuntimeError("/etc/secrets/key.pem not found")

    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        lookup_services={"ls_posts": LeakyService()},
    )
    client = TestClient(create_overlay_app(engine))
    resp = client.post("/lookup", json={"service": "ls_posts", "query": {}})
    assert resp.status_code == 400
    assert resp.json() == {"error": "lookup failed"}  # no path echoed


# --- concurrency: submit is atomic across an async manager's await -------


@pytest.mark.asyncio
async def test_concurrent_submits_with_async_manager_do_not_double_spend():
    import asyncio

    class AsyncAdmitRetain(TopicManager):
        async def identify_admissible_outputs(self, beef, previous_coins):
            await asyncio.sleep(0)  # the yield a real async manager introduces
            return AdmittanceInstructions(
                outputs_to_admit=[0], coins_to_retain=list(previous_coins)
            )

    index = RecencyIndex("tm_posts")
    engine = OverlayEngine(
        topic_managers={"tm_posts": AsyncAdmitRetain()},
        lookup_services={"ls_posts": index},
    )

    parent = _tx_one_output(b"parent")
    await engine.submit(TaggedBEEF(beef=parent.to_beef(), topics=["tm_posts"]))

    # Two children both spend parent:0, submitted concurrently.
    def child(marker: bytes) -> Transaction:
        tx = Transaction()
        tx.add_input(
            TransactionInput(
                source_transaction=parent,
                source_txid=parent.txid(),
                source_output_index=0,
            )
        )
        tx.add_output(
            TransactionOutput(
                locking_script=Script(b"\x6a" + bytes([len(marker)]) + marker),
                satoshis=1,
            )
        )
        return tx

    a, b = child(b"aa"), child(b"bb")
    await asyncio.gather(
        engine.submit(TaggedBEEF(beef=a.to_beef(), topics=["tm_posts"])),
        engine.submit(TaggedBEEF(beef=b.to_beef(), topics=["tm_posts"])),
    )

    # The submit lock serializes check-then-act: parent:0 is consumed
    # exactly once, so output_spent fired exactly once for it.
    assert index.spent.count((parent.txid(), 0)) == 1
    assert not engine.storage.is_unspent("tm_posts", parent.txid(), 0)


# --- BEEF-backed JSON answer (content negotiation) -----------------------


@pytest.mark.asyncio
async def test_engine_resolve_attaches_beef():
    engine = _engine()
    tx = _tx_one_output(b"withbeef")
    await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    refs = await engine.lookup(LookupQuestion(service="ls_posts", query={}))
    resolved = engine.resolve(refs)
    assert isinstance(resolved[0], ResolvedOutput)
    assert resolved[0].beef == tx.to_beef()


def test_output_list_to_json_includes_beef():
    out = output_list_to_json([ResolvedOutput("ab" * 32, 0, beef=b"\x01\x02", context=None)])
    assert out["outputs"][0]["beef"] == "AQI="  # base64 of \x01\x02


def test_lookup_json_is_beef_backed_with_accept_header():
    engine = _engine()
    tx = _tx_one_output(b"jsonpath")
    app = create_overlay_app(engine)
    client = TestClient(app)
    client.post(
        "/submit",
        content=tx.to_beef(),
        headers={"x-topics": json.dumps(["tm_posts"])},
    )
    resp = client.post(
        "/lookup",
        json={"service": "ls_posts", "query": {}},
        headers={"accept": "application/json"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    body = resp.json()
    assert body["type"] == "output-list"
    assert body["outputs"][0]["txid"] == tx.txid()
    # BEEF travels in the JSON answer (base64) — no second fetch needed.
    assert base64.b64decode(body["outputs"][0]["beef"]) == tx.to_beef()


# --- SqliteOverlayStorage ------------------------------------------------


def test_sqlite_storage_basic_roundtrip():
    s = SqliteOverlayStorage(":memory:")
    s.insert_output("tm_posts", "ab" * 32, 0, b"\x6a\x01\x00", 7)
    assert s.is_unspent("tm_posts", "ab" * 32, 0)
    s.put_beef("ab" * 32, b"beefbytes")
    assert s.get_beef("ab" * 32) == b"beefbytes"
    s.mark_spent("tm_posts", "ab" * 32, 0)
    assert not s.is_unspent("tm_posts", "ab" * 32, 0)
    rows = list(s.outputs("tm_posts"))
    assert len(rows) == 1 and rows[0].satoshis == 7 and rows[0].spent is True
    s.close()


@pytest.mark.asyncio
async def test_engine_end_to_end_over_sqlite():
    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        lookup_services={"ls_posts": RecencyIndex("tm_posts")},
        storage=SqliteOverlayStorage(":memory:"),
    )
    tx = _tx_one_output(b"persisted")
    await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    refs = await engine.lookup(LookupQuestion(service="ls_posts", query={}))
    assert refs[0].txid == tx.txid()
    # BEEF persisted and resolvable from SQLite.
    assert engine.resolve(refs)[0].beef == tx.to_beef()
    assert engine.storage.is_unspent("tm_posts", tx.txid(), 0)


# --- overlay CLIENT (consumer side) --------------------------------------


def _client_over(app) -> OverlayClient:
    """An OverlayClient whose transport drives an in-process Starlette app."""
    tc = TestClient(app)

    def fetch(method, url, headers, body):
        r = tc.request(method, url, content=body, headers=headers)
        return r.status_code, r.content

    return OverlayClient(host="", fetch=fetch)


# pure parsers


def test_build_submit_headers_uses_json_array_x_topics():
    h = build_submit_headers(["tm_a", "tm_b"])
    assert h["Content-Type"] == "application/octet-stream"
    assert json.loads(h["X-Topics"]) == ["tm_a", "tm_b"]


def test_parse_steak_and_admitted():
    steak = parse_steak({"tm_x": {"outputsToAdmit": [0, 2], "coinsToRetain": []}})
    assert steak["tm_x"].outputs_to_admit == [0, 2]
    empty = parse_steak({"tm_x": {"outputsToAdmit": [], "coinsToRetain": []}})
    assert empty["tm_x"].outputs_to_admit == []


def test_parse_lookup_answer_beef_int_array_and_atomic_txid():
    # overlay.peck.to returns beef as a byte array; AtomicBEEF prefix
    # 0x01010101 + 32-byte LE subject txid lets us recover the txid.
    txid = "ab" * 32
    atomic = [1, 1, 1, 1] + list(bytes.fromhex(txid)[::-1]) + [9, 9]
    outs = parse_lookup_answer({"outputs": [{"beef": atomic, "outputIndex": 3}]})
    assert outs[0].output_index == 3
    assert outs[0].txid == txid
    assert outs[0].beef[:4] == b"\x01\x01\x01\x01"


def test_parse_lookup_answer_beef_base64_and_explicit_txid():
    outs = parse_lookup_answer(
        {"outputs": [{"beef": base64.b64encode(b"xy").decode(), "outputIndex": 1, "txid": "cd" * 32}]}
    )
    assert outs[0].beef == b"xy"
    assert outs[0].txid == "cd" * 32


def test_parse_state():
    assert parse_state({"topics": [{"topic": "tm_x", "count": 2}]})[0]["topic"] == "tm_x"


# submit require_admission + HTTP errors via a fake transport


def test_submit_require_admission_raises_on_empty():
    def fetch(method, url, headers, body):
        return 200, json.dumps({"tm_x": {"outputsToAdmit": [], "coinsToRetain": []}}).encode()

    oc = OverlayClient(host="https://x", fetch=fetch)
    res = oc.submit(b"beef", ["tm_x"])
    assert res.admitted is False
    with pytest.raises(NoAdmissionError):
        oc.submit(b"beef", ["tm_x"], require_admission=True)


def test_client_raises_on_http_error():
    def fetch(method, url, headers, body):
        return 500, b"boom"

    with pytest.raises(OverlayHTTPError):
        OverlayClient(host="https://x", fetch=fetch).state()


# full in-process round trip against a real bsv-brc overlay node


def test_client_round_trip_submit_lookup_state_verify():
    engine = _engine()  # tm_posts admits [0], ls_posts indexes
    oc = _client_over(create_overlay_app(engine))

    tx = _tx_one_output(b"clientpost")
    res = oc.submit(tx.to_beef(), ["tm_posts"], require_admission=True)
    assert res.admitted
    assert res.steak["tm_posts"].outputs_to_admit == [0]

    outs = oc.lookup("ls_posts")
    assert len(outs) == 1
    assert outs[0].output_index == 0
    assert outs[0].txid == tx.txid()  # our server includes txid in the JSON
    assert outs[0].beef  # BEEF-backed

    state = oc.state()
    entry = next(e for e in state if e["topic"] == "tm_posts")
    assert entry["count"] == 1

    # client-side state-root verification against the node's published root
    assert oc.verify_state("tm_posts", [f"{tx.txid()}:0"]) is True
    assert oc.verify_state("tm_posts", ["deadbeef:0"]) is False


# --- SPV / verify_tx on submit -------------------------------------------


@pytest.mark.asyncio
async def test_verify_tx_rejects_when_false():
    from bsv_brc.overlay import SPVVerificationError

    seen = {}

    def verify(tx):
        seen["called"] = True
        return False

    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        verify_tx=verify,
    )
    tx = _tx_one_output(b"unverified")
    with pytest.raises(SPVVerificationError):
        await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    assert seen["called"]
    # rejected before admittance -> nothing stored
    assert not engine.storage.is_unspent("tm_posts", tx.txid(), 0)


@pytest.mark.asyncio
async def test_verify_tx_admits_when_true_and_receives_tx():
    captured = {}

    async def verify(tx):  # async verifier supported
        captured["txid"] = tx.txid()
        return True

    engine = OverlayEngine(
        topic_managers={"tm_posts": AdmitOutputZero()},
        lookup_services={"ls_posts": RecencyIndex("tm_posts")},
        verify_tx=verify,
    )
    tx = _tx_one_output(b"verified")
    steak = await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    assert steak["tm_posts"].outputs_to_admit == [0]
    assert captured["txid"] == tx.txid()


@pytest.mark.asyncio
async def test_no_verify_tx_keeps_default_trusting_behaviour():
    engine = _engine()  # no verify_tx
    tx = _tx_one_output(b"trusted")
    steak = await engine.submit(TaggedBEEF(beef=tx.to_beef(), topics=["tm_posts"]))
    assert steak["tm_posts"].outputs_to_admit == [0]
