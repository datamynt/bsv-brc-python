"""Tests for the BRC-22 topic submission engine and /submit adapter."""

from __future__ import annotations

import json

import pytest
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.testclient import TestClient

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions, TaggedBEEF
from bsv.script.script import Script
from bsv.transaction import Transaction, TransactionOutput

from bsv_brc.brc22 import TopicEngine, TopicManager, UnknownTopicError
from starlette.routing import Route

from bsv_brc.brc22.adapters.asgi import (
    OFF_CHAIN_HEADER,
    SubmitASGIApp,
    TOPICS_HEADER,
    instructions_to_dict,
    make_submit_route,
    parse_submit_body,
    steak_to_dict,
)


# --- fixtures ------------------------------------------------------------


def _make_beef(marker: bytes = b"hello") -> bytes:
    """Build a one-output transaction and return its BEEF bytes."""
    tx = Transaction()
    tx.add_output(
        TransactionOutput(
            locking_script=Script(b"\x6a" + bytes([len(marker)]) + marker),
            satoshis=0,
        )
    )
    return tx.to_beef()


class AdmitAllManager(TopicManager):
    """Admits output 0 of every submission (sync)."""

    def identify_admissible_outputs(self, beef, previous_coins):
        return AdmittanceInstructions(outputs_to_admit=[0], coins_to_retain=[])


class AsyncAdmitNoneManager(TopicManager):
    """Admits nothing (async, to exercise the await path)."""

    async def identify_admissible_outputs(self, beef, previous_coins):
        return AdmittanceInstructions(outputs_to_admit=[], coins_to_retain=[])


# --- engine --------------------------------------------------------------


def test_engine_requires_a_manager():
    with pytest.raises(ValueError):
        TopicEngine({})


@pytest.mark.asyncio
async def test_engine_admits_via_sync_manager():
    engine = TopicEngine({"tm_demo": AdmitAllManager()})
    steak = await engine.submit(TaggedBEEF(beef=_make_beef(), topics=["tm_demo"]))
    assert steak["tm_demo"].outputs_to_admit == [0]


@pytest.mark.asyncio
async def test_engine_awaits_async_manager():
    engine = TopicEngine({"tm_demo": AsyncAdmitNoneManager()})
    steak = await engine.submit(TaggedBEEF(beef=_make_beef(), topics=["tm_demo"]))
    assert steak["tm_demo"].outputs_to_admit == []


@pytest.mark.asyncio
async def test_engine_ignores_unhosted_topics_but_processes_hosted():
    engine = TopicEngine({"tm_demo": AdmitAllManager()})
    steak = await engine.submit(
        TaggedBEEF(beef=_make_beef(), topics=["tm_demo", "tm_other"])
    )
    assert set(steak) == {"tm_demo"}


@pytest.mark.asyncio
async def test_engine_raises_when_no_topic_hosted():
    engine = TopicEngine({"tm_demo": AdmitAllManager()})
    with pytest.raises(UnknownTopicError):
        await engine.submit(TaggedBEEF(beef=_make_beef(), topics=["tm_nope"]))


@pytest.mark.asyncio
async def test_previous_coins_resolver_is_passed_through():
    seen = {}

    class RetainManager(TopicManager):
        def identify_admissible_outputs(self, beef, previous_coins):
            seen["previous_coins"] = previous_coins
            return AdmittanceInstructions(
                outputs_to_admit=[0], coins_to_retain=previous_coins
            )

    engine = TopicEngine(
        {"tm_demo": RetainManager()},
        get_previous_coins=lambda topic, tx: [3, 7],
    )
    steak = await engine.submit(TaggedBEEF(beef=_make_beef(), topics=["tm_demo"]))
    assert seen["previous_coins"] == [3, 7]
    assert steak["tm_demo"].coins_to_retain == [3, 7]


@pytest.mark.asyncio
async def test_on_admit_callback_fires_only_on_admission():
    calls = []

    engine = TopicEngine(
        {"tm_admit": AdmitAllManager(), "tm_none": AsyncAdmitNoneManager()},
        on_admit=lambda topic, txid, ai, tx: calls.append((topic, txid)),
    )
    await engine.submit(
        TaggedBEEF(beef=_make_beef(), topics=["tm_admit", "tm_none"])
    )
    assert len(calls) == 1
    assert calls[0][0] == "tm_admit"
    assert len(calls[0][1]) == 64  # txid hex


# --- serialization -------------------------------------------------------


def test_instructions_to_dict_omits_coins_removed_when_none():
    d = instructions_to_dict(
        AdmittanceInstructions(outputs_to_admit=[1], coins_to_retain=[2])
    )
    assert d == {"outputsToAdmit": [1], "coinsToRetain": [2]}


def test_instructions_to_dict_includes_coins_removed_when_set():
    d = instructions_to_dict(
        AdmittanceInstructions(
            outputs_to_admit=[1], coins_to_retain=[], coins_removed=[5]
        )
    )
    assert d["coinsRemoved"] == [5]


def test_steak_to_dict():
    steak = {"tm_demo": AdmittanceInstructions(outputs_to_admit=[0], coins_to_retain=[])}
    assert steak_to_dict(steak) == {
        "tm_demo": {"outputsToAdmit": [0], "coinsToRetain": []}
    }


# --- off-chain framing ---------------------------------------------------


def test_parse_submit_body_plain():
    beef = _make_beef()
    parsed_beef, off_chain = parse_submit_body(beef, includes_off_chain=False)
    assert parsed_beef == beef
    assert off_chain is None


def test_parse_submit_body_with_off_chain():
    beef = _make_beef()
    off = b"\x01\x02\x03"
    framed = bytes([len(beef)]) + beef + off  # len(beef)=33 fits in one varint byte
    parsed_beef, parsed_off = parse_submit_body(framed, includes_off_chain=True)
    assert parsed_beef == beef
    assert parsed_off == off


def test_parse_submit_body_rejects_overlong_length():
    # 0xfd => next 2 bytes are the length: 0xffff = 65535, far longer than body
    with pytest.raises(ValueError):
        parse_submit_body(b"\xfd\xff\xff", includes_off_chain=True)


# --- ASGI adapter --------------------------------------------------------


def _make_client(engine: TopicEngine) -> TestClient:
    app = Starlette(routes=[Mount("/submit", app=SubmitASGIApp(engine))])
    return TestClient(app)


def test_submit_endpoint_returns_steak():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={
            TOPICS_HEADER: json.dumps(["tm_demo"]),
            "content-type": "application/octet-stream",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"tm_demo": {"outputsToAdmit": [0], "coinsToRetain": []}}


def test_submit_endpoint_rejects_get():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.get("/submit")
    assert resp.status_code == 405


def test_submit_endpoint_requires_topics_header():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post("/submit", content=_make_beef())
    assert resp.status_code == 400
    assert "x-topics" in resp.json()["error"].lower()


def test_submit_endpoint_unknown_topic_is_400():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: json.dumps(["tm_nope"])},
    )
    assert resp.status_code == 400


def test_submit_endpoint_off_chain_framing():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    beef = _make_beef()
    off = b"\x09\x08"
    framed = bytes([len(beef)]) + beef + off
    resp = client.post(
        "/submit",
        content=framed,
        headers={
            TOPICS_HEADER: json.dumps(["tm_demo"]),
            OFF_CHAIN_HEADER: "true",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["tm_demo"]["outputsToAdmit"] == [0]


def test_submit_endpoint_malformed_beef_is_400():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=b"not-a-beef",
        headers={TOPICS_HEADER: json.dumps(["tm_demo"])},
    )
    assert resp.status_code == 400


# --- X-Topics wire formats (py-sdk sends comma-separated, not JSON) ------


def test_submit_accepts_comma_separated_topics_like_py_sdk():
    # py-sdk's TopicBroadcaster sends `",".join(topics)`, NOT a JSON array.
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: "tm_demo"},  # bare comma-format, single topic
    )
    assert resp.status_code == 200
    assert resp.json()["tm_demo"]["outputsToAdmit"] == [0]


def test_submit_accepts_multi_comma_separated_topics():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: "tm_other, tm_demo"},  # whitespace + comma
    )
    assert resp.status_code == 200
    assert set(resp.json()) == {"tm_demo"}


def test_submit_still_accepts_json_array_topics():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: json.dumps(["tm_demo"])},
    )
    assert resp.status_code == 200


def test_parse_topics_header_formats():
    from bsv_brc.brc22.adapters.asgi import parse_topics_header

    assert parse_topics_header("tm_a") == ["tm_a"]
    assert parse_topics_header("tm_a,tm_b") == ["tm_a", "tm_b"]
    assert parse_topics_header(" tm_a , tm_b ") == ["tm_a", "tm_b"]
    assert parse_topics_header('["tm_a","tm_b"]') == ["tm_a", "tm_b"]
    assert parse_topics_header('["tm_a", 5]') is None  # non-string member


def test_submit_rejects_too_many_topics():
    from bsv_brc.brc22.adapters.asgi import MAX_TOPICS

    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: ",".join(f"tm_{i}" for i in range(MAX_TOPICS + 1))},
    )
    assert resp.status_code == 400
    assert "too many topics" in resp.json()["error"]


# --- error hygiene + body cap --------------------------------------------


def test_submit_does_not_leak_manager_exception_text():
    class LeakyManager(TopicManager):
        def identify_admissible_outputs(self, beef, previous_coins):
            raise RuntimeError("connection to postgres://user:pass@10.0.0.5 failed")

    client = _make_client(TopicEngine({"tm_demo": LeakyManager()}))
    resp = client.post(
        "/submit", content=_make_beef(), headers={TOPICS_HEADER: "tm_demo"}
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "submission failed"}  # no DSN echoed


def test_submit_unknown_topic_error_does_not_echo_full_list():
    client = _make_client(TopicEngine({"tm_demo": AdmitAllManager()}))
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: "tm_nope1,tm_nope2,tm_nope3"},
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert "tm_nope1" not in err  # requested list not echoed
    assert "3 requested topics" in err


def test_submit_body_cap_returns_413():
    from bsv_brc.brc22.adapters.asgi import SubmitASGIApp
    from starlette.routing import Mount

    app = Starlette(
        routes=[
            Mount(
                "/submit",
                app=SubmitASGIApp(
                    TopicEngine({"tm_demo": AdmitAllManager()}), max_body_bytes=64
                ),
            )
        ]
    )
    client = TestClient(app)
    resp = client.post(
        "/submit",
        content=b"x" * 200,  # over the 64-byte cap
        headers={TOPICS_HEADER: "tm_demo"},
    )
    assert resp.status_code == 413


# --- Starlette Route helper (no trailing-slash redirect) -----------------


def test_make_submit_route_returns_route():
    route = make_submit_route(TopicEngine({"tm_demo": AdmitAllManager()}))
    assert isinstance(route, Route)
    assert route.path == "/submit"


def test_submit_route_processes_without_redirect():
    engine = TopicEngine({"tm_demo": AdmitAllManager()})
    app = Starlette(routes=[make_submit_route(engine)])
    # follow_redirects=False proves the POST hits /submit directly (no 307).
    client = TestClient(app)
    resp = client.post(
        "/submit",
        content=_make_beef(),
        headers={TOPICS_HEADER: json.dumps(["tm_demo"])},
        follow_redirects=False,
    )
    assert resp.status_code == 200
    assert resp.json() == {"tm_demo": {"outputsToAdmit": [0], "coinsToRetain": []}}
