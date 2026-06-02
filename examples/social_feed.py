"""
A minimal social feed on an overlay — the seed of an open-source peck.to.

This is a complete, runnable overlay node that hosts one social topic:

- Topic manager ``tm_posts`` admits any output that carries a post
  (an ``OP_RETURN`` with a small JSON ``{"text": ...}`` payload).
- Lookup service ``ls_posts`` indexes admitted posts and answers
  ``{"limit": N}`` queries newest-first, returning each post's JSON in
  the output ``context`` so a client gets content without a second fetch.
- ``POST /submit`` accepts new posts, ``POST /lookup`` serves the feed
  (binary BRC-24 output-list, or a BEEF-backed JSON answer if the client
  sends ``Accept: application/json``), and ``GET /feed`` renders HTML.

For a persistent node, pass ``storage=SqliteOverlayStorage("feed.db")``
to ``OverlayEngine``.

Anyone can point a py-sdk ``TopicBroadcaster`` at ``/submit`` to post, or
a ``LookupResolver`` at ``/lookup`` to read — or run their own node with
the same two classes. That is the whole point: the protocol is the API.

Run:
    pip install "bsv-brc[starlette]" uvicorn
    python examples/social_feed.py
    # then POST a post, or open http://127.0.0.1:8000/feed

What a real deployment adds (out of scope here, all supported by the
stack): wrap the app with bsv_brc.build_brc_app for BRC-103/104 identity
+ BRC-105 paid posting, advertise the topic over SHIP/SLAP so others
discover it, and persist with a SQLite/Postgres OverlayStorage.
"""

from __future__ import annotations

import json
from typing import Optional

from starlette.responses import HTMLResponse
from starlette.routing import Route

from bsv.overlay_tools.ship_broadcaster import AdmittanceInstructions
from bsv.transaction import Transaction

from bsv_brc.brc22 import TopicManager
from bsv_brc.brc24 import LookupService, OutputRef
from bsv_brc.overlay import OverlayEngine
from bsv_brc.overlay.adapters.asgi import create_overlay_app

POSTS_TOPIC = "tm_posts"
POSTS_SERVICE = "ls_posts"


def _decode_post(locking_script: bytes) -> Optional[dict]:
    """Return the post payload if a locking script is `OP_RETURN <json>`.

    Layout: 0x6a (OP_RETURN) then a single pushdata of JSON bytes. This
    keeps the example self-contained; a real app would use the Bitcoin
    Schema / MAP protocol and parse it the same way.
    """
    if not locking_script or locking_script[0] != 0x6A:
        return None
    rest = locking_script[1:]
    if not rest:
        return None
    length = rest[0]  # small pushdata (< 76 bytes) — enough for the demo
    payload = rest[1 : 1 + length]
    try:
        data = json.loads(payload.decode("utf-8"))
        return data if isinstance(data, dict) and "text" in data else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


class PostsTopic(TopicManager):
    """Admit every output that parses as a post."""

    def identify_admissible_outputs(self, beef: bytes, previous_coins):
        tx = Transaction.from_beef(beef)
        admit = [
            i
            for i, out in enumerate(tx.outputs)
            if _decode_post(bytes.fromhex(out.locking_script.hex())) is not None
        ]
        return AdmittanceInstructions(outputs_to_admit=admit, coins_to_retain=[])

    def get_documentation(self) -> str:
        return "tm_posts — admits OP_RETURN outputs carrying {\"text\": ...}."


class PostsIndex(LookupService):
    """Index posts newest-first; carry the post JSON in `context`."""

    def __init__(self) -> None:
        self._posts: list[OutputRef] = []

    def output_admitted(self, topic, txid, output_index, locking_script, satoshis):
        if topic != POSTS_TOPIC:
            return
        post = _decode_post(locking_script)
        if post is None:
            return
        context = json.dumps(post, separators=(",", ":")).encode("utf-8")
        self._posts.insert(0, OutputRef(txid, output_index, context=context))

    def lookup(self, question):
        limit = (question.query or {}).get("limit", 20)
        return self._posts[:limit]

    def get_documentation(self) -> str:
        return "ls_posts — newest-first feed; query {\"limit\": N}."


engine = OverlayEngine(
    topic_managers={POSTS_TOPIC: PostsTopic()},
    lookup_services={POSTS_SERVICE: PostsIndex()},
)


async def feed(_request) -> HTMLResponse:
    """A tiny human-readable view of the indexed posts."""
    index: PostsIndex = engine.lookup_services[POSTS_SERVICE]  # type: ignore[assignment]
    rows = []
    for ref in index._posts[:50]:
        text = json.loads(ref.context.decode("utf-8")).get("text", "")
        rows.append(f"<li><code>{ref.txid[:12]}…:{ref.output_index}</code> — {text}</li>")
    body = "<ul>" + "".join(rows) + "</ul>" if rows else "<p>No posts yet.</p>"
    return HTMLResponse(f"<h1>overlay feed — {POSTS_TOPIC}</h1>{body}")


app = create_overlay_app(
    engine,
    extra_routes=[Route("/feed", feed, methods=["GET"])],
)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
