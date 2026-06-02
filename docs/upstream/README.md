# Upstream py-sdk bug reports

Ready-to-file issues for [`bsv-blockchain/py-sdk`](https://github.com/bsv-blockchain/py-sdk)
(`bsv-sdk` on PyPI), found while building bsv-brc on top of it.

| Report | Status |
|--------|--------|
| [LookupResolver binary parser crash](pysdk-lookup-resolver-read-var-int.md) | Confirmed in 2.0.0b1, latest PyPI 2.1.3, and `master` HEAD. **Filed: [bsv-blockchain/py-sdk#158](https://github.com/bsv-blockchain/py-sdk/issues/158)**. |
| [internalize_action mis-parses AtomicBEEF](pysdk-internalize-action-beef.md) | Confirmed in 2.0.0b1, latest PyPI 2.1.3, and `master` HEAD (byte-identical). **Filed: [bsv-blockchain/py-sdk#159](https://github.com/bsv-blockchain/py-sdk/issues/159)**. |

Both bugs persist at the latest release and at HEAD, so **bumping our pin does
not fix them** — they need upstream fixes. We deliberately work around both in
bsv-brc (see `brc24/wire.py` for the binary lookup format we emit, and
`integration.make_internalize_verifier`'s docstring warning).

Separately: our pin `bsv-sdk==2.0.0b1` (beta, 2026-01-20) is stale vs the
latest stable **2.1.3** (2026-05-20). Worth bumping on its own merits, but
verify the test suite stays green first — the bumps above are unrelated to
these two defects.
