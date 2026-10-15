"""DurableLedger.append must be atomic as a whole under concurrency.

Before: only the in-memory append was locked. The ledger line write,
fsync and ledger.head rewrite ran unlocked, so concurrent appenders
collided on ledger.head.tmp (FileNotFoundError from os.rename), wrote
lines out of seq order, and could commit a head ahead of the file;
reloading then failed with "sequence gap" or "ledger truncated".
"""

import json
import threading

from permit.durability import DurableLedger

THREADS = 4
PER_THREAD = 25
TRIALS = 5


def _hammer(d):
    ledger = DurableLedger(d)
    errors = []

    def work(tag):
        for i in range(PER_THREAD):
            try:
                ledger.append("EVT", {"t": tag, "i": i})
            except Exception as e:  # noqa: BLE001 - the test counts them
                errors.append(repr(e))

    threads = [threading.Thread(target=work, args=(k,)) for k in range(THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ledger.close()
    return errors


def test_concurrent_appends_are_durable_in_order_and_reload(tmp_path):
    want = THREADS * PER_THREAD
    for trial in range(TRIALS):
        d = tmp_path / f"t{trial}"
        errors = _hammer(d)
        assert errors == [], errors[:3]

        lines = (d / "ledger.jsonl").read_text().splitlines()
        assert [json.loads(x)["seq"] for x in lines] == list(range(want))
        head = json.loads((d / "ledger.head").read_text())
        assert head["len"] == want and head["seq"] == want - 1
        assert not (d / "ledger.head.tmp").exists()

        reloaded = DurableLedger(d)
        try:
            ok, reason = reloaded.verify_chain()
            assert ok, reason
            assert len(reloaded.receipts()) == want
            assert reloaded.tip() == head
        finally:
            reloaded.close()


def test_head_matches_file_after_each_sequential_append(tmp_path):
    ledger = DurableLedger(tmp_path)
    try:
        for i in range(5):
            r = ledger.append("EVT", {"i": i})
            head = json.loads((tmp_path / "ledger.head").read_text())
            assert head == {"len": i + 1, "seq": r.seq, "hash": r.hash}
            assert head == ledger.tip()
    finally:
        ledger.close()
