"""Tamper-EVIDENT audit log: each entry stores the hash of the previous entry (hash chain).
Every human decision is recorded here. NOTE: a hash chain detects edits to part of the log; it is not
a digital signature. An attacker who can rewrite the WHOLE file could recompute every hash, so in
production the latest hash (head) should be anchored externally (separate system / WORM storage)."""
import copy, hashlib, json, os
from datetime import datetime

PATH = os.environ.get("AUDIT_LOG", "data/audit_log.jsonl")
FIELDS = ("time", "event_id", "reviewer", "decision", "note")


def _hash(prev, body):
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()


def load(path=None):
    path = path or PATH
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]


def append(event_id, reviewer, decision, note="", path=None):
    path = path or PATH
    entries = load(path)
    prev = entries[-1]["hash"] if entries else "GENESIS"
    body = dict(time=datetime.now().isoformat(timespec="seconds"), event_id=event_id,
                reviewer=reviewer, decision=decision, note=note)
    entry = dict(body, prev=prev, hash=_hash(prev, body))
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify_entries(entries):
    """Returns (ok, index_of_first_bad_block_or_None, message)."""
    prev = "GENESIS"
    for i, e in enumerate(entries):
        body = {k: e[k] for k in FIELDS}
        if e["prev"] != prev or e["hash"] != _hash(prev, body):
            return False, i, f"Chain broken at block #{i}."
        prev = e["hash"]
    return True, None, f"All {len(entries)} block(s) verified."


def verify(path=None):
    return verify_entries(load(path))[0]


def verify_detailed(path=None):
    return verify_entries(load(path))


def head(path=None):
    e = load(path)
    return e[-1]["hash"] if e else "GENESIS"


def tamper_test(path=None):
    """NON-DESTRUCTIVE demo: edit a decision in an in-memory COPY and show the chain catches it.
    The real log file is never modified."""
    entries = copy.deepcopy(load(path))
    if len(entries) < 2:
        return None
    entries[len(entries) // 2]["decision"] = "dismiss"
    entries[len(entries) // 2]["note"] = "(edited by attacker)"
    return verify_entries(entries)


def seed_demo(path=None):
    """Explicitly-labelled demo entries (reviewer='demo_seed') so the audit view is not empty."""
    for cid, dec in [("DEMO-1", "dismiss"), ("DEMO-2", "request_justification"), ("DEMO-3", "escalate")]:
        append(cid, "demo_seed", dec, "demo seed data", path)
