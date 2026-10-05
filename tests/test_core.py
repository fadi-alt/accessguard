import os, tempfile
from src.generator import generate
from src.engine import score_events, score_custom_event
from src.cases import build_cases
from src.scenarios import SCENARIOS, build
from src import audit, patient

_cache = {}


def _data():
    if "d" not in _cache:
        s, p, e = generate(7)
        r = score_events(s, p, e).merge(e[["event_id", "label", "malicious"]], on="event_id")
        _cache["d"] = (s, p, e, r)
    return _cache["d"]


def test_break_glass_allowed_and_queued_for_review():
    s, p, e, r = _data()
    bg = r[r.is_break_glass]
    assert len(bg) > 0 and not bg.alert.any()
    assert (bg.priority == "post-emergency review").all()


def test_referral_is_linked():
    s, p, e, r = _data()
    assert not r[r.label == "legit_referral"].alert.any()


def test_core_attacks_detected():
    s, p, e, r = _data()
    for label in ["family_snooping", "vip_snooping", "role_abuse"]:
        assert r[r.label == label].alert.mean() > 0.9, label


def test_known_blind_spot_is_documented_not_hidden():
    s, p, e, r = _data()
    assert r[r.label == "low_slow_in_ward"].alert.mean() == 0.0   # README lists this limitation


def test_explanations_contain_ids_not_names():
    s, p, e, r = _data()
    text = r.explanation.str.cat()
    assert not any(n in text for n in list(p.name)[:60] + list(s.name)[:40])


def test_cases_group_bulk_theft():
    s, p, e, r = _data()
    cases, flagged = build_cases(r)
    bulk = cases[cases.label == "bulk_theft"]
    assert 1 <= len(bulk) <= 4 and bulk.n_events.max() >= 20     # ~30 rows collapse into one case
    alert_cases = cases[cases.priority != "post-emergency review"]
    assert len(alert_cases) < r.alert.sum() / 2      # fewer cases than flagged rows (emergency reviews excluded)


def test_simulator_presets_behave_as_documented():
    s, p, e, r = _data()
    expected = {"vip": "medium", "cred": "high", "family": "medium", "role": "medium", "bulk": "high",
                "glass": "post-emergency review", "referral": "none", "slow": "none"}
    for sc in SCENARIOS:
        kw = build(sc["key"], s, p)
        pts = kw.pop("patients")
        res = score_custom_event(s, pts, **kw)
        assert res["priority"] == expected[sc["key"]], (sc["key"], res["score"], res["priority"])


def test_audit_chain_detects_tampering_and_tamper_test_is_non_destructive():
    path = os.path.join(tempfile.mkdtemp(), "a.jsonl")
    for i, d in enumerate(["approve", "dismiss", "escalate"]):
        audit.append(f"C{i}", "officer", d, path=path)
    before = open(path).read()
    ok, bad, _ = audit.tamper_test(path)
    assert not ok and bad is not None                 # tampered COPY is caught
    assert open(path).read() == before and audit.verify(path)   # real file untouched
    open(path, "w").write(before.replace("dismiss", "approve"))
    assert not audit.verify(path)


def test_patient_view_uses_role_and_id_only():
    s, p, e, r = _data()
    pid = e.patient_id.value_counts().index[0]
    h = patient.access_history(e, s, r, pid)
    assert h.who.str.match(r"^(Doctor|Nurse|Billing|Receptionist) S\d{3}$").all()
    path = os.path.join(tempfile.mkdtemp(), "fb.jsonl")
    patient.add_feedback(pid, h.event_id.iloc[0], False, path)
    assert len(patient.load_feedback(path)) == 1


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("PASS", name)
