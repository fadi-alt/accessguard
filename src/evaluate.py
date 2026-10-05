"""Compare AccessGuard against a naive rule-based baseline on labelled synthetic data."""
import json
import pandas as pd
from .generator import generate
from .engine import score_events
from .cases import group_events


def baseline_flags(events):
    """Typical rule-based flagging: any after-hours access OR >20 records/hour per user."""
    ev = events.copy()
    ev["hour"] = ev.timestamp.dt.floor("h")
    per_hour = ev.groupby(["staff_id", "hour"]).event_id.transform("count")
    after_hours = (ev.timestamp.dt.hour >= 20) | (ev.timestamp.dt.hour < 7)
    return (after_hours | (per_hour > 20)).values


def metrics(y_true, y_pred):
    tp = int((y_true & y_pred).sum()); fp = int((~y_true & y_pred).sum())
    fn = int((y_true & ~y_pred).sum()); tn = int((~y_true & ~y_pred).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return dict(alerts=tp + fp, true_alerts=tp, false_alerts=fp, missed=fn,
                precision=round(prec, 3), recall=round(rec, 3),
                false_positive_rate=round(fp / (fp + tn), 4) if fp + tn else 0.0)


def incident_recall(events, flagged):
    m = events[events.malicious].copy()
    m["flag"] = flagged[events.malicious.values]
    m["day"] = m.timestamp.dt.date
    g = m.groupby(["label", "staff_id", "day"]).flag.any()
    return round(float(g.mean()), 3), g.groupby(level=0).mean().round(3).to_dict()


def case_stats(df, flags):
    """Reviewer workload: number of cases and share of cases containing a real attack."""
    f = df[flags].copy()
    if f.empty:
        return dict(cases=0, case_precision=0.0)
    f["case_n"] = group_events(f)
    g = f.groupby("case_n").malicious.any()
    return dict(cases=int(len(g)), case_precision=round(float(g.mean()), 3))


def run(seed=42):
    staff, patients, events = generate(seed)
    scored = score_events(staff, patients, events)
    scored = scored.set_index('event_id').loc[events.event_id].reset_index()
    y = events.malicious.values
    ag = scored.alert.values
    bl = baseline_flags(events)
    inc_ag, per_ag = incident_recall(events, ag)
    ev_recall = {l: round(float(ag[(events.label == l).values].mean()), 3)
                 for l in sorted(events[events.malicious].label.unique())}
    inc_bl, _ = incident_recall(events, bl)
    res = dict(seed=seed, events=len(events), malicious_events=int(y.sum()),
               accessguard=metrics(y, ag), baseline=metrics(y, bl),
               incident_recall_accessguard=inc_ag, incident_recall_baseline=inc_bl,
               incident_recall_by_scenario=per_ag, event_recall_by_scenario=ev_recall,
               review_workload=dict(accessguard=case_stats(events, ag), baseline=case_stats(events, bl)))
    res["false_alert_reduction_pct"] = round(
        100 * (1 - res["accessguard"]["false_alerts"] / max(1, res["baseline"]["false_alerts"])), 1)
    return res


def run_many(seeds=range(1, 6)):
    rows = []
    for sd in seeds:
        r = run(sd)
        rows.append(dict(seed=sd, ag_precision=r["accessguard"]["precision"], ag_recall=r["accessguard"]["recall"],
                         ag_false_alerts=r["accessguard"]["false_alerts"],
                         bl_precision=r["baseline"]["precision"], bl_recall=r["baseline"]["recall"],
                         bl_false_alerts=r["baseline"]["false_alerts"],
                         ag_incident_recall=r["incident_recall_accessguard"]))
    return pd.DataFrame(rows)


if __name__ == "__main__":
    import sys, os
    res = run(int(sys.argv[1]) if len(sys.argv) > 1 else 42)
    os.makedirs("docs", exist_ok=True)
    json.dump(res, open("docs/results.json", "w"), indent=2)
    print(json.dumps(res, indent=2))
