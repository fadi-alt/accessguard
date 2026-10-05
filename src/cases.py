"""Group individual flagged accesses into reviewable CASES (one bulk theft = one case, not 30 rows)."""
import pandas as pd
from .engine import TITLES

RANK = {"high": 0, "medium": 1, "post-emergency review": 2}


def group_events(df, gap_min=30):
    """Case index per row: same staff member, gap between accesses <= gap_min minutes."""
    d = df.sort_values(["staff_id", "timestamp"], kind="stable")
    gap = d.groupby("staff_id").timestamp.diff().dt.total_seconds().div(60)
    new = gap.isna() | (gap > gap_min)
    return new.cumsum().reindex(df.index)


def build_cases(scored, gap_min=30):
    q = scored[scored.priority.isin(RANK)].copy()
    if q.empty:
        return pd.DataFrame(columns=["case_id"]), q
    q["case_n"] = group_events(q, gap_min)
    rows = []
    for n, g in q.groupby("case_n"):
        best = g.sort_values("score", ascending=False).iloc[0]
        sigs = pd.Series([x for s in g.signals for x in s.split(",") if x]).value_counts()
        mins = max(1, round((g.timestamp.max() - g.timestamp.min()).total_seconds() / 60))
        names = ", ".join(TITLES[k] for k in sigs.index[:3]) or "none"
        pr = min(g.priority, key=RANK.get)
        row = dict(case_n=n, staff_id=best.staff_id, role=best.role, start=g.timestamp.min(),
                   end=g.timestamp.max(), n_events=len(g), n_patients=g.patient_id.nunique(),
                   max_score=int(g.score.max()), priority=pr, signals=",".join(sigs.index),
                   event_ids=list(g.event_id), top_event_id=best.event_id,
                   summary=(f"{best.role.capitalize()} {best.staff_id}: {len(g)} flagged access(es) to "
                            f"{g.patient_id.nunique()} patient(s) over {mins} min. Main signals: {names}."))
        if "malicious" in g:
            row["malicious"] = bool(g.malicious.any())
            row["label"] = (g[g.malicious].label if g.malicious.any() else g.label).mode().iloc[0]
        rows.append(row)
    cases = pd.DataFrame(rows).sort_values("start", kind="stable").reset_index(drop=True)
    cases.insert(0, "case_id", [f"C{i + 1:04d}" for i in range(len(cases))])
    cases["rank"] = cases.priority.map(RANK)
    cases = cases.sort_values(["rank", "max_score"], ascending=[True, False]).drop(columns="rank")
    return cases.reset_index(drop=True), q
