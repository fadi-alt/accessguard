"""AccessGuard - privacy officer review console (Streamlit).  Run: streamlit run app.py
All data is synthetic. Security actions are SIMULATED and always require human approval."""
import pandas as pd
import streamlit as st

from src.generator import generate
from src.engine import score_events, score_custom_event, check_care_relationship, TITLES
from src.cases import build_cases
from src.scenarios import SCENARIOS, build as build_scenario
from src.evaluate import run as run_eval, run_many
from src import audit, patient as pat

st.set_page_config(page_title="AccessGuard", page_icon="🛡️", layout="wide")


@st.cache_data
def load(seed=42):
    staff, patients, events = generate(seed)
    scored = score_events(staff, patients, events).merge(
        events[["event_id", "label", "malicious", "device", "location"]], on="event_id")
    cases, flagged = build_cases(scored)
    return staff, patients, events, scored, cases


@st.cache_data
def get_eval(seed=42):
    return run_eval(seed)


@st.cache_data
def get_multi():
    return run_many(range(1, 6))


staff, patients, events, scored, cases = load()
ev = get_eval()
PRIOS = ["high", "medium", "post-emergency review"]
BADGE = {"high": "🔴 HIGH", "medium": "🟠 MEDIUM", "post-emergency review": "🔵 POST-EMERGENCY REVIEW",
         "none": "🟢 NO CONCERN"}

with st.sidebar:
    st.markdown("### 🛡️ AccessGuard")
    reviewer = st.text_input("Privacy officer ID", "officer_01")
    demo = st.toggle("Demo mode (show ground-truth labels)", False)
    st.markdown("**Break-glass (emergency) access is never blocked.** It is allowed, logged, and reviewed afterwards.")
    ok, bad, msg = audit.verify_detailed()
    (st.success if ok else st.error)(f"Audit chain: {'intact' if ok else 'BROKEN at #' + str(bad)}")
    if st.button("Load labelled demo decisions"):
        audit.seed_demo(); st.rerun()
    st.caption("ASTRA 2026 - Cyber in Healthcare | Track 4: Identity + Human Security | Synthetic data only")

st.title("🛡️ AccessGuard - Insider Access Monitoring")
st.caption("Care-relationship-aware detection of unjustified patient-record access. "
           "Nothing is blocked automatically: every action needs human approval.")

t_queue, t_sim, t_eval, t_audit, t_patient, t_safety = st.tabs(
    ["🚨 Review queue", "🧪 Live simulator", "📊 Evaluation", "🔐 Audit trail", "👤 Patient view", "🏥 Safety & limits"])

# ============================ REVIEW QUEUE ============================
with t_queue:
    decided = {e["event_id"] for e in audit.load()}
    n_alert_events = int(scored.alert.sum())
    open_cases = cases[~cases.case_id.isin(decided)]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Open cases", len(open_cases))
    c2.metric("High priority", int((open_cases.priority == "high").sum()))
    c3.metric("Post-emergency reviews", int((open_cases.priority == "post-emergency review").sum()))
    c4.metric("Flagged accesses → cases", f"{n_alert_events} → {int(cases[cases.priority != 'post-emergency review'].shape[0])}",
              help="Flagged accesses are grouped per staff member (30-min gap) so reviewers triage cases, not rows.")

    f1, f2, f3 = st.columns([2, 1, 1])
    pri = f1.multiselect("Priority", PRIOS, ["high", "medium"])
    hide = f2.checkbox("Hide resolved", True)
    q = f3.text_input("Search staff/case ID")
    view = cases[cases.priority.isin(pri)]
    if hide:
        view = view[~view.case_id.isin(decided)]
    if q:
        view = view[view.staff_id.str.contains(q.upper()) | view.case_id.str.contains(q.upper())]
    cols = ["case_id", "start", "staff_id", "role", "n_events", "n_patients", "max_score", "priority", "summary"]
    st.dataframe(view[cols + (["label"] if demo else [])], use_container_width=True, hide_index=True, height=250)

    if view.empty:
        st.info("No open cases match the filters.")
    else:
        cid = st.selectbox("Open a case", view.case_id.tolist())
        case = view[view.case_id == cid].iloc[0]
        top = scored[scored.event_id == case.top_event_id].iloc[0]
        s = staff[staff.staff_id == case.staff_id].iloc[0]
        st.markdown(f"#### {BADGE[case.priority]} · Case {cid} · risk {case.max_score}/100")
        st.progress(min(1.0, case.max_score / 100))
        st.info(case.summary)
        d1, d2 = st.columns(2)
        with d1:
            st.markdown("**Staff member**")
            st.write(f"{s.role.capitalize()} {s.staff_id} · ward {s.ward} · {s.shift_type} shift · "
                     f"usual device {s.home_device} @ {s.home_loc}")
        with d2:
            st.markdown("**Most serious access in this case**")
            st.write(top.explanation)
        st.markdown("**Why (transparent signal weights)**")
        st.table(pd.DataFrame(top.signals_breakdown)[["title", "weight", "description"]]
                 .rename(columns={"title": "Signal", "weight": "Points", "description": "Detail"}))
        with st.expander(f"All {case.n_events} flagged accesses in this case"):
            st.dataframe(scored[scored.event_id.isin(case.event_ids)][
                ["event_id", "timestamp", "patient_id", "action", "score", "signals"]],
                use_container_width=True, hide_index=True)

        st.markdown("##### ⚖️ Human decision (recorded in the hash-chained audit log)")
        note = st.text_input("Reviewer note", key=f"note_{cid}")
        if case.priority == "post-emergency review":
            b = st.columns(2)
            acts = [("✅ Confirm genuine emergency", "confirm_emergency"), ("⬆️ Escalate", "escalate")]
        else:
            b = st.columns(4)
            acts = [("🛑 Approve: suspend session (simulated)", "approve_suspend_session_SIMULATED"),
                    ("📋 Request justification", "request_justification"),
                    ("⬆️ Escalate to compliance", "escalate"), ("❎ Dismiss", "dismiss")]
        for col, (label, code) in zip(b, acts):
            if col.button(label, key=f"{code}_{cid}", use_container_width=True):
                audit.append(cid, reviewer, code, note)
                st.toast(f"{code} recorded for {cid}")
                st.rerun()

    with st.expander("Patient-reported unexpected accesses (feedback loop)"):
        fb = pat.load_feedback()
        bad = fb[~fb.expected] if len(fb) else fb
        if bad.empty:
            st.write("No patient reports yet. Use the **Patient view** tab.")
        else:
            m = bad.merge(scored[["event_id", "score", "priority", "staff_id"]], on="event_id", how="left")
            st.dataframe(m, use_container_width=True, hide_index=True)
            st.caption(f"{int((m.priority.isin(['high', 'medium'])).sum())} of {len(m)} patient-reported accesses were "
                       "also flagged by the engine; the rest are candidates to tune the model.")

# ============================ SIMULATOR ============================
with t_sim:
    st.markdown("Pick a scenario and see exactly how AccessGuard scores it. One scenario is a **known blind spot**.")
    cols = st.columns(4)
    for i, sc in enumerate(SCENARIOS):
        with cols[i % 4]:
            st.markdown(f"**{sc['icon']} {sc['title']}**")
            st.caption(f"{sc['desc']}  \n*Expected: {sc['expect']}*")
            if st.button("Run", key=f"run_{sc['key']}", use_container_width=True):
                kw = build_scenario(sc["key"], staff, patients)
                pts = kw.pop("patients")
                res = score_custom_event(staff, pts, **kw)
                st.session_state["sim"] = dict(title=sc["title"], res=res, kw=kw)
    with st.expander("🛠️ Custom access builder"):
        a, b, c = st.columns(3)
        sid = a.selectbox("Staff", staff.staff_id.tolist(),
                          format_func=lambda x: f"{x} · {staff.set_index('staff_id').loc[x, 'role']} · "
                                                f"{staff.set_index('staff_id').loc[x, 'ward']}")
        pid = b.selectbox("Patient", patients.patient_id.tolist(),
                          format_func=lambda x: f"{x} · {patients.set_index('patient_id').loc[x, 'ward']}"
                                                f"{' · VIP' if patients.set_index('patient_id').loc[x, 'vip'] else ''}")
        act = c.selectbox("Action", ["view_summary", "view_clinical_notes", "view_billing", "export_record"])
        d, e_, f_ = st.columns(3)
        odd_dev = d.checkbox("Unfamiliar device")
        odd_loc = e_.checkbox("External network")
        glass = f_.checkbox("Break-glass emergency")
        night = st.checkbox("At 03:00")
        if st.button("Evaluate custom access", type="primary"):
            res = score_custom_event(
                staff, patients, sid, pid, act,
                device="UNKNOWN-DEVICE-9999" if odd_dev else None,
                location="Ext-IP-VPN" if odd_loc else None, break_glass=glass,
                timestamp=pd.Timestamp("2026-01-12 03:00:00" if night else "2026-01-12 11:00:00"))
            st.session_state["sim"] = dict(title="Custom access", res=res, kw={})
    if "sim" in st.session_state:
        r = st.session_state["sim"]["res"]
        st.markdown("---")
        st.markdown(f"### Result: {st.session_state['sim']['title']}")
        x, y = st.columns([1, 2])
        x.metric("Risk score", f"{r['score']} / 100")
        x.markdown(f"**{BADGE[r['priority']]}**")
        y.info(r["explanation"])
        y.caption(f"Care link: {r['link_type']} - {r['link_desc']}")
        if r["signals_breakdown"]:
            st.table(pd.DataFrame(r["signals_breakdown"])[["title", "weight", "description"]]
                     .rename(columns={"title": "Signal", "weight": "Points", "description": "Detail"}))
        if st.session_state["sim"]["title"].startswith("Low-and-slow"):
            st.warning("Known limitation: access inside the user's own ward looks legitimate to a care-link "
                       "check. Detecting it needs longer-term per-user behaviour baselines (future scope).")

# ============================ EVALUATION ============================
with t_eval:
    a, b = ev["accessguard"], ev["baseline"]
    st.markdown("Labelled **synthetic** attacks and tricky legitimate cases (night shifts, break-glass, shift cover). "
                "Baseline = common rule: *flag after-hours access or >20 records/hour*.")
    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Precision", a["precision"], f"baseline {b['precision']}", delta_color="off")
    k2.metric("Recall (events)", a["recall"], f"baseline {b['recall']}", delta_color="off")
    k3.metric("False alerts", a["false_alerts"], f"baseline {b['false_alerts']}", delta_color="off")
    w = ev["review_workload"]
    k4.metric("Reviewer cases", w["accessguard"]["cases"], f"baseline {w['baseline']['cases']}", delta_color="off")
    st.table(pd.DataFrame({"AccessGuard": a, "Naive rule baseline": b}))
    st.markdown(f"**Incident-level recall** (an attack counts as caught if at least one event is flagged): "
                f"AccessGuard **{ev['incident_recall_accessguard']}** vs baseline **{ev['incident_recall_baseline']}**. "
                f"False alerts reduced by **{ev['false_alert_reduction_pct']}%**. "
                f"Case precision: **{w['accessguard']['case_precision']}** vs **{w['baseline']['case_precision']}**.")
    st.markdown("##### Detection by scenario")
    sc_df = pd.DataFrame({"Event recall": ev["event_recall_by_scenario"],
                          "Incident recall": ev["incident_recall_by_scenario"]})
    st.bar_chart(sc_df)
    st.table(sc_df)
    st.warning("Known misses: `low_slow_in_ward` (0%) is a deliberate blind spot, and some credential-theft events "
               "target night-shift staff so the off-shift signal does not fire. Results use synthetic data we "
               "designed: they prove the concept, not real-world accuracy.")
    if st.button("Run multi-seed check (seeds 1-5)"):
        m = get_multi()
        st.dataframe(m, hide_index=True, use_container_width=True)
        st.caption("Mean AccessGuard precision "
                   f"{m.ag_precision.mean():.2f}, recall {m.ag_recall.mean():.2f}; baseline precision "
                   f"{m.bl_precision.mean():.2f}, recall {m.bl_recall.mean():.2f}.")

# ============================ AUDIT ============================
with t_audit:
    st.markdown("Every human decision is appended to a **SHA-256 hash chain** "
                "(`hash = SHA256(previous_hash + entry)`). Editing or deleting an entry breaks the chain.")
    ok, bad, msg = audit.verify_detailed()
    (st.success if ok else st.error)(msg)
    st.code(f"Chain head (anchor this externally in production): {audit.head()}")
    st.caption("A hash chain is tamper-EVIDENT, not a digital signature: someone who can rewrite the whole file can "
               "recompute every hash, which is why the head hash should be stored in a separate system.")
    if st.button("🧪 Run non-destructive tamper test"):
        t = audit.tamper_test()
        if t is None:
            st.info("Need at least 2 entries. Make decisions, or use 'Load labelled demo decisions' in the sidebar.")
        else:
            st.error(f"Edited a copy of the log → detected: {t[2]} (your real log was not modified).")
    entries = audit.load()
    if entries:
        df = pd.DataFrame(entries)
        df.insert(0, "block", range(len(df)))
        df["prev"] = df.prev.str[:12] + "…"; df["hash"] = df.hash.str[:12] + "…"
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Export audit log (JSONL)", "\n".join(__import__("json").dumps(e) for e in entries),
                           "accessguard_audit_log.jsonl")
    else:
        st.info("No decisions recorded yet.")

# ============================ PATIENT VIEW ============================
with t_patient:
    st.markdown("Transparency for patients: **who viewed my record?** Staff appear as role + ID only. "
                "Patient answers become labelled feedback for the privacy team.")
    counts = events.patient_id.value_counts()
    pid = st.selectbox("Patient (synthetic)", counts.index.tolist()[:60],
                       format_func=lambda x: f"{x} ({counts[x]} accesses)")
    hist = pat.access_history(events, staff, scored, pid)
    st.dataframe(hist.drop(columns=["score", "priority"]), use_container_width=True, hide_index=True)
    eid = st.selectbox("Pick an access to give feedback on", hist.event_id.tolist())
    y, n = st.columns(2)
    if y.button("✅ Yes, this was expected", use_container_width=True):
        pat.add_feedback(pid, eid, True); st.toast("Feedback saved")
    if n.button("❓ No, I did not expect this", use_container_width=True):
        pat.add_feedback(pid, eid, False); st.toast("Reported to the privacy team")

# ============================ SAFETY ============================
with t_safety:
    st.markdown("""
### Patient safety first
Blocking an emergency clinician can harm a patient. So AccessGuard **never blocks break-glass access**: it is allowed
instantly, logged, and queued for a human to confirm afterwards. Every other consequential action (suspending a session,
escalating) needs explicit approval from a privacy officer.

### What the AI/detector does and does not do
- **Does:** scores each access using a care-relationship check plus 7 transparent weighted signals, and explains why.
- **Data used:** access logs, ward/care-team/referral data, role permissions (all synthetic here).
- **When uncertain:** mid-score events go to a lower-priority queue. Nothing is ever actioned automatically.
- **False positives:** staff covering another ward, or a coincidental shared surname → human review dismisses them.
- **False negatives:** slow snooping inside the user's own ward (0% in our test), and attackers working inside a
  night-shift user's hours.
- **Output is a risk indicator, not a verdict.**

### Assumptions and limitations
- Metrics come from synthetic data we designed. Real hospitals have messier care data.
- Detection quality depends on accurate ward / care-team / referral records.
- Suspension is simulated; there is no real EHR integration.
- A malicious break-glass abuse is caught only by the after-the-fact review.
- The audit log is tamper-evident, not tamper-proof (see Audit tab).

### Regulatory fit (supports, not certifies)
Access accountability and audit controls are expected by HIPAA (US) and are relevant to India's DPDP Act 2023 and
ABDM health-data rules. This prototype supports those goals; it is not a compliance certification.

```
Synthetic EHR access log → Engine (care link + signals) → Cases → Privacy officer review → Hash-chained audit log
                                                              ↑ patient feedback ("was this expected?")
```
""")
