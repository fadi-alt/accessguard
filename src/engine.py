"""AccessGuard detection engine.
Core idea: an access is justified if a CARE RELATIONSHIP exists. Accesses without one are
scored with transparent, weighted signals. The engine NEVER takes disruptive action:
it produces a ranked review queue and a human approves every action.
"""
import pandas as pd

ALLOWED = {
    "doctor": {"view_summary", "view_clinical_notes"},
    "nurse": {"view_summary", "view_clinical_notes"},
    "billing": {"view_billing"},
    "receptionist": {"view_summary"},
}
CLINICAL = {"doctor", "nurse"}

WEIGHTS = {
    "no_care_link": 40,       # no ward / care-team / referral justification
    "same_surname": 20,       # patient shares surname with staff (possible family)
    "vip_record": 20,         # restricted/VIP patient without care link
    "role_mismatch": 25,      # action not permitted for role (e.g. billing -> clinical notes, any export)
    "bulk_access": 30,        # >=10 unlinked patients within 10 minutes
    "new_device_or_loc": 35,  # device/location differs from the staff member's baseline
    "off_shift": 15,          # outside this person's own shift (per-user, not a global rule)
}
BREAK_GLASS_SCORE = 30        # allowed, never blocked, but queued for review after the emergency
ALERT_THRESHOLD = 50          # queue for human review
HIGH_THRESHOLD = 70
BULK_N = 10                   # unlinked patients inside the window that counts as bulk access

TITLES = {
    "no_care_link": "No care relationship",
    "same_surname": "Shared surname",
    "vip_record": "Restricted (VIP) record",
    "role_mismatch": "Role / action mismatch",
    "bulk_access": "Bulk access burst",
    "new_device_or_loc": "Unfamiliar device/location",
    "off_shift": "Outside own shift",
    "break_glass": "Emergency (break-glass)",
}
TEXT = {
    "no_care_link": "no active care relationship found (not their ward, care team or referral)",
    "same_surname": "patient shares the staff member's surname",
    "vip_record": "patient record is restricted (VIP)",
    "role_mismatch": "action '{action}' is not permitted for the role '{role}'",
    "bulk_access": "{n} records outside their care within 10 minutes",
    "new_device_or_loc": "unfamiliar device/location ({device} @ {location})",
    "off_shift": "access outside their normal shift",
    "break_glass": "emergency (break-glass) access - allowed, queued for after-the-fact review",
}


def _is_off_shift(ts, shift):
    night = ts.hour >= 20 or ts.hour < 7
    return night if shift == "day" else (not night)


def check_care_relationship(s, p, action):
    """Returns (linked, type, description) for staff row `s` and patient row `p`."""
    team = set(str(p.care_team).split(","))
    ok = action in ALLOWED[s.role]
    if s.staff_id in team:
        return True, "Care team member", "Staff member is on the patient's care team / referral."
    if s.role in CLINICAL:
        if p.ward == s.ward and ok:
            return True, "Same ward", f"Patient is admitted to the staff member's ward ({s.ward})."
        return False, "No care relationship", "Not their ward, not on the care team, no referral."
    if ok and not p.vip:
        return True, "Role-permitted admin access", "Permitted administrative action on a non-restricted record."
    return False, "No care relationship", "Action or record not covered by this role's administrative duties."


def priority_for(score, break_glass):
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= ALERT_THRESHOLD:
        return "medium"
    return "post-emergency review" if break_glass else "none"


def explain(role, staff_id, patient_id, action, score, priority, reasons):
    """Deterministic, template-based explanation (cannot invent facts). An optional LLM may
    rephrase this text but must only ever be given these de-identified facts."""
    if priority == "none":
        return "No concern: access is consistent with the care relationship."
    nxt = {"high": "Recommended: privacy officer reviews now and decides whether to suspend the session.",
           "medium": "Recommended: privacy officer reviews and decides to dismiss or escalate.",
           "post-emergency review": "Recommended: confirm the emergency was genuine."}[priority]
    return (f"{role.capitalize()} {staff_id} accessed patient {patient_id} ({action}). "
            f"Risk {int(score)}/100. Why: {'; '.join(reasons)}. {nxt}")


def evaluate_access(s, p, action, ts, device, location, break_glass=False, bulk_n=0):
    """Score ONE access. `bulk_n` = distinct unlinked patients this user touched in the last 10 min."""
    linked, link_type, link_desc = check_care_relationship(s, p, action)
    sig = {}
    if break_glass:
        sig["break_glass"] = BREAK_GLASS_SCORE
    elif not linked:
        sig["no_care_link"] = WEIGHTS["no_care_link"]
        if s.surname == p.surname:
            sig["same_surname"] = WEIGHTS["same_surname"]
        if p.vip:
            sig["vip_record"] = WEIGHTS["vip_record"]
    if action not in ALLOWED[s.role]:
        sig["role_mismatch"] = WEIGHTS["role_mismatch"]
    if not linked and not break_glass and bulk_n >= BULK_N:
        sig["bulk_access"] = WEIGHTS["bulk_access"]
    if device != s.home_device or location != s.home_loc:
        sig["new_device_or_loc"] = WEIGHTS["new_device_or_loc"]
    if not break_glass and _is_off_shift(ts, s.shift_type):
        sig["off_shift"] = WEIGHTS["off_shift"]
    score = min(100, sum(sig.values()))
    priority = priority_for(score, break_glass)
    reasons = [TEXT[k].format(action=action, role=s.role, n=bulk_n, device=device, location=location)
               for k in sig]
    breakdown = [dict(signal=k, title=TITLES[k], weight=w, description=r)
                 for (k, w), r in zip(sig.items(), reasons)]
    return dict(score=score, priority=priority, signals=",".join(sig), reasons=reasons,
                signals_breakdown=breakdown, linked=linked, link_type=link_type, link_desc=link_desc,
                explanation=explain(s.role, s.staff_id, p.patient_id, action, score, priority, reasons))


def score_custom_event(staff, patients, staff_id, patient_id, action, device=None, location=None,
                       break_glass=False, timestamp=None, bulk_n=0):
    s = staff.set_index("staff_id").loc[staff_id].copy(); s["staff_id"] = staff_id
    p = patients.set_index("patient_id").loc[patient_id].copy(); p["patient_id"] = patient_id
    ts = timestamp if timestamp is not None else pd.Timestamp("2026-01-12 11:00:00")
    return evaluate_access(s, p, action, ts, device or s.home_device, location or s.home_loc,
                           break_glass, bulk_n)


def score_events(staff, patients, events, window_min=10):
    st = staff.set_index("staff_id")
    pt = patients.set_index("patient_id")
    events = events.sort_values("timestamp", kind="stable").reset_index(drop=True)
    recent = {}   # staff_id -> [(ts, patient_id)] of unlinked accesses
    rows = []
    for e in events.itertuples():
        s = st.loc[e.staff_id].copy(); s["staff_id"] = e.staff_id
        p = pt.loc[e.patient_id].copy(); p["patient_id"] = e.patient_id
        bulk_n = 0
        linked, _, _ = check_care_relationship(s, p, e.action)
        if not linked and not e.break_glass:
            q = [(t, pid) for t, pid in recent.get(e.staff_id, [])
                 if (e.timestamp - t).total_seconds() <= window_min * 60]
            q.append((e.timestamp, e.patient_id))
            recent[e.staff_id] = q
            bulk_n = len({pid for _, pid in q})
        r = evaluate_access(s, p, e.action, e.timestamp, e.device, e.location, bool(e.break_glass), bulk_n)
        rows.append(dict(event_id=e.event_id, timestamp=e.timestamp, staff_id=e.staff_id, staff=s["name"],
                         role=s.role, patient_id=e.patient_id, action=e.action,
                         is_break_glass=bool(e.break_glass), **r))
    out = pd.DataFrame(rows)
    out["alert"] = out.priority.isin(["medium", "high"])
    return out
