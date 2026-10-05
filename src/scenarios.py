"""Preset scenarios for the live simulator. Each builds a concrete (staff, patient) pair from the data."""
import pandas as pd

TS_DAY = pd.Timestamp("2026-01-12 11:30:00")
TS_NIGHT = pd.Timestamp("2026-01-12 03:15:00")

SCENARIOS = [
    dict(key="vip", title="VIP patient snooping", icon="👑",
         desc="Receptionist opens a restricted VIP record with no care relationship.",
         expect="medium/high alert"),
    dict(key="cred", title="Credential theft at 3 AM", icon="🔓",
         desc="Day-shift doctor's account used from an unknown device over an external VPN at 03:15.",
         expect="high alert"),
    dict(key="family", title="Family snooping", icon="👪",
         desc="Nurse opens the chart of a same-surname patient admitted to another ward.",
         expect="medium alert"),
    dict(key="role", title="Billing role abuse", icon="💼",
         desc="Billing clerk tries to read clinical notes.", expect="medium alert"),
    dict(key="bulk", title="Bulk export burst", icon="📦",
         desc="Nurse exports records of 12 unrelated patients within minutes.", expect="high alert"),
    dict(key="glass", title="Legit break-glass emergency", icon="🚨",
         desc="Nurse opens an unassigned patient using emergency override.",
         expect="ALLOWED - queued for post-emergency review"),
    dict(key="referral", title="Authorised referral", icon="🤝",
         desc="Doctor added to another ward patient's care team for a consult.",
         expect="no alert (care link found)"),
    dict(key="slow", title="Low-and-slow in-ward snooping", icon="🕳️",
         desc="Nurse reads an in-ward patient she is not treating. KNOWN BLIND SPOT.",
         expect="NOT detected (documented limitation)"),
]


def build(key, staff, patients):
    """Returns dict(staff_id, patient_id, action, device, location, break_glass, timestamp, bulk_n, patients)."""
    pts = patients.copy()
    base = dict(device=None, location=None, break_glass=False, timestamp=TS_DAY, bulk_n=0)

    def first(df):
        return df.iloc[0]

    if key == "vip":
        s = first(staff[staff.role == "receptionist"])
        p = first(pts[pts.vip])
        return dict(base, staff_id=s.staff_id, patient_id=p.patient_id, action="view_summary", patients=pts)
    if key == "cred":
        s = first(staff[(staff.role == "doctor") & (staff.shift_type == "day")])
        p = first(pts[(pts.ward != s.ward) & (~pts.vip)])
        return dict(base, staff_id=s.staff_id, patient_id=p.patient_id, action="view_clinical_notes",
                    device="UNKNOWN-LAPTOP-4821", location="Ext-IP-VPN", timestamp=TS_NIGHT, patients=pts)
    if key == "family":
        for _, s in staff[(staff.role == "nurse") & (staff.shift_type == "day")].iterrows():
            c = pts[(pts.surname == s.surname) & (pts.ward != s.ward) & (~pts.vip)]
            if not c.empty:
                return dict(base, staff_id=s.staff_id, patient_id=first(c).patient_id,
                            action="view_clinical_notes", patients=pts)
        raise ValueError("no same-surname pair in this dataset")
    if key == "role":
        s = first(staff[staff.role == "billing"])
        return dict(base, staff_id=s.staff_id, patient_id=first(pts[~pts.vip]).patient_id,
                    action="view_clinical_notes", patients=pts)
    if key == "bulk":
        s = first(staff[(staff.role == "nurse") & (staff.shift_type == "day")])
        p = first(pts[(pts.ward != s.ward) & (~pts.vip)])
        return dict(base, staff_id=s.staff_id, patient_id=p.patient_id, action="export_record",
                    bulk_n=12, patients=pts)
    if key == "glass":
        s = first(staff[(staff.role == "nurse") & (staff.shift_type == "day")])
        p = first(pts[(pts.ward != s.ward) & (~pts.vip)])
        return dict(base, staff_id=s.staff_id, patient_id=p.patient_id, action="view_summary",
                    break_glass=True, patients=pts)
    if key == "referral":
        s = first(staff[(staff.role == "doctor") & (staff.shift_type == "day")])
        p = first(pts[(pts.ward != s.ward) & (~pts.vip)])
        pts.loc[pts.patient_id == p.patient_id, "care_team"] += "," + s.staff_id
        return dict(base, staff_id=s.staff_id, patient_id=p.patient_id, action="view_clinical_notes",
                    patients=pts)
    if key == "slow":
        for _, s in staff[(staff.role == "nurse") & (staff.shift_type == "day")].iterrows():
            c = pts[(pts.ward == s.ward) & (~pts.vip) & (~pts.care_team.fillna("").str.contains(s.staff_id))]
            if not c.empty:
                return dict(base, staff_id=s.staff_id, patient_id=first(c).patient_id,
                            action="view_clinical_notes", patients=pts)
        raise ValueError("no in-ward candidate")
    raise KeyError(key)
