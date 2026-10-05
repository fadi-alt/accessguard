"""Synthetic hospital + EHR access-log generator.
ALL DATA IS FAKE. No real patient or staff information is used.
Injects 5 labelled attack scenarios plus tricky *legitimate* cases
(break-glass emergencies, referrals, night shifts) so false positives are testable.
"""
import random
from datetime import datetime, timedelta
import pandas as pd

SURNAMES = ["Nair", "Menon", "Pillai", "Kurup", "Varma", "Iyer", "Das", "Khan",
            "Thomas", "Mathew", "Joseph", "George", "Sharma", "Reddy", "Rao"]
FIRST = ["Anu", "Ravi", "Sita", "Arun", "Maya", "Kiran", "Leela", "Vijay", "Divya",
         "Hari", "Nisha", "Rohan", "Fathima", "Joby", "Tara", "Sanjay"]
WARDS = ["ICU", "Cardiology", "Maternity", "Ortho", "General", "Paediatrics"]
CLINICAL = ["doctor", "nurse"]
ACTIONS_BY_ROLE = {
    "doctor": ["view_summary", "view_clinical_notes"],
    "nurse": ["view_summary", "view_clinical_notes"],
    "billing": ["view_billing"],
    "receptionist": ["view_summary"],
}
START = datetime(2026, 1, 5, 0, 0)


def build_world(seed=42, n_staff=40, n_patients=200):
    rng = random.Random(seed)
    staff = []
    for i in range(n_staff):
        role = rng.choices(["doctor", "nurse", "billing", "receptionist"], [8, 20, 6, 6])[0]
        sn = rng.choice(SURNAMES)
        staff.append(dict(staff_id=f"S{i:03d}", name=f"{rng.choice(FIRST)} {sn}", surname=sn, role=role,
                          ward=rng.choice(WARDS) if role in CLINICAL else "Admin",
                          shift_type=rng.choice(["day", "day", "night"]) if role in CLINICAL else "day",
                          home_device=f"WS-{rng.randint(100, 999)}", home_loc="Hospital-LAN"))
    staff = pd.DataFrame(staff)
    clinical = staff[staff.role.isin(CLINICAL)]
    patients = []
    for i in range(n_patients):
        ward = rng.choice(WARDS)
        pool = clinical[clinical.ward == ward].staff_id.tolist()
        team = rng.sample(pool, min(len(pool), rng.randint(1, 3))) if pool else []
        sn = rng.choice(SURNAMES)
        patients.append(dict(patient_id=f"P{i:04d}", name=f"{rng.choice(FIRST)} {sn}", surname=sn,
                             ward=ward, vip=(i % 40 == 0), care_team=",".join(team)))
    return rng, staff, pd.DataFrame(patients)


def _ts(rng, day, shift):
    hour = rng.randint(8, 19) if shift == "day" else rng.choice(list(range(20, 24)) + list(range(0, 7)))
    return START + timedelta(days=day, hours=hour, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))


def _pick(rng, df):
    return df.iloc[rng.randrange(len(df))]


def generate(seed=42, days=7, normal_per_staff_day=12):
    rng, staff, patients = build_world(seed)
    ev = []

    def add(ts, s, p, action, device=None, loc=None, bg=False, label="normal"):
        ev.append(dict(timestamp=ts, staff_id=s.staff_id, patient_id=p.patient_id, action=action,
                       device=device or s.home_device, location=loc or s.home_loc, break_glass=bg,
                       label=label, malicious=not (label == "normal" or label.startswith("legit_"))))

    # ---- legitimate traffic ----
    for _, s in staff.iterrows():
        if s.role in CLINICAL:
            mine = patients[(patients.ward == s.ward) | patients.care_team.str.contains(s.staff_id)]
        else:
            mine = patients[~patients.vip]   # VIP records are restricted for admin roles
        if mine.empty:
            mine = patients
        for d in range(days):
            for _ in range(rng.randint(normal_per_staff_day - 4, normal_per_staff_day)):
                add(_ts(rng, d, s.shift_type), s, _pick(rng, mine), rng.choice(ACTIONS_BY_ROLE[s.role]))

    nurses = staff[staff.role == "nurse"]
    doctors = staff[staff.role == "doctor"]

    # ---- tricky LEGITIMATE cases (must NOT be treated as attacks) ----
    for _ in range(25):   # break-glass emergency outside own ward
        s = _pick(rng, nurses)
        add(_ts(rng, rng.randrange(days), s.shift_type), s, _pick(rng, patients[patients.ward != s.ward]),
            "view_summary", bg=True, label="legit_break_glass")
    for _ in range(15):   # doctor consulting on a referral (added to care team)
        s = _pick(rng, doctors)
        p = _pick(rng, patients[patients.ward != s.ward])
        patients.loc[patients.patient_id == p.patient_id, "care_team"] += "," + s.staff_id
        add(_ts(rng, rng.randrange(days), s.shift_type), s, p, "view_clinical_notes", label="legit_referral")

    for _ in range(40):   # nurse covering a colleague's ward (no formal care link, no break-glass)
        s = _pick(rng, nurses)
        add(_ts(rng, rng.randrange(days), s.shift_type), s, _pick(rng, patients[(patients.ward != s.ward) & (~patients.vip)]),
            "view_summary", label="legit_shift_cover")

    # ---- ATTACK 1: family snooping ----
    for _ in range(14):
        s = _pick(rng, nurses)
        cand = patients[(patients.surname == s.surname) & (patients.ward != s.ward)]
        if cand.empty:
            continue
        add(_ts(rng, rng.randrange(days), "day"), s, _pick(rng, cand), "view_clinical_notes", label="family_snooping")

    # ---- ATTACK 2: VIP snooping ----
    vips = patients[patients.vip]
    for _ in range(14):
        s = _pick(rng, staff[staff.role.isin(["nurse", "receptionist"])])
        cand = vips[vips.ward != s.ward]
        add(_ts(rng, rng.randrange(days), "day"), s, _pick(rng, cand), "view_summary", label="vip_snooping")

    # ---- ATTACK 3: bulk theft (30 exports in ~7 minutes) ----
    for _ in range(3):
        s = _pick(rng, nurses)
        t0 = _ts(rng, rng.randrange(days), "day")
        for j, pid in enumerate(rng.sample(range(len(patients)), 30)):
            add(t0 + timedelta(seconds=j * 15), s, patients.iloc[pid], "export_record", label="bulk_theft")

    # ---- ATTACK 4: credential compromise (new device, external, 3am) ----
    for _ in range(3):
        s = _pick(rng, staff)
        t0 = START + timedelta(days=rng.randrange(days), hours=3, minutes=rng.randint(0, 40))
        for j, pid in enumerate(rng.sample(range(len(patients)), 8)):
            add(t0 + timedelta(seconds=j * 40), s, patients.iloc[pid], "view_clinical_notes",
                device=f"UNKNOWN-{rng.randint(1000, 9999)}", loc="Ext-IP-VPN", label="credential_compromise")

    # ---- ATTACK 5: role abuse (billing clerk reads clinical notes) ----
    for _ in range(14):
        s = _pick(rng, staff[staff.role == "billing"])
        add(_ts(rng, rng.randrange(days), "day"), s, _pick(rng, patients), "view_clinical_notes", label="role_abuse")

    # ---- ATTACK 6 (known blind spot): low-and-slow snooping on in-ward patients ----
    for _ in range(10):
        s = _pick(rng, nurses)
        cand = patients[(patients.ward == s.ward) & (~patients.vip) &
                        (~patients.care_team.str.contains(s.staff_id))]
        if cand.empty:
            continue
        add(_ts(rng, rng.randrange(days), s.shift_type), s, _pick(rng, cand), "view_clinical_notes",
            label="low_slow_in_ward")

    events = pd.DataFrame(ev).sort_values("timestamp", kind="stable").reset_index(drop=True)
    events.insert(0, "event_id", [f"E{i:06d}" for i in range(len(events))])
    return staff, patients, events


if __name__ == "__main__":
    staff, patients, events = generate()
    staff.to_csv("data/staff.csv", index=False)
    patients.to_csv("data/patients.csv", index=False)
    events.to_csv("data/events.csv", index=False)
    print(len(events), "events;", int(events.malicious.sum()), "malicious")
    print(events.label.value_counts().to_string())
