"""Patient transparency: 'who viewed my record' + feedback loop. Staff are shown as role + ID only."""
import json, os
import pandas as pd

FEEDBACK = os.environ.get("PATIENT_FEEDBACK", "data/patient_feedback.jsonl")


def access_history(events, staff, scored, patient_id):
    e = events[events.patient_id == patient_id].merge(
        staff[["staff_id", "role", "ward"]], on="staff_id", how="left")
    e = e.merge(scored[["event_id", "score", "priority"]], on="event_id", how="left")
    e["who"] = e.role.str.capitalize() + " " + e.staff_id
    return e.sort_values("timestamp")[["event_id", "timestamp", "who", "ward", "action", "break_glass",
                                      "score", "priority"]].reset_index(drop=True)


def add_feedback(patient_id, event_id, expected, path=None):
    path = path or FEEDBACK
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(dict(patient_id=patient_id, event_id=event_id, expected=bool(expected))) + "\n")


def load_feedback(path=None):
    path = path or FEEDBACK
    if not os.path.exists(path):
        return pd.DataFrame(columns=["patient_id", "event_id", "expected"])
    return pd.read_json(path, lines=True)
