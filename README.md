# 🛡️ AccessGuard
**Care-relationship-aware insider-snooping detection for hospital records, with human-in-the-loop review.**
**Live demo:** https://accessguard-astra.streamlit.app/

| | |
|---|---|
| **Team** | _<fill in>_ |
| **Track** | 4 - Identity + Human Security (also touches 5 - Data, Privacy + Trust) |
| **Challenge number & title** | _<fill in from the official list>_ |
| **License** | MIT |
| **GitHub collaborator** | _https://github.com/kmctcoecybersecurity-stack_ |

## 1. Healthcare problem
Hospital staff can open thousands of patient records. Curiosity snooping (relatives, VIPs), data theft and stolen
credentials often go unnoticed for months. Manual audits don't scale, and simple rules ("flag after-hours access")
bury real abuse under false alarms, because nurses legitimately work nights.

**Chain:** unjustified record access → insider misuse / credential compromise / bulk theft → AccessGuard →
working prototype → patient outcome (privacy protected, abuse surfaced for review quickly, emergency care never delayed).

## 2. Solution
An access is **justified** if a **care relationship** exists (same ward, care team, referral). Accesses without one are
scored with 7 transparent weighted signals, grouped into **cases**, and sent to a privacy officer with a plain-language
explanation. **Nothing is blocked automatically:** `Alert → Risk score → Human review → Approve/Dismiss/Escalate → Audit log`.

**Patient-safety rule:** emergency (break-glass) access is **never blocked**. It is allowed, logged, and queued for
after-the-fact review.

## 3. Features
- Care-relationship check + 7 transparent signals (no black box): no care link 40, unfamiliar device/location 35,
  bulk burst 30, role mismatch 25, VIP record 20, shared surname 20, outside own shift 15.
- **Cases, not rows:** one bulk theft = one case. (148 flagged accesses → 51 cases on the demo data.)
- **Live simulator:** 8 preset scenarios (including a *known miss*) plus a custom access builder.
- **Per-user shift baseline:** night-shift staff are not flagged just for working nights.
- Deterministic template explanations (no generative model, so no invented facts).
- **Hash-chained audit log** of every human decision, with a non-destructive tamper test.
- **Patient view:** "who viewed my record" (role + ID only) with a "was this expected?" feedback loop.
- Evaluation against a naive rule baseline, computed live (nothing hard-coded).

## 4. Architecture
```
Synthetic EHR access log ─► Engine (care link + 7 signals + score) ─► Cases ─► Privacy-officer review (Streamlit)
(6 attack types + legit edge cases)                                              │ human decision      ▲ patient feedback
                                                                                 ▼                     │
                                                                    Hash-chained audit log      Patient view
```

## 5. Technology stack & disclosures
Python 3, pandas (BSD), numpy (BSD), Streamlit (Apache-2.0). Standard-library `hashlib` for the hash chain.
**No external AI/LLM model is used** (rule-based scoring + template explanations). AI coding assistants were used
during development: _<list the tools your team actually used>_.

## 6. Setup
```bash
git clone <repo-url> && cd accessguard
pip install -r requirements.txt
python -m src.generator        # synthetic data -> data/
python -m src.evaluate         # metrics -> docs/results.json
python -m tests.test_core      # 9 tests
python -m tests.smoke_ui       # runs the whole UI script headlessly
streamlit run app.py           # review console
```

## 7. Demo (5 minutes)
1. **Problem (30s).** Insider snooping goes unnoticed; "after-hours" rules drown reviewers.
2. **Review queue (90s).** Open a high-priority bulk-theft case → explanation + signal weights → *Approve (simulated)* → entry appears in the audit log.
3. **Simulator (90s).** Run *VIP snooping* (flagged), *Break-glass* (allowed, queued for review), *Low-and-slow* (missed: say so openly).
4. **Evaluation (60s).** Precision, workload and false alerts vs the baseline; point out the limits.
5. **Safety & future (30s).** Synthetic data, human approval, tamper test, limitations, FHIR/SIEM next.

## 8. Evaluation (synthetic data, seed 42 - see `docs/results.json`)
| | AccessGuard | Naive rule baseline* |
|---|---|---|
| Precision | 0.98 | 0.13 |
| Recall (events) | 0.87 | 0.52 |
| False alerts | 3 | 581 |
| Reviewer cases | 51 | 379 |
| Incident-level recall† | 0.82 | 0.15 |

\* *flag after-hours access, or >20 records/hour.* † *an attack counts as caught if at least one of its events is flagged.*
Across seeds 1-5: AccessGuard precision ≈ 0.98, recall ≈ 0.89, ~2 false alerts; baseline precision ≈ 0.17, recall ≈ 0.71
(the baseline's recall varies by seed), ~620 false alerts.

| Scenario | Event recall | Incident recall |
|---|---|---|
| Family snooping / VIP snooping / role abuse | 1.00 | 1.00 |
| Bulk theft | 0.93 | 1.00 |
| Credential compromise | 0.79 | 1.00 |
| **Low-and-slow in own ward (blind spot)** | **0.00** | **0.00** |

## 9. Evidence
Screenshots in `docs/screenshots/`: _<review queue, case detail, simulator, evaluation, audit log + tamper test, patient view>_

## 10. AI / detection limitations & human oversight
- **What it does:** rule-based risk scoring over care links, role permissions and behaviour signals. It is a risk
  indicator, not a verdict.
- **Data used:** access logs, ward / care-team / referral data, role permissions (synthetic).
- **Uncertainty:** mid-score events go to a lower-priority queue; nothing is actioned automatically.
- **False positives:** staff covering another ward, or a coincidental shared surname (3 in our test). Humans dismiss them.
- **False negatives:** low-and-slow snooping inside the user's own ward (0% detected), and credential theft that
  happens during a night-shift user's own hours.
- **Unsafe output:** explanations are fixed templates filled with IDs; no free text is generated.

## 11. Limitations & assumptions
- Metrics come from synthetic data we designed; they show the concept works, not real-world accuracy.
- Quality depends on accurate ward / care-team / referral records, which real hospitals often lack.
- Session suspension is simulated; there is no EHR integration.
- Malicious break-glass abuse is caught only by after-the-fact review.
- The audit log is tamper-**evident**, not tamper-proof: someone who can rewrite the whole file can recompute the
  chain. In production the head hash would be anchored in a separate system.

## 12. Safety & privacy
Synthetic data only; no real patients, credentials, or systems touched or scanned. No secrets in the repository.
Explanations and the patient view show roles and IDs, never names. Supports (does not certify) access-accountability
goals in HIPAA, India's DPDP Act 2023 and ABDM health-data rules.

## 13. Future scope
FHIR `AuditEvent` / HL7 ingestion, SIEM/SOAR connectors, long-term per-user behaviour baselines (to close the in-ward
blind spot), external anchoring of the audit-log head, optional local LLM to rephrase explanations (de-identified facts only).

## 14. Team & contributions
_<Member 1 - ...>_
