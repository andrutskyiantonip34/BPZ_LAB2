import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from mypolicy import (OBJECTS, SUBJECTS, VariantDetector, VariantPolicy, build_policy,
                      objects_accessible_by)

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


class ClockLog(AuditLog):
    def __init__(self) -> None:
        super().__init__()
        self.t = 1_700_000_000.0

    def _now(self) -> float:
        return self.t


def test_policy_size_matches_variant():
    # Policy has exactly 7 subjects and 21 objects as required by variant 1.
    assert len(SUBJECTS) == 7 and len(OBJECTS) == 21


def test_direct_role_grant():
    # A right granted directly to the subject's role is allowed.
    assert build_policy().evaluate("bob", "report1", R).allowed


def test_role_inheritance_one_level():
    # A senior role inherits rights of its junior role (accountant -> employee).
    assert build_policy().evaluate("bob", "doc3", R | W).allowed


def test_role_inheritance_transitive():
    # Inheritance is transitive across several levels (admin -> ... -> guest).
    p = build_policy()
    assert {"admin", "hr_manager", "employee", "guest"} <= p.roles_of("alice")
    assert p.evaluate("alice", "doc1", R).allowed


def test_junior_does_not_get_senior_rights():
    # A junior role does not receive rights of a senior role.
    d = build_policy().evaluate("dave", "report1", R)
    assert not d.allowed and "safe default" in d.reason


def test_partial_rights_are_not_enough():
    # A combined action is allowed only if every requested right is present.
    p = build_policy()
    assert p.evaluate("frank", "doc1", R).allowed
    assert not p.evaluate("frank", "doc1", R | W).allowed


def test_safe_default_unknown_subject():
    # An unknown subject is denied by the safe default rule.
    d = build_policy().evaluate("mallory", "doc1", R)
    assert not d.allowed and "safe default" in d.reason


def test_safe_default_unknown_object():
    # Access to an unknown object is denied by the safe default rule.
    assert not build_policy().evaluate("alice", "secret99", R).allowed


def test_empty_policy_denies_everything():
    # An empty policy denies every request.
    p = VariantPolicy()
    assert not any(p.evaluate(s, o, R).allowed for s in SUBJECTS for o in OBJECTS)


def test_deny_overrides_inherited_grant():
    # A deny entry overrides a right inherited through roles.
    p = build_policy()
    assert p.effective("alice", "hr3") & R
    d = p.evaluate("alice", "hr3", R)
    assert not d.allowed and "deny" in d.reason


def test_deny_is_per_action():
    # A deny entry blocks only the listed action, other actions stay allowed.
    p = build_policy()
    assert p.evaluate("bob", "report6", R).allowed
    assert not p.evaluate("bob", "report6", W).allowed


def test_deny_changes_result_vs_base_model():
    # The deny rule changes the decision compared with plain RBAC.
    p = build_policy()
    base = VariantPolicy()
    base.__dict__.update(p.__dict__)
    base.deny = {}
    assert base.evaluate("grace", "report2", R).allowed
    assert not p.evaluate("grace", "report2", R).allowed


def test_deny_is_per_subject():
    # A deny entry affects only its own subject, not others with the same role.
    assert build_policy().evaluate("bob", "report2", R).allowed


def test_complete_mediation_every_call_is_logged():
    # Every monitor call produces exactly one audit log entry.
    mon = ReferenceMonitor(build_policy())
    calls = [(s, o, R) for s in SUBJECTS for o in OBJECTS[:5]]
    for s, o, a in calls:
        mon.check(s, o, a)
    entries = mon.audit.entries()
    assert len(entries) == len(calls)
    assert any(e["allowed"] for e in entries) and any(not e["allowed"] for e in entries)


def test_enforce_raises_and_logs_denial():
    # enforce raises PermissionError on denial and still logs the decision.
    mon = ReferenceMonitor(build_policy())
    try:
        mon.enforce("frank", "config1", W)
        raised = False
    except PermissionError:
        raised = True
    assert raised
    last = mon.audit.entries()[-1]
    assert last["subject"] == "frank" and last["allowed"] is False


def test_audit_entries_are_copies():
    # Changing the list returned by entries() does not modify the audit log.
    mon = ReferenceMonitor(build_policy())
    mon.check("alice", "doc1", R)
    mon.audit.entries().clear()
    assert len(mon.audit.entries()) == 1


def test_a5_new_right_detected():
    # Anomaly A5 fires when a subject uses a right for the first time.
    mon = ReferenceMonitor(build_policy())
    for _ in range(5):
        mon.check("bob", "report1", R)
    mon.check("bob", "report1", W)
    alerts = VariantDetector(baseline=5).scan(mon.audit)
    assert len(alerts) == 1 and alerts[0].startswith("А5") and "WRITE" in alerts[0]


def test_a5_ignores_denied_attempts():
    # Denied requests are not treated as newly used rights by A5.
    mon = ReferenceMonitor(build_policy())
    for _ in range(5):
        mon.check("dave", "doc3", R)
    mon.check("dave", "config1", D)
    assert VariantDetector(baseline=5).scan(mon.audit) == []


def test_a4_read_spike_detected():
    # Anomaly A4 fires on a sharp spike of allowed reads in one window.
    log = ClockLog()
    mon = ReferenceMonitor(build_policy(), log)
    for minute in range(3):
        log.t = 1_700_000_000.0 + 60 * minute
        mon.check("bob", "report1", R)
        mon.check("bob", "report2", R)
    log.t += 60
    for o in [f"report{i}" for i in range(1, 7)] + ["doc1", "doc2", "doc3", "doc4"] * 2:
        mon.check("bob", o, R)
    alerts = VariantDetector(baseline=100).scan(mon.audit)
    assert len(alerts) == 1 and alerts[0].startswith("А4") and "bob" in alerts[0]


def test_a4_no_alert_below_min_reads():
    # A4 stays silent when the read count is below min_reads.
    log = ClockLog()
    mon = ReferenceMonitor(build_policy(), log)
    mon.check("bob", "report1", R)
    log.t += 60
    for o in ("report1", "report2", "report3", "report4"):
        mon.check("bob", o, R)
    assert VariantDetector(baseline=100, min_reads=10).scan(mon.audit) == []


def test_both_anomalies_together_and_clean_log():
    # Both anomalies are reported together and a clean log gives no alerts.
    log = ClockLog()
    mon = ReferenceMonitor(build_policy(), log)
    for minute in range(3):
        log.t = 1_700_000_000.0 + 60 * minute
        mon.check("bob", "report1", R)
        mon.check("bob", "report2", R)
    clean = VariantDetector(baseline=6).scan(mon.audit)
    log.t += 60
    for o in [f"report{i}" for i in range(1, 7)] * 2:
        mon.check("bob", o, R)
    mon.check("bob", "report3", W)
    alerts = VariantDetector(baseline=6).scan(mon.audit)
    assert clean == []
    assert {a[:2] for a in alerts} == {"А4", "А5"} and len(alerts) == 2
    assert VariantDetector().scan(AuditLog()) == []


def test_who_has_access():
    # The who-has-access query returns only subjects allowed to read hr3.
    assert subjects_with_access(build_policy(), SUBJECTS, "hr3", R) == ["carol"]


def test_what_subject_can_access():
    # The what-can-subject-access query returns only objects frank can read.
    assert objects_accessible_by(build_policy(), "frank", OBJECTS, R) == ["doc1", "doc2"]


def test_queries_are_dual():
    # Both queries agree for every subject-object pair.
    p = build_policy()
    for s in SUBJECTS:
        for o in OBJECTS:
            assert (s in subjects_with_access(p, SUBJECTS, o, R)) == \
                   (o in objects_accessible_by(p, s, OBJECTS, R))
