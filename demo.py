import sys

from accesscontrol.monitor import AuditLog, Permission, ReferenceMonitor, subjects_with_access
from mypolicy import OBJECTS, SUBJECTS, VariantDetector, VariantPolicy, build_policy, objects_accessible_by

R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE


class ClockLog(AuditLog):
    def __init__(self, t: float = 1_763_100_000.0) -> None:
        super().__init__()
        self.t = t

    def _now(self) -> float:
        return self.t


def step2() -> None:
    p = VariantPolicy()
    p.add_role("employee")
    p.assign("alice", "employee")
    p.grant("employee", "doc1", R)
    print(p.evaluate("alice", "doc1", R))
    print(p.evaluate("alice", "doc1", W))


EXPECTED = [
    ("alice", "doc1", R, True),
    ("alice", "config1", W, True),
    ("alice", "hr3", R, False),
    ("bob", "report1", W, True),
    ("bob", "doc3", R, True),
    ("bob", "report6", R, True),
    ("bob", "report6", W, False),
    ("bob", "hr1", R, False),
    ("carol", "hr3", R, True),
    ("dave", "report1", R, False),
    ("erin", "audit1", R, True),
    ("erin", "audit1", W, False),
    ("frank", "doc1", R, True),
    ("frank", "doc1", W, False),
    ("grace", "report2", R, False),
    ("grace", "report3", R, True),
    ("mallory", "doc1", R, False),
]


def step3() -> None:
    p = build_policy()
    base = VariantPolicy()
    base.__dict__.update(p.__dict__)
    base.deny = {}
    print("subject object action base expected actual")
    ok = 0
    for s, o, a, exp in EXPECTED:
        d = p.evaluate(s, o, a)
        ok += d.allowed == exp
        print(s, o, a.name, base.evaluate(s, o, a).allowed, exp, d.allowed)
    print(f"{ok}/{len(EXPECTED)} OK")


def step4() -> None:
    mon = ReferenceMonitor(build_policy())
    d = mon.check("alice", "doc1", R)
    print(d.allowed, d.reason)
    try:
        mon.enforce("bob", "hr1", W)
    except PermissionError as e:
        print("PermissionError:", e)
    calls = 2
    for s, o, a, _ in EXPECTED:
        mon.check(s, o, a)
        calls += 1
    print("calls:", calls, "log entries:", len(mon.audit.entries()))
    print("\n".join(mon.audit.dump().splitlines()[:6]))


def anomalous_log() -> ReferenceMonitor:
    log = ClockLog()
    mon = ReferenceMonitor(build_policy(), log)
    t0 = log.t
    for minute in range(5):
        log.t = t0 + 60 * minute
        mon.check("bob", "report1", R)
        mon.check("bob", "report2", R)
        mon.check("carol", "hr1", R)
        mon.check("dave", "doc3", R)
        mon.check("dave", "doc3", W)
        mon.check("frank", "doc1", R)
    log.t = t0 + 60 * 5
    for o in [f"report{i}" for i in range(1, 7)] + ["doc1", "doc2", "doc3", "doc4", "doc5", "doc6"]:
        mon.check("bob", o, R)
    mon.check("carol", "hr2", W)
    mon.check("frank", "doc1", W)
    return mon


def clean_log() -> ReferenceMonitor:
    log = ClockLog()
    mon = ReferenceMonitor(build_policy(), log)
    t0 = log.t
    for minute in range(6):
        log.t = t0 + 60 * minute
        mon.check("bob", "report1", R)
        mon.check("bob", "report2", R)
        mon.check("carol", "hr1", R)
        mon.check("dave", "doc3", R)
        mon.check("dave", "doc3", W)
        mon.check("frank", "doc1", R)
    return mon


def step5() -> None:
    det = VariantDetector(baseline=30, read_factor=3.0, min_reads=10, window=60)
    mon = anomalous_log()
    print("anomalous log:", len(mon.audit.entries()), "entries")
    for a in det.scan(mon.audit):
        print(a)
    mon = clean_log()
    print("clean log:", len(mon.audit.entries()), "entries", det.scan(mon.audit))


def step7() -> None:
    p = build_policy()
    for o in ("doc1", "report2", "hr3", "config1"):
        print("who reads", o, subjects_with_access(p, SUBJECTS, o, R))
    for s in ("alice", "grace", "frank"):
        print(s, "reads", objects_accessible_by(p, s, OBJECTS, R))
    print("consistent:", all(
        (s in subjects_with_access(p, SUBJECTS, o, R)) == (o in objects_accessible_by(p, s, OBJECTS, R))
        for s in SUBJECTS for o in OBJECTS))


STEPS = {"2": step2, "3": step3, "4": step4, "5": step5, "7": step7}

if __name__ == "__main__":
    for k in sys.argv[1:] or STEPS:
        STEPS[k]()
