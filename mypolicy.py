from __future__ import annotations

import collections

from accesscontrol.monitor import AnomalyDetector, AuditLog, Decision, Permission, Policy


class VariantPolicy(Policy):
    def __init__(self) -> None:
        self.grants: dict[tuple[str, str], Permission] = {}
        self.user_roles: dict[str, set[str]] = collections.defaultdict(set)
        self.parents: dict[str, set[str]] = collections.defaultdict(set)
        self.deny: dict[tuple[str, str], Permission] = {}

    def add_role(self, role: str, inherits: tuple[str, ...] = ()) -> None:
        self.parents[role].update(inherits)

    def assign(self, subject: str, role: str) -> None:
        self.user_roles[subject].add(role)

    def grant(self, who: str, obj: str, perm: Permission) -> None:
        key = (who, obj)
        self.grants[key] = self.grants.get(key, Permission.NONE) | perm

    def add_deny(self, subject: str, obj: str, perm: Permission) -> None:
        key = (subject, obj)
        self.deny[key] = self.deny.get(key, Permission.NONE) | perm

    def roles_of(self, subject: str) -> set[str]:
        seen: set[str] = set()
        queue = collections.deque(self.user_roles.get(subject, ()))
        while queue:
            role = queue.popleft()
            if role in seen:
                continue
            seen.add(role)
            queue.extend(self.parents.get(role, ()))
        return seen

    def effective(self, subject: str, obj: str) -> Permission:
        perm = Permission.NONE
        for role in self.roles_of(subject):
            perm |= self.grants.get((role, obj), Permission.NONE)
        return perm

    def evaluate(self, subject: str, obj: str, action: Permission) -> Decision:
        if action == Permission.NONE:
            return Decision(False, "порожня дія (safe default)")
        denied = action & self.deny.get((subject, obj), Permission.NONE)
        if denied:
            return Decision(False, f"заборонний запис deny: {denied.name}")
        effective = self.effective(subject, obj)
        if action & effective == action:
            return Decision(True, "надано (RBAC)")
        return Decision(False, "явного дозволу немає (safe default)")


SUBJECTS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]
OBJECTS = (
    [f"doc{i}" for i in range(1, 9)]
    + [f"report{i}" for i in range(1, 7)]
    + [f"hr{i}" for i in range(1, 5)]
    + ["config1", "config2", "audit1"]
)


def build_policy() -> VariantPolicy:
    p = VariantPolicy()
    R, W, D = Permission.READ, Permission.WRITE, Permission.DELETE

    p.add_role("guest")
    p.add_role("employee", inherits=("guest",))
    p.add_role("accountant", inherits=("employee",))
    p.add_role("hr_manager", inherits=("employee",))
    p.add_role("auditor", inherits=("guest",))
    p.add_role("admin", inherits=("accountant", "hr_manager"))

    for o in ("doc1", "doc2"):
        p.grant("guest", o, R)
    for o in ("doc3", "doc4", "doc5", "doc6"):
        p.grant("employee", o, R | W)
    for o in ("doc1", "doc2"):
        p.grant("employee", o, W)
    for o in ("report1", "report2", "report3", "report4", "report5", "report6"):
        p.grant("accountant", o, R | W)
    for o in ("hr1", "hr2", "hr3", "hr4"):
        p.grant("hr_manager", o, R | W)
    for o in ("report1", "report2", "report3", "audit1"):
        p.grant("auditor", o, R)
    for o in ("doc7", "doc8", "config1", "config2", "audit1"):
        p.grant("admin", o, Permission.ADMIN)
    for o in OBJECTS:
        p.grant("admin", o, D)

    p.assign("alice", "admin")
    p.assign("bob", "accountant")
    p.assign("carol", "hr_manager")
    p.assign("dave", "employee")
    p.assign("erin", "auditor")
    p.assign("frank", "guest")
    p.assign("grace", "accountant")
    p.assign("grace", "auditor")

    p.add_deny("alice", "hr3", R | W)
    p.add_deny("bob", "report6", W)
    p.add_deny("grace", "report2", R | W | D)
    return p


class VariantDetector(AnomalyDetector):
    def __init__(self, baseline: int = 20, read_factor: float = 3.0,
                 min_reads: int = 10, window: float = 60.0) -> None:
        self.baseline = baseline
        self.read_factor = read_factor
        self.min_reads = min_reads
        self.window = window

    def scan(self, log: AuditLog) -> list[str]:
        entries = log.entries()
        return self._new_rights(entries) + self._read_spike(entries)

    def _new_rights(self, entries: list[dict]) -> list[str]:
        alerts: list[str] = []
        known: dict[str, set[str]] = collections.defaultdict(set)
        for i, r in enumerate(entries):
            if not r["allowed"]:
                continue
            subj, act = r["subject"], r["action"]
            if i >= self.baseline and act not in known[subj]:
                alerts.append(f"А5: {subj} уперше використав право {act} ({r['object']})")
            known[subj].add(act)
        return alerts

    def _read_spike(self, entries: list[dict]) -> list[str]:
        alerts: list[str] = []
        reads = [r for r in entries if r["allowed"] and r["action"] == "READ"]
        if not reads:
            return alerts
        t0 = min(r["ts"] for r in reads)
        per_subject: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        for r in reads:
            per_subject[r["subject"]][int((r["ts"] - t0) // self.window)] += 1
        for subj, buckets in sorted(per_subject.items()):
            counts = [buckets.get(b, 0) for b in range(max(buckets) + 1)]
            for b in range(1, len(counts)):
                cur = counts[b]
                avg = sum(counts[:b]) / b
                if cur >= self.min_reads and cur > self.read_factor * max(avg, 1.0):
                    alerts.append(f"А4: {subj} зчитав {cur} об'єктів у вікні {b} (середнє {avg:.1f})")
        return alerts


def objects_accessible_by(policy: Policy, subject: str, objects, action: Permission) -> list[str]:
    return [o for o in objects if policy.evaluate(subject, o, action).allowed]
