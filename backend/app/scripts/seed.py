"""Idempotent demo data seeder.

Run inside the backend container:
    python -m app.scripts.seed
"""
from __future__ import annotations

import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import structlog
from sqlalchemy import select

from app.core.db import get_session_factory, init_db
from app.models import (
    AuditLog,
    Inference,
    Target,
    User,
    Event,
    DetectionRule,
    Alert,
    VaultObject,
)
from app.modules.vault.services import encryption, storage

log = structlog.get_logger(__name__)
RULES_DIR = Path(__file__).resolve().parents[1] / "modules" / "siem" / "rules"


SOURCES = ["auth-app", "edge-firewall", "windows-eventlog", "k8s-apiserver", "linux-auditd"]
SEVERITIES = ["info", "info", "info", "low", "low", "medium", "high"]
EVENT_VERBS = [
    "ssh login", "ssh failure", "powershell exec", "dns query", "smb connect",
    "http request", "kerberos tgt", "process create", "file write", "user logon",
]


async def _ensure_demo_user(session) -> User:
    existing = (
        await session.execute(select(User).where(User.email == "analyst@sentinelops.local"))
    ).scalar_one_or_none()
    if existing:
        return existing
    user = User(
        id=uuid.uuid4(),
        email="analyst@sentinelops.local",
        display_name="Demo Analyst",
        is_active=True,
    )
    session.add(user)
    await session.flush()
    return user


async def _seed_siem(session, user: User) -> None:
    n_existing = (await session.execute(select(Event))).scalars().first()
    if n_existing:
        log.info("siem_already_seeded")
        return

    rules: list[DetectionRule] = []
    for rule_file in sorted(RULES_DIR.glob("*.json")):
        spec = json.loads(rule_file.read_text())
        rules.append(
            DetectionRule(
                id=uuid.uuid4(),
                name=spec["name"],
                description=spec.get("description", ""),
                query_dsl_json=spec.get("query_dsl") or spec.get("query", {}),
                enabled=True,
                attack_technique_ids_array=spec.get("attack_technique_ids")
                or spec.get("attack_techniques", []),
            )
        )
    session.add_all(rules)
    await session.flush()

    now = datetime.now(tz=timezone.utc)
    events: list[Event] = []
    for i in range(500):
        ts = now - timedelta(minutes=random.randint(0, 30 * 24 * 60))
        verb = random.choice(EVENT_VERBS)
        sev = random.choice(SEVERITIES)
        ev = Event(
            id=uuid.uuid4(),
            timestamp=ts,
            source=random.choice(SOURCES),
            raw_json={"verb": verb, "raw": f"event-{i}"},
            parsed_json={"verb": verb, "user": f"u{random.randint(1, 50)}", "src_ip": f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"},
            severity=sev,
            tags_array=["seed"],
        )
        events.append(ev)
    session.add_all(events)
    await session.flush()

    # 1 alert for every ~20 events using a random rule
    for ev in random.sample(events, k=max(1, len(events) // 20)):
        rule = random.choice(rules)
        session.add(
            Alert(
                id=uuid.uuid4(),
                event_id=ev.id,
                rule_id=rule.id,
                score=round(random.uniform(0.5, 0.99), 2),
                status=random.choice(["new", "new", "new", "ack", "resolved"]),
            )
        )
    log.info("siem_seeded", events=len(events), rules=len(rules))


async def _seed_recon(session, user: User) -> None:
    if (await session.execute(select(Target))).scalars().first():
        return
    targets = [
        Target(id=uuid.uuid4(), kind="domain", value="example.com", owner_id=user.id),
        Target(id=uuid.uuid4(), kind="domain", value="hackthebox.eu", owner_id=user.id),
        Target(id=uuid.uuid4(), kind="cidr", value="10.0.0.0/24", owner_id=user.id),
    ]
    session.add_all(targets)
    log.info("recon_seeded", targets=len(targets))


async def _seed_ids(session) -> None:
    if (await session.execute(select(Inference))).scalars().first():
        return
    classes = ["normal", "neptune", "smurf", "ipsweep", "satan"]
    rows = []
    now = datetime.now(tz=timezone.utc)
    for i in range(50):
        cls = random.choices(classes, weights=[7, 2, 1, 1, 1])[0]
        rows.append(
            Inference(
                id=uuid.uuid4(),
                timestamp=now - timedelta(minutes=i * 7),
                features_json={"duration": random.random(), "src_bytes": random.randint(0, 50000)},
                prediction=cls,
                probability=round(random.uniform(0.6, 0.99), 3),
                label="benign" if cls == "normal" else "attack",
                attack_class=None if cls == "normal" else "dos" if cls in ("neptune", "smurf") else "probe",
            )
        )
    session.add_all(rows)
    log.info("ids_seeded", inferences=len(rows))


async def _seed_vault(session, user: User) -> None:
    if (await session.execute(select(VaultObject).where(VaultObject.owner_id == user.id))).scalars().first():
        return
    samples = [
        ("ir-runbook.md", b"# Incident Response Runbook\n\n1. Triage\n2. Contain\n3. Eradicate\n4. Recover\n"),
        ("ssh-keys.txt", b"placeholder -- dummy demo content, do not use\n"),
    ]
    for name, payload in samples:
        blob = encryption.encrypt_for_user(payload, user.id)
        oid = uuid.uuid4()
        path = storage.write_blob(user.id, oid, blob.ciphertext)
        session.add(
            VaultObject(
                id=oid,
                owner_id=user.id,
                name=name,
                size=len(payload),
                mime_type="text/plain",
                storage_path=path,
                nonce=blob.nonce,
                wrapped_dek=blob.wrapped_dek,
                dek_nonce=blob.dek_nonce,
            )
        )
    log.info("vault_seeded", objects=len(samples))


async def main() -> None:
    await init_db()
    factory = get_session_factory()
    async with factory() as session:
        async with session.begin():
            user = await _ensure_demo_user(session)
            await _seed_siem(session, user)
            await _seed_recon(session, user)
            await _seed_ids(session)
            await _seed_vault(session, user)
    log.info("seed_complete")


if __name__ == "__main__":
    asyncio.run(main())
