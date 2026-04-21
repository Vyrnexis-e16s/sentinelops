"""initial schema: users, webauthn, audit, siem, recon, ids, vault

Revision ID: 0001_initial
Revises:
Create Date: 2026-04-23 00:00:00
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --------------------------------------------------------------------- #
    # Identity                                                              #
    # --------------------------------------------------------------------- #
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(320), unique=True, nullable=False, index=True),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
    )

    op.create_table(
        "webauthn_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("credential_id", sa.LargeBinary, unique=True, nullable=False, index=True),
        sa.Column("public_key", sa.LargeBinary, nullable=False),
        sa.Column("sign_count", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("nickname", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "audit_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), index=True),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True, index=True),
        sa.Column("action", sa.String(120), nullable=False, index=True),
        sa.Column("resource_type", sa.String(120), nullable=False),
        sa.Column("resource_id", sa.String(120), nullable=True),
        sa.Column("metadata_json", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("prev_hash", sa.LargeBinary(length=32), nullable=False),
        sa.Column("entry_hash", sa.LargeBinary(length=32), nullable=False, unique=True),
    )

    # --------------------------------------------------------------------- #
    # SIEM                                                                  #
    # --------------------------------------------------------------------- #
    op.create_table(
        "siem_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("source", sa.String(120), nullable=False, index=True),
        sa.Column("raw_json", postgresql.JSONB, nullable=False),
        sa.Column("parsed_json", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("tags_array", postgresql.ARRAY(sa.String), nullable=False,
                  server_default=sa.text("ARRAY[]::varchar[]")),
    )
    op.create_index("ix_siem_events_severity", "siem_events", ["severity"])

    op.create_table(
        "siem_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("query_dsl_json", postgresql.JSONB, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("attack_technique_ids_array", postgresql.ARRAY(sa.String), nullable=False,
                  server_default=sa.text("ARRAY[]::varchar[]")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    op.create_table(
        "siem_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("siem_events.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("siem_rules.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("status", sa.String(24), nullable=False, server_default="new", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("assigned_to_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
    )

    # --------------------------------------------------------------------- #
    # Recon                                                                 #
    # --------------------------------------------------------------------- #
    op.create_table(
        "recon_targets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("value", sa.String(255), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.UniqueConstraint("owner_id", "value", name="uq_recon_target_owner_value"),
    )

    op.create_table(
        "recon_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("recon_targets.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("kind", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="queued", index=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("result_json", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
    )

    op.create_table(
        "recon_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("job_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("recon_jobs.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("evidence_json", postgresql.JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
    )

    # --------------------------------------------------------------------- #
    # IDS                                                                   #
    # --------------------------------------------------------------------- #
    op.create_table(
        "ids_inferences",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now(), index=True),
        sa.Column("features_json", postgresql.JSONB, nullable=False),
        sa.Column("prediction", sa.Integer, nullable=False),
        sa.Column("probability", sa.Float, nullable=False),
        sa.Column("label", sa.String(16), nullable=False, server_default="benign", index=True),
        sa.Column("attack_class", sa.String(64), nullable=True),
    )

    # --------------------------------------------------------------------- #
    # Vault                                                                 #
    # --------------------------------------------------------------------- #
    op.create_table(
        "vault_objects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("size", sa.BigInteger, nullable=False, server_default="0"),
        sa.Column("mime_type", sa.String(120), nullable=False, server_default="application/octet-stream"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("storage_path", sa.String(1024), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("wrap_nonce", sa.LargeBinary(length=12), nullable=False),
    )

    op.create_table(
        "vault_access_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("object_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("vault_objects.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("grantee_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("permissions", sa.String(32), nullable=False, server_default="read"),
    )


def downgrade() -> None:
    op.drop_table("vault_access_grants")
    op.drop_table("vault_objects")
    op.drop_table("ids_inferences")
    op.drop_table("recon_findings")
    op.drop_table("recon_jobs")
    op.drop_table("recon_targets")
    op.drop_table("siem_alerts")
    op.drop_table("siem_rules")
    op.drop_index("ix_siem_events_severity", table_name="siem_events")
    op.drop_table("siem_events")
    op.drop_table("audit_log")
    op.drop_table("webauthn_credentials")
    op.drop_table("users")
