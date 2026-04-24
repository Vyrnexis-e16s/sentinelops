"""siem threat intel + case investigations

Revision ID: 0002_siem_iocs
Revises: 0001_initial
Create Date: 2026-04-24
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002_siem_iocs"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "siem_threat_iocs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ioc_type", sa.String(24), nullable=False, index=True),
        sa.Column("value", sa.String(512), nullable=False, index=True),
        sa.Column("stix_id", sa.String(256), nullable=True),
        sa.Column("source", sa.String(200), nullable=False, server_default="stix"),
        sa.Column("metadata_json", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_siem_ioc_type_value", "siem_threat_iocs", ["ioc_type", "value"], unique=True)

    op.create_table(
        "siem_investigations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("state", sa.String(32), nullable=False, server_default="open", index=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("alert_ids", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("siem_investigations")
    op.drop_index("ix_siem_ioc_type_value", table_name="siem_threat_iocs")
    op.drop_table("siem_threat_iocs")
