"""Recon: per-target recurring scan schedules.

Revision ID: 0008
Revises: 0007
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_recon_schedules"
down_revision = "0007_vapt_ttp_memory_graph"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "recon_schedules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default=sa.text("60")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("params_json", sa.JSON(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_job_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["target_id"], ["recon_targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_job_id"], ["recon_jobs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_recon_schedules_target_id", "recon_schedules", ["target_id"], unique=False)
    op.create_index("ix_recon_schedules_owner_id", "recon_schedules", ["owner_id"], unique=False)
    op.create_index("ix_recon_schedules_enabled", "recon_schedules", ["enabled"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_recon_schedules_enabled", table_name="recon_schedules")
    op.drop_index("ix_recon_schedules_owner_id", table_name="recon_schedules")
    op.drop_index("ix_recon_schedules_target_id", table_name="recon_schedules")
    op.drop_table("recon_schedules")
