"""vapt_briefs: saved executive summaries (per user).

Revision ID: 0006
Revises: 0005
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006_vapt_briefs"
down_revision = "0005_ids_prediction_varchar"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vapt_briefs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vapt_briefs_owner_id", "vapt_briefs", ["owner_id"], unique=False)
    op.create_index("ix_vapt_briefs_created_at", "vapt_briefs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vapt_briefs_created_at", table_name="vapt_briefs")
    op.drop_index("ix_vapt_briefs_owner_id", table_name="vapt_briefs")
    op.drop_table("vapt_briefs")
