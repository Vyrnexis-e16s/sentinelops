"""users.password_hash for email+password fallback auth

Revision ID: 0003_user_password_hash
Revises: 0002_siem_iocs
Create Date: 2026-04-25
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_user_password_hash"
down_revision: Union[str, None] = "0002_siem_iocs"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_hash", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("users", "password_hash")
