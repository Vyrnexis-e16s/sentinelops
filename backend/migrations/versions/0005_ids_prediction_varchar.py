"""Widen ids_inferences.prediction from integer to varchar(48).

Revision ID: 0005_ids_prediction_varchar
Revises: 0004_align_legacy_columns
Create Date: 2026-04-25

Why
----
Earlier schemas stored ``prediction`` as an integer label (the encoded
class id from the training pipeline). The current model writes the
human-readable class name (e.g. ``neptune``, ``normal``, ``smurf``) so
the column has to be a string. Keeping the old integer column made
``POST /ids/infer`` fail with::

    DatatypeMismatchError: column "prediction" is of type integer
                           but expression is of type character varying

This migration widens the column in-place, preserving any existing rows
by casting them to text.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_ids_prediction_varchar"
down_revision: Union[str, None] = "0004_align_legacy_columns"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    pred_type = bind.execute(
        sa.text(
            "SELECT data_type FROM information_schema.columns "
            "WHERE table_name='ids_inferences' AND column_name='prediction'"
        )
    ).scalar()
    if pred_type and pred_type.lower() == "integer":
        op.execute(
            "ALTER TABLE ids_inferences ALTER COLUMN prediction "
            "TYPE varchar(48) USING prediction::varchar"
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    # Down-migrate is best-effort: any non-integer values become NULL,
    # which is acceptable for a development rollback.
    op.execute(
        "ALTER TABLE ids_inferences ALTER COLUMN prediction "
        "TYPE integer USING NULLIF(regexp_replace(prediction, '[^0-9-]', '', 'g'), '')::integer"
    )
