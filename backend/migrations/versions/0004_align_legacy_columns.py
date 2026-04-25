"""Align legacy DB columns with current ORM models.

Revision ID: 0004_align_legacy_columns
Revises: 0003_user_password_hash
Create Date: 2026-04-25

Why this migration exists
-------------------------
Several tables shipped initially with column types/names that were later
changed in the SQLAlchemy models, but no migration was written. As a result
production-style stacks running the older schema fail at runtime with:

* ``column "dek_nonce" of relation "vault_objects" does not exist``
* ``column "tags_array" is of type character varying[] but expression is of
  type json``

This migration converges the schema with the models that already exist:

1. ``vault_objects`` — rename ``wrap_nonce`` to ``dek_nonce`` (the model now
   refers to the wrap nonce as ``dek_nonce``).
2. ``siem_events.tags_array`` — convert from PostgreSQL ``varchar[]`` to
   ``jsonb`` so JSON-encoded payloads from the API serialise cleanly.
3. ``siem_rules.attack_technique_ids_array`` — same conversion as above.

All conversions are USING-clauses that preserve existing data: arrays are
turned into JSON arrays via ``to_jsonb`` / array_to_json.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004_align_legacy_columns"
down_revision: Union[str, None] = "0003_user_password_hash"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # -- vault_objects: rename wrap_nonce -> dek_nonce (only on Postgres; sqlite tests use the model directly)
    if dialect == "postgresql":
        existing = [
            r[0]
            for r in bind.execute(
                sa.text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_name='vault_objects'"
                )
            ).fetchall()
        ]
        if "wrap_nonce" in existing and "dek_nonce" not in existing:
            op.alter_column("vault_objects", "wrap_nonce", new_column_name="dek_nonce")
        elif "dek_nonce" not in existing:
            op.add_column(
                "vault_objects",
                sa.Column("dek_nonce", sa.LargeBinary(), nullable=False, server_default=sa.text("''::bytea")),
            )

        # -- siem_events.tags_array: varchar[] -> jsonb
        op.execute(
            "ALTER TABLE siem_events ALTER COLUMN tags_array DROP DEFAULT"
        )
        op.execute(
            "ALTER TABLE siem_events ALTER COLUMN tags_array "
            "TYPE jsonb USING to_jsonb(tags_array)"
        )
        op.execute(
            "ALTER TABLE siem_events ALTER COLUMN tags_array "
            "SET DEFAULT '[]'::jsonb"
        )

        # -- siem_rules.attack_technique_ids_array: varchar[] -> jsonb
        op.execute(
            "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array DROP DEFAULT"
        )
        op.execute(
            "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array "
            "TYPE jsonb USING to_jsonb(attack_technique_ids_array)"
        )
        op.execute(
            "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array "
            "SET DEFAULT '[]'::jsonb"
        )



def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect != "postgresql":
        return

    op.execute(
        "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array DROP DEFAULT"
    )
    op.execute(
        "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array "
        "TYPE varchar[] USING (SELECT array(SELECT jsonb_array_elements_text(attack_technique_ids_array)))"
    )
    op.execute(
        "ALTER TABLE siem_rules ALTER COLUMN attack_technique_ids_array "
        "SET DEFAULT ARRAY[]::varchar[]"
    )

    op.execute(
        "ALTER TABLE siem_events ALTER COLUMN tags_array DROP DEFAULT"
    )
    op.execute(
        "ALTER TABLE siem_events ALTER COLUMN tags_array "
        "TYPE varchar[] USING (SELECT array(SELECT jsonb_array_elements_text(tags_array)))"
    )
    op.execute(
        "ALTER TABLE siem_events ALTER COLUMN tags_array "
        "SET DEFAULT ARRAY[]::varchar[]"
    )

    op.alter_column("vault_objects", "dek_nonce", new_column_name="wrap_nonce")
