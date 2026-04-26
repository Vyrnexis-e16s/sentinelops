"""VAPT: TTP memory, graph edges, analyst feedback (Postgres; optional Neo4j via Cypher export).

Revision ID: 0007
Revises: 0006
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_vapt_ttp_memory_graph"
down_revision = "0006_vapt_briefs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vapt_ttp_memory",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("technique_id", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("narrative_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_id", "technique_id", name="uq_vapt_ttp_owner_technique"),
    )
    op.create_index("ix_vapt_ttp_memory_owner_id", "vapt_ttp_memory", ["owner_id"], unique=False)
    op.create_index("ix_vapt_ttp_memory_technique_id", "vapt_ttp_memory", ["technique_id"], unique=False)
    op.create_index("ix_vapt_ttp_memory_created_at", "vapt_ttp_memory", ["created_at"], unique=False)
    op.create_index("ix_vapt_ttp_memory_updated_at", "vapt_ttp_memory", ["updated_at"], unique=False)

    op.create_table(
        "vapt_graph_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("from_technique_id", sa.String(length=32), nullable=False),
        sa.Column("to_technique_id", sa.String(length=32), nullable=False),
        sa.Column("relation", sa.String(length=120), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vapt_graph_edges_owner_id", "vapt_graph_edges", ["owner_id"], unique=False)
    op.create_index(
        "ix_vapt_graph_edges_from_technique_id", "vapt_graph_edges", ["from_technique_id"], unique=False
    )
    op.create_index(
        "ix_vapt_graph_edges_to_technique_id", "vapt_graph_edges", ["to_technique_id"], unique=False
    )
    op.create_index("ix_vapt_graph_edges_created_at", "vapt_graph_edges", ["created_at"], unique=False)

    op.create_table(
        "vapt_analyst_feedback",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("owner_id", sa.Uuid(), nullable=False),
        sa.Column("ref_type", sa.String(length=32), nullable=False),
        sa.Column("ref_key", sa.String(length=64), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vapt_analyst_feedback_owner_id", "vapt_analyst_feedback", ["owner_id"], unique=False)
    op.create_index("ix_vapt_analyst_feedback_ref_type", "vapt_analyst_feedback", ["ref_type"], unique=False)
    op.create_index("ix_vapt_analyst_feedback_ref_key", "vapt_analyst_feedback", ["ref_key"], unique=False)
    op.create_index("ix_vapt_analyst_feedback_created_at", "vapt_analyst_feedback", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_vapt_analyst_feedback_created_at", table_name="vapt_analyst_feedback")
    op.drop_index("ix_vapt_analyst_feedback_ref_key", table_name="vapt_analyst_feedback")
    op.drop_index("ix_vapt_analyst_feedback_ref_type", table_name="vapt_analyst_feedback")
    op.drop_index("ix_vapt_analyst_feedback_owner_id", table_name="vapt_analyst_feedback")
    op.drop_table("vapt_analyst_feedback")

    op.drop_index("ix_vapt_graph_edges_created_at", table_name="vapt_graph_edges")
    op.drop_index("ix_vapt_graph_edges_to_technique_id", table_name="vapt_graph_edges")
    op.drop_index("ix_vapt_graph_edges_from_technique_id", table_name="vapt_graph_edges")
    op.drop_index("ix_vapt_graph_edges_owner_id", table_name="vapt_graph_edges")
    op.drop_table("vapt_graph_edges")

    op.drop_index("ix_vapt_ttp_memory_updated_at", table_name="vapt_ttp_memory")
    op.drop_index("ix_vapt_ttp_memory_created_at", table_name="vapt_ttp_memory")
    op.drop_index("ix_vapt_ttp_memory_technique_id", table_name="vapt_ttp_memory")
    op.drop_index("ix_vapt_ttp_memory_owner_id", table_name="vapt_ttp_memory")
    op.drop_table("vapt_ttp_memory")
