"""Add enrolled collector identity without manufacturing identities for shared keys.

Revision ID: 004_collector_identity
Revises: 003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "004_collector_identity"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "collectors",
        sa.Column("collector_id", sa.String(255), primary_key=True),
        sa.Column("tenant_id", sa.String(100), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("allowed_source_types", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("credential_generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_contact_at", sa.DateTime(timezone=True)),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)),
        sa.Column("last_observed_at", sa.DateTime(timezone=True)),
        sa.Column("client_version", sa.String(100)),
        sa.Column("client_last_success_at", sa.DateTime(timezone=True)),
        sa.Column("client_counters", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_collectors_tenant_id", "collectors", ["tenant_id"])
    op.create_table(
        "collector_credentials",
        sa.Column("credential_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "collector_id", sa.String(255), sa.ForeignKey("collectors.collector_id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("secret_digest", sa.String(64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )
    op.create_index("idx_collector_credentials_collector", "collector_credentials", ["collector_id"])


def downgrade():
    op.drop_table("collector_credentials")
    op.drop_table("collectors")
