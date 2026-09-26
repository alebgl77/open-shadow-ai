"""Initial schema — all tables.

Revision ID: 001_initial
Revises:
Create Date: 2026-03-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

revision: str = "001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("username", sa.String(255), unique=True, nullable=False),
        sa.Column("email", sa.String(255)),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="viewer"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("true")),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ── detections ───────────────────────────────────────────
    op.create_table(
        "detections",
        sa.Column("detection_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("entity_type", sa.String(50), nullable=False),
        sa.Column("entity_name", sa.String(255), nullable=False),
        sa.Column("entity_category", sa.String(100)),
        sa.Column("catalog_item_id", sa.String(100)),
        sa.Column("classification", sa.String(50), server_default="unknown"),
        sa.Column("shadow_ai_status", sa.String(50), server_default="suspected"),
        sa.Column("confidence_score", sa.Float, nullable=False, server_default=sa.text("0.0")),
        sa.Column("risk_score", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("impacted_users_count", sa.Integer, server_default=sa.text("0")),
        sa.Column("impacted_devices_count", sa.Integer, server_default=sa.text("0")),
        sa.Column("total_events_count", sa.BigInteger, server_default=sa.text("0")),
        sa.Column("source_types", ARRAY(sa.Text), server_default="{}"),
        sa.Column("primary_evidence", sa.Text),
        sa.Column("evidence_bundle", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("reasoning_summary", sa.Text),
        sa.Column("analyst_status", sa.String(50), server_default="new"),
        sa.Column("analyst_id", UUID(as_uuid=True)),
        sa.Column("analyst_notes", sa.Text),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("recommended_action", sa.String(100)),
        sa.Column("governance_id", UUID(as_uuid=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="valid_confidence"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="valid_risk"),
    )
    op.create_index("idx_detections_risk", "detections", ["risk_score", "analyst_status"])
    op.create_index("idx_detections_classification", "detections", ["classification"])
    op.create_index("idx_detections_entity", "detections", ["entity_type", "entity_name"])
    op.create_index("idx_detections_last_seen", "detections", ["last_seen_at"])
    op.create_index("idx_detections_catalog", "detections", ["catalog_item_id"])

    # ── catalog ──────────────────────────────────────────────
    op.create_table(
        "catalog",
        sa.Column("catalog_item_id", sa.String(100), primary_key=True),
        sa.Column("canonical_name", sa.String(255), nullable=False),
        sa.Column("aliases", ARRAY(sa.Text), server_default="{}"),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("vendor", sa.String(255)),
        sa.Column("description", sa.Text),
        sa.Column("domains", ARRAY(sa.Text), server_default="{}"),
        sa.Column("url_patterns", ARRAY(sa.Text), server_default="{}"),
        sa.Column("processes", ARRAY(sa.Text), server_default="{}"),
        sa.Column("extension_ids", ARRAY(sa.Text), server_default="{}"),
        sa.Column("oauth_app_ids", ARRAY(sa.Text), server_default="{}"),
        sa.Column("local_ports", ARRAY(sa.Text), server_default="{}"),
        sa.Column("local_paths", ARRAY(sa.Text), server_default="{}"),
        sa.Column("container_patterns", ARRAY(sa.Text), server_default="{}"),
        sa.Column("user_agent_patterns", ARRAY(sa.Text), server_default="{}"),
        sa.Column("rule_tags", ARRAY(sa.Text), server_default="{}"),
        sa.Column("default_trust_level", sa.String(50), server_default="unknown"),
        sa.Column("status", sa.String(50), server_default="active"),
        sa.Column("source_of_truth", sa.String(50), server_default="builtin"),
        sa.Column("last_reviewed_at", sa.DateTime(timezone=True)),
        sa.Column("local_override", sa.Boolean, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # ── governance ───────────────────────────────────────────
    op.create_table(
        "governance",
        sa.Column("governance_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=False),
        sa.Column("org_classification", sa.String(50), nullable=False),
        sa.Column("owner", sa.String(255)),
        sa.Column("exception_policy", sa.Text),
        sa.Column("enforcement_mode", sa.String(50), server_default="monitor"),
        sa.Column("justification", sa.Text),
        sa.Column("approved_by", sa.String(255)),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
        sa.Column("approved_until", sa.DateTime(timezone=True)),
        sa.Column("created_by", UUID(as_uuid=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_governance_target", "governance", ["target_type", "target_id"])

    # ── audit_log ────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("audit_id", UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("user_id", UUID(as_uuid=True), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(100)),
        sa.Column("resource_id", sa.String(255)),
        sa.Column("details", JSONB, server_default=sa.text("'{}'::jsonb")),
        sa.Column("ip_address", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("idx_audit_timestamp", "audit_log", ["timestamp"])
    op.create_index("idx_audit_user", "audit_log", ["user_id", "timestamp"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("governance")
    op.drop_table("catalog")
    op.drop_table("detections")
    op.drop_table("users")
