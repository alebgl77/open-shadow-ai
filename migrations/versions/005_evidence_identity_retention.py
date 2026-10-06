"""Observed identity membership; never invent dates for unaged legacy evidence.

Revision ID: 005_evidence_identity
Revises: 004_collector_identity
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "005_evidence_identity"
down_revision = "004_collector_identity"
branch_labels = None
depends_on = None


def cleared_legacy_bundle(value):
    if not isinstance(value, dict):
        return {"_risk_score_stale": True}
    clean = {key: item for key, item in value.items() if not key.startswith(("_user", "_device", "_identity"))}
    for source in ("dns", "proxy", "endpoint", "browser", "oauth", "directory", "instrumented", "casb", "network"):
        section = clean.get(source)
        if not isinstance(section, dict):
            clean.pop(source, None)
            continue
        clean[source] = {
            key: item
            for key, item in section.items()
            if key not in {"sample_values", "sample_observations", "network_observations"}
        }
    clean["_risk_score_stale"] = True
    return clean


def upgrade():
    op.create_table(
        "detection_identity_members",
        sa.Column(
            "detection_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("detections.detection_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("kind", sa.String(10), primary_key=True),
        sa.Column("identity_digest", sa.String(64), primary_key=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("kind IN ('user', 'device')", name="valid_evidence_identity_kind"),
    )
    op.create_index("idx_evidence_identity_last_seen", "detection_identity_members", ["last_seen_at"])
    # Bounded keyset reads/writes inside Alembic's schema transaction. No legacy
    # identity receives aggregate last_seen: another person's activity is not its age.
    detections = sa.table(
        "detections",
        sa.column("detection_id", postgresql.UUID(as_uuid=True)),
        sa.column("evidence_bundle", postgresql.JSONB()),
        sa.column("impacted_users_count", sa.Integer()),
        sa.column("impacted_devices_count", sa.Integer()),
        sa.column("primary_evidence", sa.Text()),
    )
    connection, cursor = op.get_bind(), None
    while True:
        query = (
            sa.select(detections.c.detection_id, detections.c.evidence_bundle)
            .order_by(detections.c.detection_id)
            .limit(500)
        )
        if cursor is not None:
            query = query.where(detections.c.detection_id > cursor)
        rows = connection.execute(query).all()
        if not rows:
            break
        for identifier, bundle in rows:
            connection.execute(
                sa.update(detections)
                .where(detections.c.detection_id == identifier)
                .values(
                    evidence_bundle=cleared_legacy_bundle(bundle),
                    impacted_users_count=0,
                    impacted_devices_count=0,
                    primary_evidence=None,
                )
            )
        cursor = rows[-1][0]


def downgrade():
    op.drop_table("detection_identity_members")
