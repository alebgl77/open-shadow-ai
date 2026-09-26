"""Add detection uniqueness and persistent processing ledgers.

Existing duplicate detections are never automatically merged: review and preserve
analyst annotations, pick a canonical row per catalog_item_id, back up the others,
then remove duplicates and rerun. Migration fails atomically before modifications.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "002_reliable_ingest"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""DO $$ BEGIN
      IF EXISTS (SELECT catalog_item_id FROM detections WHERE catalog_item_id IS NOT NULL
                 GROUP BY catalog_item_id HAVING count(*) > 1) THEN
        RAISE EXCEPTION 'Duplicate catalog detections exist. Back up detections, preserve analyst annotations, '
          'consolidate rows per catalog_item_id, then retry migration 002.';
      END IF;
    END $$""")
    op.create_unique_constraint("uq_detection_catalog", "detections", ["catalog_item_id"])
    for name in ("ingest_receipts", "correlation_receipts"):
        columns = [
            sa.Column("event_id", UUID(as_uuid=True), primary_key=True),
            sa.Column("received_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        ]
        if name == "correlation_receipts":
            columns.append(sa.Column("catalog_item_id", sa.String(100), nullable=False))
        op.create_table(name, *columns)


def downgrade():
    op.drop_table("correlation_receipts")
    op.drop_table("ingest_receipts")
    op.drop_constraint("uq_detection_catalog", "detections", type_="unique")
