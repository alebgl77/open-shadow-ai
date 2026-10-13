"""Browser extension inventory: current installation state and version changes.

Revision ID: 006_extension_inventory
Revises: 005_evidence_identity

Both tables are bounded by the identity retention window and rebuilt from the agents'
next inventory snapshots, so the downgrade drops them without preserving data.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "006_extension_inventory"
down_revision = "005_evidence_identity"
branch_labels = None
depends_on = None

# "" is a record a wire v1 agent sent without an install source; "unknown" is one the agent could not read.
INSTALL_SOURCES = ("", "store", "user", "unpacked", "external", "policy", "component", "orphan", "unknown")
INSTALL_SOURCE_CHECK = "install_source IN ({})".format(", ".join(f"'{value}'" for value in INSTALL_SOURCES))


def upgrade():
    op.create_table(
        "extension_inventory",
        sa.Column("inventory_key", sa.String(64), primary_key=True),
        sa.Column("device_digest", sa.String(64), nullable=False),
        sa.Column("user_digest", sa.String(64)),
        sa.Column("host_label", sa.String(255), nullable=False),
        sa.Column("user_label", sa.String(255)),
        sa.Column("browser", sa.String(64), nullable=False),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("extension_id", sa.Text(), nullable=False),
        sa.Column("extension_name", sa.Text(), nullable=False, server_default=""),
        sa.Column("version", sa.String(100)),
        sa.Column("enabled", sa.Boolean()),
        sa.Column("install_source", sa.String(20), nullable=False, server_default=""),
        sa.Column("installed_at", sa.DateTime(timezone=True)),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("catalog_item_id", sa.String(100)),
        sa.Column("collector_id", sa.String(255), nullable=False, server_default=""),
        sa.Column("identity_basis", sa.String(64), nullable=False),
        sa.Column("last_event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("wire_version", sa.SmallInteger(), nullable=False, server_default="1"),
        sa.CheckConstraint(INSTALL_SOURCE_CHECK, name="valid_extension_install_source"),
    )
    for name, column in (
        ("idx_extension_inventory_last_seen", "last_seen_at"),
        ("idx_extension_inventory_extension", "extension_id"),
        ("idx_extension_inventory_browser", "browser"),
        ("idx_extension_inventory_host", "host_label"),
        ("idx_extension_inventory_catalog", "catalog_item_id"),
        ("idx_extension_inventory_basis", "identity_basis"),
        ("idx_extension_inventory_device", "device_digest"),
    ):
        op.create_index(name, "extension_inventory", [column])
    op.create_table(
        "extension_version_changes",
        sa.Column("change_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "inventory_key",
            sa.String(64),
            sa.ForeignKey("extension_inventory.inventory_key", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("extension_id", sa.Text(), nullable=False),
        sa.Column("extension_name", sa.Text(), nullable=False, server_default=""),
        sa.Column("browser", sa.String(64), nullable=False),
        sa.Column("host_label", sa.String(255), nullable=False),
        sa.Column("user_label", sa.String(255)),
        sa.Column("profile", sa.String(255), nullable=False, server_default=""),
        sa.Column("from_version", sa.String(100)),
        sa.Column("to_version", sa.String(100)),
        sa.Column("previous_observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("catalog_item_id", sa.String(100)),
        sa.UniqueConstraint("event_id", name="uq_extension_version_change_event"),
    )
    for name, columns in (
        ("idx_extension_version_changes_observed", ["observed_at"]),
        ("idx_extension_version_changes_extension", ["extension_id", "observed_at"]),
        ("idx_extension_version_changes_installation", ["inventory_key", "observed_at"]),
    ):
        op.create_index(name, "extension_version_changes", columns)


def downgrade():
    op.drop_table("extension_version_changes")
    op.drop_table("extension_inventory")
