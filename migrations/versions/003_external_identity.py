"""Add explicit SCIM authority and monotonic session revocation.

Revision ID: 003
Revises: 002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "003"
down_revision = "002_reliable_ingest"
branch_labels = None
depends_on = None


def normalized_usernames(rows):
    """Preflight BEFORE schema changes: never silently merge local identities."""
    seen, result = set(), []
    for user_id, username in rows:
        key = username.strip().casefold()
        if not key or key in seen:
            raise RuntimeError(
                "Identity migration blocked by empty or case-insensitive duplicate usernames. "
                "Rename conflicting local accounts explicitly, then rerun alembic upgrade head."
            )
        seen.add(key)
        result.append({"user_id": user_id, "key": key})
    return result


def upgrade():
    connection = op.get_bind()
    # Migration requires online data preflight. Alembic holds the schema transaction.
    connection.execute(sa.text("LOCK TABLE users IN ACCESS EXCLUSIVE MODE"))
    rows = normalized_usernames(connection.execute(sa.text("SELECT user_id, username FROM users")))
    op.add_column("users", sa.Column("username_key", sa.Text(), nullable=True))
    if rows:
        connection.execute(sa.text("UPDATE users SET username_key=:key WHERE user_id=:user_id"), rows)
    op.alter_column("users", "username_key", nullable=False)
    op.create_index("uq_users_username_key", "users", ["username_key"], unique=True)
    for column in (
        sa.Column("identity_kind", sa.String(16), nullable=False, server_default="local"),
        sa.Column("oidc_issuer", sa.String(1024)),
        sa.Column("external_id", sa.String(255)),
        sa.Column("session_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scim_deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("display_name", sa.String(255)),
        sa.Column("given_name", sa.String(255)),
        sa.Column("family_name", sa.String(255)),
        sa.Column("scim_emails", postgresql.JSONB(), nullable=False, server_default="[]"),
    ):
        op.add_column("users", column)
    op.create_unique_constraint("uq_users_external_identity", "users", ["oidc_issuer", "external_id"])
    op.create_table(
        "scim_groups",
        sa.Column("group_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("external_id", sa.String(255), unique=True, nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("deleted", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "scim_memberships",
        sa.Column(
            "group_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scim_groups.group_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )
    op.create_index("idx_scim_membership_user", "scim_memberships", ["user_id"])
    op.alter_column("audit_log", "user_id", nullable=True)
    op.add_column("audit_log", sa.Column("actor_kind", sa.String(16), nullable=False, server_default="user"))


def downgrade():
    connection = op.get_bind()
    incompatible = connection.execute(
        sa.text(
            "SELECT EXISTS(SELECT 1 FROM users WHERE identity_kind <> 'local' OR session_version <> 0) "
            "OR EXISTS(SELECT 1 FROM scim_groups) OR EXISTS(SELECT 1 FROM audit_log WHERE user_id IS NULL)"
        )
    ).scalar()
    if incompatible:
        raise RuntimeError(
            "Downgrade blocked: external identities, groups, service audit records or revoked sessions exist. "
            "Restore a pre-003 backup in an isolated deployment; do not discard identity authority or revocations."
        )
    op.drop_column("audit_log", "actor_kind")
    op.alter_column("audit_log", "user_id", nullable=False)
    op.drop_table("scim_memberships")
    op.drop_table("scim_groups")
    op.drop_constraint("uq_users_external_identity", "users", type_="unique")
    op.drop_index("uq_users_username_key", table_name="users")
    for name in (
        "username_key",
        "identity_kind",
        "oidc_issuer",
        "external_id",
        "session_version",
        "scim_deleted",
        "display_name",
        "given_name",
        "family_name",
        "scim_emails",
    ):
        op.drop_column("users", name)
