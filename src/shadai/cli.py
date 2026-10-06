"""CLI commands for ShadAI administration."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from shadai.config import load_config


async def _init_db() -> None:
    """Run Alembic migrations to create/update all tables."""
    import subprocess

    result = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], capture_output=True, text=True)
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    print("Database initialized successfully.")


async def _create_admin() -> None:
    """Create the initial admin user interactively."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from shadai.models.user import UserORM
    from shadai.security.auth import hash_password

    config = load_config()
    engine = create_async_engine(config.database.postgres_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    username = input("Admin username: ").strip()
    email = input("Admin email: ").strip()
    password = getpass.getpass("Admin password: ")
    confirm = getpass.getpass("Confirm password: ")

    if password != confirm:
        print("Passwords do not match.", file=sys.stderr)
        sys.exit(1)

    if len(password) < 12 or len(password.encode()) > 72:
        print("Password must be at least 12 characters and at most 72 UTF-8 bytes.", file=sys.stderr)
        sys.exit(1)

    async with session_factory() as session:
        user = UserORM(
            username=username,
            email=email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
        )
        session.add(user)
        await session.commit()

    await engine.dispose()
    print(f"Admin user '{username}' created successfully.")


async def _sync_catalog():
    from shadai.database import close_all, get_postgres_session, init_postgres
    from shadai.engine.catalog_loader import sync_catalog

    config = load_config()
    await init_postgres(config.database)
    try:
        async for session in get_postgres_session():
            count = await sync_catalog(session, config.catalog)
        print(f"Catalog synchronized: {count} YAML entries; local changes preserved.")
    finally:
        await close_all()


def main() -> None:
    parser = argparse.ArgumentParser(prog="shadai", description="ShadAI CLI")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init-db", help="Run database migrations")
    subparsers.add_parser("create-admin", help="Create initial admin user")
    subparsers.add_parser("sync-catalog", help="Sync YAML catalog into PostgreSQL")

    from shadai.workers.redis_lifecycle import add_arguments
    add_arguments(subparsers.add_parser("queue-maintenance", help="Explicit Redis inventory/archive/retention"))

    args = parser.parse_args()

    if args.command == "queue-maintenance":
        import json

        from shadai.workers.redis_lifecycle import run
        try:
            print(json.dumps(asyncio.run(run(args)), separators=(",", ":")))
        except Exception as exc:
            print(json.dumps({"status": "retention_failed", "error_type": type(exc).__name__}))
            sys.exit(1)
    elif args.command == "init-db":
        asyncio.run(_init_db())
    elif args.command == "sync-catalog":
        asyncio.run(_sync_catalog())
    elif args.command == "create-admin":
        asyncio.run(_create_admin())
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
