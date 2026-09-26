"""Catalog loader: reads YAML files, builds in-memory indexes for fast matching."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

import structlog
import yaml

from shadai.config import CatalogSettings
from shadai.models.catalog import CatalogItemRead, CatalogYAMLEntry

logger = structlog.get_logger()


class CatalogIndex:
    """In-memory index for fast event-to-catalog matching."""

    def __init__(self):
        self.domain_index: dict[str, str] = {}  # domain -> catalog_item_id
        self.url_pattern_index: list[tuple[re.Pattern, str]] = []
        self.process_index: dict[str, str] = {}  # process name (lower) -> catalog_item_id
        self.extension_index: dict[str, str] = {}
        self.oauth_app_index: dict[str, str] = {}
        self.port_index: dict[int, str] = {}
        self.container_pattern_index: list[tuple[re.Pattern, str]] = []
        self.user_agent_pattern_index: list[tuple[re.Pattern, str]] = []
        self.items: dict[str, CatalogItemRead] = {}


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Convert a glob pattern (fnmatch) to a compiled regex."""
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


def load_catalog_from_yaml(builtin_path: str, local_path: str) -> list[CatalogItemRead]:
    """Load all catalog YAML files, with local overrides taking priority."""
    items: dict[str, CatalogItemRead] = {}

    # Load builtin
    for yaml_file in sorted(Path(builtin_path).glob("*.yaml")):
        try:
            with open(yaml_file) as f:
                raw = yaml.safe_load(f)
            if not raw:
                continue
            entry = CatalogYAMLEntry(**raw)
            items[entry.id] = CatalogItemRead(
                catalog_item_id=entry.id,
                canonical_name=entry.canonical_name,
                aliases=entry.aliases,
                category=entry.category,
                vendor=entry.vendor,
                description=entry.description,
                domains=entry.signatures.domains,
                url_patterns=entry.signatures.url_patterns,
                processes=entry.signatures.processes,
                extension_ids=entry.signatures.extension_ids,
                oauth_app_ids=entry.signatures.oauth_app_ids,
                local_ports=entry.signatures.local_ports,
                local_paths=entry.signatures.local_paths,
                container_patterns=entry.signatures.container_patterns,
                user_agent_patterns=entry.signatures.user_agent_patterns,
                rule_tags=entry.rule_tags,
                default_trust_level=entry.default_trust_level,
                source_of_truth="builtin",
            )
        except Exception as e:
            logger.warning("catalog_load_error", file=str(yaml_file), error=str(e))

    # Load local overrides (take priority)
    local_dir = Path(local_path)
    if local_dir.exists():
        for yaml_file in sorted(local_dir.glob("*.yaml")):
            try:
                with open(yaml_file) as f:
                    raw = yaml.safe_load(f)
                if not raw:
                    continue
                entry = CatalogYAMLEntry(**raw)
                items[entry.id] = CatalogItemRead(
                    catalog_item_id=entry.id,
                    canonical_name=entry.canonical_name,
                    aliases=entry.aliases,
                    category=entry.category,
                    vendor=entry.vendor,
                    description=entry.description,
                    domains=entry.signatures.domains,
                    url_patterns=entry.signatures.url_patterns,
                    processes=entry.signatures.processes,
                    extension_ids=entry.signatures.extension_ids,
                    oauth_app_ids=entry.signatures.oauth_app_ids,
                    local_ports=entry.signatures.local_ports,
                    local_paths=entry.signatures.local_paths,
                    container_patterns=entry.signatures.container_patterns,
                    user_agent_patterns=entry.signatures.user_agent_patterns,
                    rule_tags=entry.rule_tags,
                    default_trust_level=entry.default_trust_level,
                    source_of_truth="local",
                    local_override=True,
                )
            except Exception as e:
                logger.warning("catalog_local_load_error", file=str(yaml_file), error=str(e))

    logger.info("catalog_loaded", total=len(items))
    return list(items.values())


def build_catalog_index(items: list[CatalogItemRead]) -> CatalogIndex:
    """Build an in-memory index for O(1) lookups."""
    index = CatalogIndex()

    for item in items:
        if item.status != "active":
            continue

        index.items[item.catalog_item_id] = item

        # Domain index (exact, lowercased)
        for domain in item.domains:
            index.domain_index[domain.lower()] = item.catalog_item_id

        # URL pattern index (compiled regex)
        for pattern in item.url_patterns:
            try:
                index.url_pattern_index.append((_glob_to_regex(pattern), item.catalog_item_id))
            except re.error:
                pass

        # Process index (exact, lowercased, strip .exe)
        for proc in item.processes:
            name = proc.lower().removesuffix(".exe")
            index.process_index[name] = item.catalog_item_id

        # Extension index (exact)
        for ext_id in item.extension_ids:
            index.extension_index[ext_id] = item.catalog_item_id

        # OAuth app index (exact)
        for oauth_id in item.oauth_app_ids:
            index.oauth_app_index[oauth_id] = item.catalog_item_id

        # Port index (exact)
        for port in item.local_ports:
            index.port_index[port] = item.catalog_item_id

        # Container pattern index (compiled regex)
        for pattern in item.container_patterns:
            try:
                index.container_pattern_index.append((_glob_to_regex(pattern), item.catalog_item_id))
            except re.error:
                pass

        # User-Agent pattern index (compiled regex)
        for pattern in item.user_agent_patterns:
            try:
                index.user_agent_pattern_index.append((_glob_to_regex(pattern), item.catalog_item_id))
            except re.error:
                pass

    logger.info(
        "catalog_index_built",
        domains=len(index.domain_index),
        processes=len(index.process_index),
        extensions=len(index.extension_index),
        ports=len(index.port_index),
    )
    return index


class CatalogManager:
    """Manages catalog lifecycle: load, index, reload."""

    def __init__(self, settings: CatalogSettings):
        self._settings = settings
        self._items = load_catalog_from_yaml(settings.builtin_path, settings.local_path)
        self._index = build_catalog_index(self._items)

    def reload(self) -> None:
        self._items = load_catalog_from_yaml(self._settings.builtin_path, self._settings.local_path)
        self._index = build_catalog_index(self._items)

    def get_index(self) -> CatalogIndex:
        return self._index

    def get_items(self) -> list[CatalogItemRead]:
        return self._items


async def sync_catalog(session, settings: CatalogSettings) -> int:
    """Seed/update managed YAML rows, preserving every local/admin customization."""
    from sqlalchemy.dialects.postgresql import insert

    from shadai.models.catalog import CatalogItemORM

    items = load_catalog_from_yaml(settings.builtin_path, settings.local_path)
    if not items:
        raise RuntimeError("No catalog entries loaded; check configured catalog paths")
    for item in items:
        data = item.model_dump(exclude={"created_at", "updated_at", "last_reviewed_at"})
        data["local_ports"] = [str(port) for port in data["local_ports"]]
        statement = insert(CatalogItemORM).values(**data)
        statement = statement.on_conflict_do_update(
            index_elements=["catalog_item_id"],
            set_={key: value for key, value in data.items() if key != "catalog_item_id"},
            where=(CatalogItemORM.local_override.is_(False) & (CatalogItemORM.source_of_truth == "builtin")),
        )
        await session.execute(statement)
    return len(items)


async def load_database_catalog(session):
    from sqlalchemy import select

    from shadai.models.catalog import CatalogItemORM

    result = await session.execute(select(CatalogItemORM).where(CatalogItemORM.status == "active"))
    return build_catalog_index([CatalogItemRead.model_validate(item) for item in result.scalars().all()])
