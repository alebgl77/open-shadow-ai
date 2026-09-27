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
    """In-memory index for fast event-to-catalog matching.

    Several items may share a signature (a vendor's API and chat products on one host,
    a common SDK user agent). Exact keys keep every owner and patterns keep their
    specificity, so attribution never depends on the order items were loaded.
    """

    def __init__(self):
        self.domain_index: dict[str, tuple[str, ...]] = {}  # domain -> catalog_item_ids
        self.url_pattern_index: list[tuple[int, re.Pattern, str]] = []  # (specificity, regex, item)
        self.process_index: dict[str, tuple[str, ...]] = {}  # process name (lower, no .exe)
        self.extension_index: dict[str, tuple[str, ...]] = {}
        self.oauth_app_index: dict[str, tuple[str, ...]] = {}
        self.port_index: dict[int, tuple[str, ...]] = {}
        self.container_pattern_index: list[tuple[int, re.Pattern, str]] = []
        self.user_agent_pattern_index: list[tuple[int, re.Pattern, str]] = []
        self.items: dict[str, CatalogItemRead] = {}


def _glob_to_regex(pattern: str) -> re.Pattern:
    """Convert a glob pattern (fnmatch) to a compiled regex."""
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE)


def _add_owner(index: dict, key, item_id: str) -> None:
    owners = index.get(key, ())
    if item_id not in owners:
        index[key] = tuple(sorted((*owners, item_id)))


def _add_pattern(index: list, pattern: str, item_id: str) -> None:
    try:
        compiled = _glob_to_regex(pattern)
    except re.error:
        return
    # Literal characters measure specificity: "/v1/chat/completions" outranks "/v1/*".
    index.append((len(pattern) - sum(pattern.count(c) for c in "*?[]"), compiled, item_id))


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

    for item in sorted(items, key=lambda entry: entry.catalog_item_id):
        if item.status != "active":
            continue

        item_id = item.catalog_item_id
        index.items[item_id] = item
        for domain in item.domains:
            _add_owner(index.domain_index, domain.lower().rstrip("."), item_id)
        for proc in item.processes:
            _add_owner(index.process_index, proc.lower().removesuffix(".exe"), item_id)
        for ext_id in item.extension_ids:
            _add_owner(index.extension_index, ext_id, item_id)
        for oauth_id in item.oauth_app_ids:
            _add_owner(index.oauth_app_index, oauth_id, item_id)
        for port in item.local_ports:
            _add_owner(index.port_index, port, item_id)
        for pattern in item.url_patterns:
            _add_pattern(index.url_pattern_index, pattern, item_id)
        for pattern in item.container_patterns:
            _add_pattern(index.container_pattern_index, pattern, item_id)
        for pattern in item.user_agent_patterns:
            _add_pattern(index.user_agent_pattern_index, pattern, item_id)

    for patterns in (index.url_pattern_index, index.container_pattern_index, index.user_agent_pattern_index):
        patterns.sort(key=lambda entry: (-entry[0], entry[2], entry[1].pattern))

    shared = sum(
        len(owners) > 1
        for table in (index.domain_index, index.process_index, index.extension_index, index.port_index)
        for owners in table.values()
    )
    logger.info(
        "catalog_index_built",
        domains=len(index.domain_index),
        processes=len(index.process_index),
        extensions=len(index.extension_index),
        ports=len(index.port_index),
        shared_signatures=shared,
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
