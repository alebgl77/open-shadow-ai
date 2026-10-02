"""Catalog matcher: matches events against the catalog index.

Improvements over v1:
- Subdomain fallback (api.openai.com → openai.com)
- User-Agent matching (now wired via event.user_agent field)
- Confidence floor for ambiguous ports (8080, 3000, etc.)
- Returns best match by confidence, not first match
- Shared signatures resolve deterministically, independent of catalog order
"""

from __future__ import annotations

from pydantic import BaseModel

from shadai.engine.catalog_loader import CatalogIndex
from shadai.models.event import CanonicalEvent


class CatalogMatch(BaseModel):
    """Result of matching an event against the catalog."""

    catalog_item_id: str
    matched_field: str
    matched_value: str
    match_confidence: float


# Base confidence scores per signal type (from PRD section 1.3)
SIGNAL_CONFIDENCE: dict[str, float] = {
    "extension_id": 0.95,
    "oauth_app_id": 0.95,
    "process_port": 0.95,
    "container_image": 0.95,
    "process_name": 0.90,
    "url_pattern": 0.90,
    "user_agent": 0.90,
    "domain_proxy": 0.85,
    "domain_dns": 0.60,
    "port_only": 0.50,
    "subdomain_proxy": 0.75,
    "subdomain_dns": 0.50,
}

# Ports too generic for standalone matching (high false positive risk)
GENERIC_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 8888}


def _domain_parents(domain: str) -> list[str]:
    """Generate parent domains for subdomain fallback.
    e.g., 'api.chat.openai.com' → ['chat.openai.com', 'openai.com']
    """
    parts = domain.split(".")
    parents = []
    for i in range(1, len(parts) - 1):
        parent = ".".join(parts[i:])
        if "." in parent:  # need at least x.y
            parents.append(parent)
    return parents


def _event_hosts(event: CanonicalEvent) -> frozenset[str]:
    hosts = set()
    for value in (event.url_host, event.domain, event.sni):
        host = value.lower().rstrip(".")
        name, colon, port = host.rpartition(":")
        hosts.add(name if colon and port.isdigit() and ":" not in name else host)
    return frozenset(hosts - {""})


def _in_scope(scope: tuple[str, ...] | None, hosts: frozenset[str]) -> bool:
    return scope is None or any(host == allowed or host.endswith("." + allowed) for host in hosts for allowed in scope)


def _pattern_matches(entries: list, value: str, hosts: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    """(item, catalog pattern) for the most specific in-scope match; entries are sorted by specificity."""
    best, found = None, set()
    for entry in entries:
        if best is not None and entry.specificity < best:
            break
        if _in_scope(entry.hosts, hosts) and entry.regex.match(value):
            best = entry.specificity
            found.add((entry.item_id, entry.text))
    return sorted(found)


class CatalogMatcher:
    """Matches canonical events against the catalog index.

    Returns the single best match rather than first-match-wins. Shared signatures yield
    one candidate per owner; ties go to the item corroborated by more signal types, then
    to the lowest catalog ID, so the result never depends on catalog load order.
    """

    def __init__(self, index: CatalogIndex):
        self._index = index

    def upstream_match(self, event: CanonicalEvent) -> CatalogMatch | None:
        """A match the ingestion boundary computed from signals it then discarded."""
        if event.catalog_match_id not in self._index.items:
            return None  # none, or an entry that is no longer active
        return CatalogMatch(
            catalog_item_id=event.catalog_match_id,
            matched_field=event.match_field,
            matched_value="",
            match_confidence=event.match_confidence,
        )

    def match_event(self, event: CanonicalEvent) -> CatalogMatch | None:
        """Match an event against the catalog. Returns best match by confidence."""
        if event.source_type == "directory":
            return None
        candidates: list[CatalogMatch] = []
        hosts = _event_hosts(event)

        def add(owners, field: str, value: str, confidence: float) -> None:
            candidates.extend(
                CatalogMatch(
                    catalog_item_id=item_id, matched_field=field, matched_value=value, match_confidence=confidence
                )
                for item_id in owners
            )

        def add_patterns(matches: list[tuple[str, str]], field: str, confidence: float) -> None:
            # Report the catalog pattern: paths and user agents are evaluated, never repeated.
            for item_id, pattern in matches:
                add((item_id,), field, pattern, confidence)

        # 1. Extension ID (highest specificity)
        if event.extension_id:
            add(
                self._index.extension_index.get(event.extension_id, ()),
                "extension_id",
                event.extension_id,
                SIGNAL_CONFIDENCE["extension_id"],
            )

        # 2. OAuth App ID
        if event.oauth_app_id:
            add(
                self._index.oauth_app_index.get(event.oauth_app_id, ()),
                "oauth_app_id",
                event.oauth_app_id,
                SIGNAL_CONFIDENCE["oauth_app_id"],
            )

        # 3. Container image pattern
        if event.container_image:
            add(
                [
                    item_id
                    for item_id, _ in _pattern_matches(self._index.container_pattern_index, event.container_image)
                ],
                "container_image",
                event.container_image,
                SIGNAL_CONFIDENCE["container_image"],
            )

        # 4. Process name + optional port boost
        port_owners = self._index.port_index.get(event.local_port, ()) if event.local_port else ()
        if event.process_name:
            for item_id in self._index.process_index.get(event.process_name.lower().removesuffix(".exe"), ()):
                confidence = SIGNAL_CONFIDENCE["process_port" if item_id in port_owners else "process_name"]
                add((item_id,), "process_name", event.process_name, confidence)

        # 5. Port alone (only if process didn't match AND port is not generic)
        if event.local_port not in GENERIC_PORTS:
            matched = {candidate.catalog_item_id for candidate in candidates}
            add(
                [item_id for item_id in port_owners if item_id not in matched],
                "local_port",
                str(event.local_port),
                SIGNAL_CONFIDENCE["port_only"],
            )

        # 6. URL pattern match on the request's host; query strings are never evaluated
        if event.url_path and hosts:
            path = event.url_path.split("?", 1)[0].split("#", 1)[0]
            add_patterns(
                _pattern_matches(self._index.url_pattern_index, path, hosts),
                "url_pattern",
                SIGNAL_CONFIDENCE["url_pattern"],
            )

        # 7. Domain match with subdomain fallback (most specific parent first)
        is_proxy = event.source_type == "proxy"
        for domain_field in [event.url_host, event.domain, event.sni]:
            if not domain_field:
                continue
            domain_lower = domain_field.lower().rstrip(".")
            if owners := self._index.domain_index.get(domain_lower):
                confidence = SIGNAL_CONFIDENCE["domain_proxy"] if is_proxy else SIGNAL_CONFIDENCE["domain_dns"]
                add(owners, "domain", domain_field, confidence)
                break
            parent = next((p for p in _domain_parents(domain_lower) if p in self._index.domain_index), None)
            if parent:
                confidence = SIGNAL_CONFIDENCE["subdomain_proxy"] if is_proxy else SIGNAL_CONFIDENCE["subdomain_dns"]
                add(self._index.domain_index[parent], "domain", f"{domain_field} (via {parent})", confidence)
                break

        # 8. User-Agent pattern match
        if event.user_agent:
            add_patterns(
                _pattern_matches(self._index.user_agent_pattern_index, event.user_agent, hosts),
                "user_agent",
                SIGNAL_CONFIDENCE["user_agent"],
            )

        if not candidates:
            return None

        best: dict[str, CatalogMatch] = {}
        support: dict[str, set[str]] = {}
        for candidate in candidates:
            item_id = candidate.catalog_item_id
            support.setdefault(item_id, set()).add(candidate.matched_field)
            if item_id not in best or candidate.match_confidence > best[item_id].match_confidence:
                best[item_id] = candidate
        return min(
            best.values(),
            key=lambda c: (-c.match_confidence, -len(support[c.catalog_item_id]), c.catalog_item_id),
        )
