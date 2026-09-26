"""Catalog matcher: matches events against the catalog index.

Improvements over v1:
- Subdomain fallback (api.openai.com → openai.com)
- User-Agent matching (now wired via event.user_agent field)
- Confidence floor for ambiguous ports (8080, 3000, etc.)
- Returns best match by confidence, not first match
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


class CatalogMatcher:
    """Matches canonical events against the catalog index.

    Returns the single best match (highest confidence) rather than first-match-wins,
    so that a high-specificity signal is never shadowed by a lower one evaluated earlier.
    """

    def __init__(self, index: CatalogIndex):
        self._index = index

    def match_event(self, event: CanonicalEvent) -> CatalogMatch | None:
        """Match an event against the catalog. Returns best match by confidence."""
        if event.source_type == "directory":
            return None
        candidates: list[CatalogMatch] = []

        # 1. Extension ID (highest specificity)
        if event.extension_id and event.extension_id in self._index.extension_index:
            candidates.append(
                CatalogMatch(
                    catalog_item_id=self._index.extension_index[event.extension_id],
                    matched_field="extension_id",
                    matched_value=event.extension_id,
                    match_confidence=SIGNAL_CONFIDENCE["extension_id"],
                )
            )

        # 2. OAuth App ID
        if event.oauth_app_id and event.oauth_app_id in self._index.oauth_app_index:
            candidates.append(
                CatalogMatch(
                    catalog_item_id=self._index.oauth_app_index[event.oauth_app_id],
                    matched_field="oauth_app_id",
                    matched_value=event.oauth_app_id,
                    match_confidence=SIGNAL_CONFIDENCE["oauth_app_id"],
                )
            )

        # 3. Container image pattern
        if event.container_image:
            for pattern, item_id in self._index.container_pattern_index:
                if pattern.match(event.container_image):
                    candidates.append(
                        CatalogMatch(
                            catalog_item_id=item_id,
                            matched_field="container_image",
                            matched_value=event.container_image,
                            match_confidence=SIGNAL_CONFIDENCE["container_image"],
                        )
                    )
                    break

        # 4. Process name + optional port boost
        if event.process_name:
            proc_lower = event.process_name.lower().removesuffix(".exe")
            if proc_lower in self._index.process_index:
                confidence = SIGNAL_CONFIDENCE["process_name"]
                if event.local_port and event.local_port in self._index.port_index:
                    port_item = self._index.port_index[event.local_port]
                    if port_item == self._index.process_index[proc_lower]:
                        confidence = SIGNAL_CONFIDENCE["process_port"]
                candidates.append(
                    CatalogMatch(
                        catalog_item_id=self._index.process_index[proc_lower],
                        matched_field="process_name",
                        matched_value=event.process_name,
                        match_confidence=confidence,
                    )
                )

        # 5. Port alone (only if process didn't match AND port is not generic)
        if event.local_port and event.local_port not in GENERIC_PORTS and event.local_port in self._index.port_index:
            port_item = self._index.port_index[event.local_port]
            already_matched = any(c.catalog_item_id == port_item for c in candidates)
            if not already_matched:
                confidence = SIGNAL_CONFIDENCE["port_only"]
                if event.local_port in GENERIC_PORTS:
                    confidence = 0.30  # Very low for generic ports
                candidates.append(
                    CatalogMatch(
                        catalog_item_id=port_item,
                        matched_field="local_port",
                        matched_value=str(event.local_port),
                        match_confidence=confidence,
                    )
                )

        # 6. URL pattern match
        if event.url_path:
            for pattern, item_id in self._index.url_pattern_index:
                if pattern.match(event.url_path):
                    candidates.append(
                        CatalogMatch(
                            catalog_item_id=item_id,
                            matched_field="url_pattern",
                            matched_value=event.url_path,
                            match_confidence=SIGNAL_CONFIDENCE["url_pattern"],
                        )
                    )
                    break

        # 7. Domain match with subdomain fallback
        is_proxy = event.source_type == "proxy"
        for domain_field in [event.url_host, event.domain, event.sni]:
            if not domain_field:
                continue
            domain_lower = domain_field.lower().rstrip(".")

            # Exact match first
            if domain_lower in self._index.domain_index:
                confidence = SIGNAL_CONFIDENCE["domain_proxy"] if is_proxy else SIGNAL_CONFIDENCE["domain_dns"]
                candidates.append(
                    CatalogMatch(
                        catalog_item_id=self._index.domain_index[domain_lower],
                        matched_field="domain",
                        matched_value=domain_field,
                        match_confidence=confidence,
                    )
                )
                break

            # Subdomain fallback: try parent domains
            for parent in _domain_parents(domain_lower):
                if parent in self._index.domain_index:
                    confidence = (
                        SIGNAL_CONFIDENCE["subdomain_proxy"] if is_proxy else SIGNAL_CONFIDENCE["subdomain_dns"]
                    )
                    candidates.append(
                        CatalogMatch(
                            catalog_item_id=self._index.domain_index[parent],
                            matched_field="domain",
                            matched_value=f"{domain_field} (via {parent})",
                            match_confidence=confidence,
                        )
                    )
                    break
            else:
                continue
            break

        # 8. User-Agent pattern match
        if event.user_agent:
            for pattern, item_id in self._index.user_agent_pattern_index:
                if pattern.match(event.user_agent):
                    candidates.append(
                        CatalogMatch(
                            catalog_item_id=item_id,
                            matched_field="user_agent",
                            matched_value=event.user_agent,
                            match_confidence=SIGNAL_CONFIDENCE["user_agent"],
                        )
                    )
                    break

        if not candidates:
            return None

        # Return the highest-confidence match
        return max(candidates, key=lambda c: c.match_confidence)
