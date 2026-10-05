"""Reviewed service domains and label boundaries for passive network metadata."""

from pathlib import Path

import pytest
import yaml

from shadai.engine.catalog_loader import build_catalog_index, load_catalog_from_yaml
from shadai.engine.matcher import CatalogMatcher
from shadai.models.catalog import CatalogItemRead, CatalogYAMLEntry
from shadai.models.event import CanonicalEvent

ROOT = Path(__file__).resolve().parents[1]
BUILTIN = ROOT / "catalog" / "builtin"
DOMAINS = [
    ("supermaven.com", "supermaven", "code_assistant"),
    ("udio.com", "udio", "voice_ai"),
    ("fal.ai", "fal-ai", "ai_platform"),
    ("fal.run", "fal-ai", "ai_platform"),
    ("queue.fal.run", "fal-ai", "ai_platform"),
    ("windsurf.com", "codeium", "code_assistant"),
    ("codeiumdata.com", "codeium", "code_assistant"),
    ("grok.com", "grok", "llm_chat"),
    ("cursor.com", "cursor", "code_assistant"),
    ("cursorapi.com", "cursor", "code_assistant"),
    ("marketplace.cursorapi.com", "cursor", "code_assistant"),
    ("suno.com", "suno", "voice_ai"),
    ("app.suno.ai", "suno", "voice_ai"),
]


@pytest.fixture(scope="module")
def catalog():
    return build_catalog_index(load_catalog_from_yaml(str(BUILTIN), str(ROOT / "catalog" / "local")))


def network_event(host, protocol="TLS"):
    field = "domain" if protocol == "DNS" else "url_host" if protocol == "HTTP" else "sni"
    return CanonicalEvent(source_type="network", protocol=protocol, collector_id="catalog-test", **{field: host})


def test_builtin_ids_and_reviewed_domains_are_unique(catalog):
    entries = [CatalogYAMLEntry(**yaml.safe_load(path.read_text())) for path in sorted(BUILTIN.glob("*.yaml"))]
    assert len({entry.id for entry in entries}) == len(entries) == len(catalog.items)
    for domain, item_id, category in DOMAINS:
        # Subdomains use the suffix matcher; exact reviewed roots have a single owner.
        owners = catalog.domain_index.get(domain)
        if owners:
            assert owners == (item_id,)
        assert catalog.items[item_id].category == category


@pytest.mark.parametrize("domain,item_id,category", DOMAINS)
@pytest.mark.parametrize("protocol", ["DNS", "TLS", "QUIC", "HTTP"])
def test_reviewed_network_domains_match_existing_categories(catalog, domain, item_id, category, protocol):
    event = network_event(domain.upper() + ".", protocol)
    resolution = CatalogMatcher(catalog).resolve_event(event)
    assert not resolution.ambiguous
    assert resolution.match.catalog_item_id == item_id
    assert catalog.items[resolution.match.catalog_item_id].category == category
    assert resolution.match.matched_field == "domain"


@pytest.mark.parametrize("domain,item_id,category", [
    entry for entry in DOMAINS if entry[0] not in {"queue.fal.run", "marketplace.cursorapi.com"}
])
@pytest.mark.parametrize("template", ["evil{}", "{}.evil.example", "prefix-{}"])
def test_reviewed_network_domain_label_boundaries(catalog, domain, item_id, category, template):
    event = network_event(template.format(domain))
    assert CatalogMatcher(catalog).match_event(event) is None


@pytest.mark.parametrize("domain", ["googleapis.com", "github.com", "api2.cursor.com.evil.example"])
def test_generic_infrastructure_and_suffix_attacks_remain_unattributed(catalog, domain):
    assert CatalogMatcher(catalog).match_event(network_event(domain)) is None


def test_existing_family_ids_and_signatures_are_preserved(catalog):
    assert {"codeium.com", "api.codeium.com", "server.codeium.com"} <= set(catalog.items["codeium"].domains)
    assert {"cursor.sh", "api2.cursor.sh", "www.cursor.com"} <= set(catalog.items["cursor"].domains)
    assert {"grok.x.ai", "api.x.ai", "console.x.ai"} <= set(catalog.items["grok"].domains)
    assert "Windsurf" in catalog.items["codeium"].aliases
    assert "Legacy" in catalog.items["supermaven"].description


def test_shared_reviewed_domain_remains_ambiguous(catalog):
    service = catalog.items["supermaven"]
    other = CatalogItemRead(
        catalog_item_id="synthetic-other", canonical_name="Synthetic other", category="code_assistant",
        domains=["supermaven.com"],
    )
    event = network_event("supermaven.com")
    for entries in ([service, other], [other, service]):
        resolution = CatalogMatcher(build_catalog_index(entries)).resolve_event(event)
        assert resolution.ambiguous and resolution.match is None
