"""Reported PAN-OS event times survive import and enforce the shared age window."""

from datetime import UTC, datetime, timedelta

import pytest

from shadai.api import ingestion
from shadai.parsers.proxy import paloalto
from shadai.parsers.proxy.paloalto import PaloAltoURLLogParser

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
BODY = "src=192.0.2.10 dst=198.51.100.20 url=api.openai.com/backend-api dport=443"


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def frozen_clock(monkeypatch):
    monkeypatch.setattr(paloalto, "datetime", FrozenDatetime)
    monkeypatch.setattr(ingestion, "datetime", FrozenDatetime)


def header(stamp):
    return f"<14>1 {stamp} PA-5220 - - - - {BODY}"


@pytest.mark.parametrize("days_old", [0, 1, 180])
@pytest.mark.parametrize("source", ["header", "kv"])
def test_source_time_preserved_and_retention_rejects_old_input(days_old, source):
    stamp = NOW - timedelta(days=days_old)
    text = stamp.isoformat()
    line = header(text) if source == "header" else f"timestamp={text} {BODY}"
    event = PaloAltoURLLogParser().parse(line)
    assert event.timestamp == stamp
    if days_old == 180:
        with pytest.raises(ValueError, match="retention window"):
            ingestion.prepare_event(event, trusted_collector=True)
    else:
        assert ingestion.prepare_event(event, trusted_collector=True).timestamp == stamp


@pytest.mark.parametrize("field", ["receive_time", "time_generated", "timestamp"])
def test_explicit_valid_kv_timestamp_precedes_header(field):
    old_header = (NOW - timedelta(days=180)).isoformat()
    line = f"{header(old_header)} {field}={NOW.isoformat()}"
    event = PaloAltoURLLogParser().parse(line)
    assert ingestion.prepare_event(event, trusted_collector=True).timestamp == NOW


def test_reported_old_kv_time_cannot_be_replaced_by_recent_header():
    old = NOW - timedelta(days=180)
    event = PaloAltoURLLogParser().parse(f"{header(NOW.isoformat())} timestamp={old.isoformat()}")
    assert event.timestamp == old
    with pytest.raises(ValueError, match="retention window"):
        ingestion.prepare_event(event, trusted_collector=True)


def test_explicit_kv_field_priority_is_preserved():
    line = (
        f'{header(NOW.isoformat())} timestamp=2026-10-13T12:00:00Z '
        'time_generated="2026/10/14 12:00:00" receive_time="2026/10/15 12:00:00"'
    )
    assert PaloAltoURLLogParser().parse(line).timestamp == NOW


@pytest.mark.parametrize("field", ["receive_time", "time_generated", "timestamp"])
@pytest.mark.parametrize("stamp", ["", "-", "private-malformed-date", "2026-02-30T12:00:00Z"])
def test_explicit_invalid_kv_timestamp_rejected_even_with_valid_header(field, stamp):
    line = f'{header(NOW.isoformat())} {field}="{stamp}"'
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)


@pytest.mark.parametrize("stamp", ["-", "private-malformed-date", "2026-02-30T12:00:00Z", "2026-10-15T12:00:00"])
def test_invalid_or_missing_header_time_is_rejected(stamp):
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(header(stamp))


def test_missing_legacy_kv_source_time_is_rejected():
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(BODY)


@pytest.mark.parametrize("header_time", ["-", "invalid-header"])
def test_valid_explicit_kv_time_can_supply_missing_or_invalid_header_time(header_time):
    event = PaloAltoURLLogParser().parse(f"{header(header_time)} timestamp={NOW.isoformat()}")
    assert event.timestamp == NOW


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize(
    "stamp",
    ["2026-10-15T12:00:00Z", "2026-10-15T12:00:00.000000Z", "2026-10-15T14:00:00+02:00", "2026-10-15T07:00:00-05:00"],
)
def test_iso_timezones_preserve_instant_independently_of_source_zone(source, stamp):
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    event = PaloAltoURLLogParser(timezone="Europe/Paris").parse(line)
    assert event.timestamp == NOW
    assert event.timestamp.tzinfo is UTC


def test_local_kv_time_uses_configured_source_zone():
    event = PaloAltoURLLogParser(timezone="Europe/Paris").parse(f'receive_time="2026/10/15 14:00:00" {BODY}')
    assert ingestion.prepare_event(event, trusted_collector=True).timestamp == NOW


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize("stamp", ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"])
def test_reported_utc_overflow_is_a_sanitized_validation_error(source, stamp):
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)


@pytest.mark.parametrize(
    ("stamp", "zone"), [("0001/01/01 00:00:00", "Etc/GMT-1"), ("9999/12/31 23:59:59", "Etc/GMT+1")]
)
def test_local_time_conversion_bounds_are_sanitized(stamp, zone):
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser(timezone=zone).parse(f'receive_time="{stamp}" {BODY}')


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("0001-01-01T01:00:00+01:00", datetime.min.replace(tzinfo=UTC)),
        ("9999-12-31T22:59:59.999999-01:00", datetime.max.replace(tzinfo=UTC)),
    ],
)
def test_valid_utc_boundary_values_are_preserved(stamp, expected):
    assert PaloAltoURLLogParser().parse(header(stamp)).timestamp == expected


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("Oct 15 13:00:00", NOW - timedelta(hours=1)),
        ("Dec 31 23:59:59", datetime(2025, 12, 31, 22, 59, 59, tzinfo=UTC)),
    ],
)
def test_bsd_year_inference_uses_frozen_clock_and_source_zone(stamp, expected):
    event = PaloAltoURLLogParser(timezone="Europe/Paris").parse(f'timestamp="{stamp}" {BODY}')
    assert event.timestamp == expected


def test_future_reported_time_is_not_replaced_by_observation_time():
    future = NOW + timedelta(hours=1)
    event = PaloAltoURLLogParser().parse(header(future.isoformat()))
    assert event.timestamp == future
    with pytest.raises(ValueError, match="future"):
        ingestion.prepare_event(event, trusted_collector=True)


def test_csv_reported_source_time_is_preserved():
    parts = [""] * 32
    parts[1], parts[7], parts[8], parts[25], parts[31] = (
        "2026/10/15 14:00:00", "192.0.2.10", "198.51.100.20", "443", "api.openai.com/backend-api"
    )
    event = PaloAltoURLLogParser(timezone="Europe/Paris").parse(",".join(parts))
    assert event.timestamp == NOW


def test_non_url_input_still_does_not_produce_an_event():
    assert PaloAltoURLLogParser().parse("# header") is None


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize("sign", ["+", "-"])
@pytest.mark.parametrize("offset", ["02:75", "00:60", "24:00", "99:00", "23:60", "01:99"])
def test_malformed_offset_components_are_rejected_before_conversion(source, sign, offset):
    stamp = f"2026-10-15T12:00:00{sign}{offset}"
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize(
    "stamp",
    [
        "2026-W42-4T12:00:00Z",
        "2026-288T12:00:00Z",
        "20261015T120000Z",
        "2026-10-15",
        "2026-10-15X12:00:00Z",
        "2026-10-15t12:00:00Z",
        "2026-10-15T12:00:00z",
        "2026-10-15T12:00Z",
        "2026-10-15T24:00:00Z",
        "2026-10-15T12:60:00Z",
        "2026-10-15T12:00:60Z",
        "2026-10-15T12:00:00,1Z",
        "2026-10-15T12:00:00.1234567Z",
        "2026-10-15T12:00:00+0200",
        "2026-10-15T12:00:00+02",
        "2026-10-15T12:00:00+02:00:30",
        "2026-10-15T12:00:00+02:00.5",
    ],
)
def test_unsupported_iso_spelling_is_rejected(source, stamp):
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize("stamp", ["2026-02-29T12:00:00Z", "2026-13-15T12:00:00Z", "2026-10-00T12:00:00Z"])
def test_calendar_validation_still_rejects_nonexistent_dates(source, stamp):
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)


@pytest.mark.parametrize("source", ["header", "kv"])
@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("2026-10-15T12:00:00+00:00", NOW),
        ("2026-10-15T12:00:00-00:00", NOW),
        ("2026-10-15T17:30:00+05:30", NOW),
        ("2026-10-15T12:00:00+23:59", NOW - timedelta(hours=23, minutes=59)),
        ("2026-10-15T12:00:00-23:59", NOW + timedelta(hours=23, minutes=59)),
        ("2026-10-15T12:00:00.123456Z", NOW.replace(microsecond=123456)),
    ],
)
def test_valid_standard_offset_components_and_fraction_are_preserved(source, stamp, expected):
    line = header(stamp) if source == "header" else f"timestamp={stamp} {BODY}"
    assert PaloAltoURLLogParser(timezone="Europe/Paris").parse(line).timestamp == expected


@pytest.mark.parametrize(
    ("stamp", "expected"),
    [
        ("2026/10/15 14:00:00", NOW),
        ("Oct 15 13:00:00", NOW - timedelta(hours=1)),
        ("Oct  5 13:00:00", datetime(2026, 10, 5, 11, tzinfo=UTC)),
    ],
)
def test_legacy_local_and_bsd_spelling_remain_kv_only(stamp, expected):
    parser = PaloAltoURLLogParser(timezone="Europe/Paris")
    assert parser.parse(f'timestamp="{stamp}" {BODY}').timestamp == expected
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        parser._parse_timestamp(stamp, rfc5424=True)
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        parser.parse(header(stamp))


@pytest.mark.parametrize("stamp", ["2026/10/15 14:0:00", "Oct 15 13:0:00", "2026/1/15 14:00:00"])
def test_legacy_fallback_rejects_unsupported_spelling(stamp):
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(f'timestamp="{stamp}" {BODY}')


@pytest.mark.parametrize("stamp", ["2026-W42-4T12:00:00Z", "2026-10-15T12:00:00+02:75"])
def test_valid_kv_precedence_survives_strict_header_validation(stamp):
    event = PaloAltoURLLogParser().parse(f"{header(stamp)} timestamp={NOW.isoformat()}")
    assert event.timestamp == NOW


@pytest.mark.parametrize("field", ["receive_time", "time_generated", "timestamp"])
def test_invalid_kv_offset_is_not_replaced_by_valid_header(field):
    line = f"{header(NOW.isoformat())} {field}=2026-10-15T12:00:00+00:60"
    with pytest.raises(ValueError, match="^Invalid or missing Palo Alto event timestamp$"):
        PaloAltoURLLogParser().parse(line)
