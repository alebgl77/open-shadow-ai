from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from shadai.collectors.syslog_receiver import SyslogCollector
from shadai.models.event import CanonicalEvent
from shadai.parsers.base import get_parser
from shadai.parsers.dns.bind import BindQueryLogParser
from shadai.parsers.proxy.fortigate import FortiGateWebFilterParser
from shadai.parsers.proxy.paloalto import PaloAltoURLLogParser

FORTIGATE = 'date=2026-03-27 time=14:23:45 devname="FG-200F" hostname="chat.openai.com" srcip=10.0.0.5 {extra}'
EXPECTED = datetime(2026, 3, 27, 13, 23, 45, tzinfo=UTC)


@pytest.mark.parametrize(
    "extra",
    [
        'tz="+0100"',
        'tz="+01:00"',
        "eventtime=1774617825",
        "eventtime=1774617825000",
        "eventtime=1774617825000000",
        'eventtime=1774617825000000000 tz="+0100"',
    ],
)
def test_fortigate_uses_device_offset_or_epoch(extra):
    event = FortiGateWebFilterParser().parse(FORTIGATE.format(extra=extra))
    assert event.timestamp == EXPECTED


def test_fortigate_without_offset_uses_configured_source_zone():
    line = FORTIGATE.format(extra="")
    assert FortiGateWebFilterParser().parse(line).timestamp == EXPECTED + timedelta(hours=1)
    assert get_parser("fortigate_webfilter", timezone="Europe/Paris").parse(line).timestamp == EXPECTED
    summer = line.replace("2026-03-27", "2026-07-01")
    parsed = FortiGateWebFilterParser(timezone="Europe/Paris").parse(summer).timestamp
    assert parsed == datetime(2026, 7, 1, 12, 23, 45, tzinfo=UTC)
    with pytest.raises(ValueError, match="timezone"):
        get_parser("fortigate_webfilter", timezone="Mars/Olympus")


def test_recent_fortigate_events_from_utc_plus_zones_are_accepted():
    from shadai.api.ingestion import prepare_event

    now = datetime.now(UTC).replace(microsecond=0)
    local = now.astimezone(timezone(timedelta(hours=2)))
    line = f'date={local:%Y-%m-%d} time={local:%H:%M:%S} hostname=chat.openai.com srcip=10.0.0.5 tz="+0200"'
    event = prepare_event(FortiGateWebFilterParser().parse(line), trusted_collector=True)
    assert event.timestamp == now


def test_local_wall_clock_parsers_follow_source_zone():
    bind = (
        "27-Mar-2026 14:23:45.123 queries: info: client @0x1 10.0.0.5#5353 (chat.openai.com): "
        "query: chat.openai.com IN A +"
    )
    assert BindQueryLogParser(timezone="Europe/Paris").parse(bind).timestamp == EXPECTED
    pan = PaloAltoURLLogParser(timezone="Europe/Paris")
    assert pan._parse_timestamp("2026/03/27 14:23:45") == EXPECTED
    assert pan._parse_timestamp("2026-03-27T13:23:45Z") == EXPECTED
    recent = datetime.now(UTC).astimezone(pan.timezone) - timedelta(hours=1)
    stamp = pan._parse_timestamp(recent.strftime("%b %d %H:%M:%S"))
    assert abs(stamp - recent.replace(microsecond=0)) < timedelta(seconds=1)


async def test_rejected_event_does_not_drop_its_neighbours():
    redis = MagicMock()
    pipe = MagicMock()
    pipe.execute = AsyncMock()
    redis.pipeline.return_value = pipe
    collector = SyslogCollector("fw", FortiGateWebFilterParser(), redis)
    now = datetime.now(UTC)
    events = [
        CanonicalEvent(source_type="proxy", domain="chat.openai.com", timestamp=now),
        CanonicalEvent(source_type="proxy", domain="chat.openai.com", timestamp=now + timedelta(hours=2)),
        CanonicalEvent(source_type="proxy", domain="claude.ai", timestamp=now),
    ]
    assert await collector.push_events(events) == 2
    assert pipe.xadd.call_count == 2
    pipe.execute.assert_awaited_once()
    assert await collector.push_events(events[1:2]) == 0
    assert pipe.execute.await_count == 1
