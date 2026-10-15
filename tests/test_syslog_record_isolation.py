"""Malformed TCP input is isolated from following records and delivery failures."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from queue_fakes import admission_fake

from shadai.collectors import syslog_receiver
from shadai.collectors.syslog_receiver import SyslogCollector, SyslogUDPProtocol
from shadai.models.event import CanonicalEvent
from shadai.parsers.proxy.squid import SquidAccessLogParser

PRIVATE_MARKER = "private-record-and-exception-canary"


def squid_line(host="api.openai.com", port="443", *, timestamp=None):
    epoch = (timestamp or datetime.now(UTC)).timestamp()
    return f"{epoch:.3f} 2 192.0.2.10 TCP_TUNNEL/200 34 CONNECT {host}:{port} - HIER_DIRECT/198.51.100.20 -\n"


def connection(lines):
    reader = SimpleNamespace(readline=AsyncMock(side_effect=[*(line.encode() for line in lines), b""]))
    writer = SimpleNamespace(
        get_extra_info=lambda field: ("192.0.2.10", 1234), close=MagicMock(), wait_closed=AsyncMock()
    )
    return reader, writer


def collector_with_admission():
    pipe = SimpleNamespace(xadd=MagicMock(), execute=AsyncMock())
    redis = admission_fake(SimpleNamespace(pipeline=lambda **kwargs: pipe), pipe)
    return SyslogCollector("synthetic-squid", SquidAccessLogParser(), redis), pipe


async def test_bad_squid_record_preserves_following_records_exactly_once(monkeypatch):
    collector, pipe = collector_with_admission()
    log = MagicMock()
    monkeypatch.setattr(syslog_receiver, "logger", log)
    reader, writer = connection([
        squid_line(port=PRIVATE_MARKER),
        squid_line("api.openai.com"),
        squid_line("claude.ai"),
    ])
    await collector._handle_tcp_connection(reader, writer)
    queued = [json.loads(call.args[1]["data"]) for call in pipe.xadd.call_args_list]
    assert [event["domain"] for event in queued] == ["api.openai.com", "claude.ai"]
    assert len({event["event_id"] for event in queued}) == 2
    assert pipe.execute.await_count == 2
    assert reader.readline.await_count == 4
    assert collector.counters["tcp_record_rejections"] == 1
    assert collector.counters["tcp_processing_failures"] == 0
    log.warning.assert_called_once_with(
        "syslog_record_rejected", collector="synthetic-squid", error_type="ValueError"
    )
    assert PRIVATE_MARKER not in str(log.mock_calls)
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()
    assert not collector.connections


@pytest.mark.parametrize("failure", [ValueError(PRIVATE_MARKER), OverflowError(PRIVATE_MARKER)])
async def test_only_parser_input_failures_are_skipped(failure, monkeypatch):
    collector, _ = collector_with_admission()
    event = CanonicalEvent(source_type="proxy")
    collector.parser = SimpleNamespace(parse=MagicMock(side_effect=[failure, None, event]))
    collector.push_events = AsyncMock()
    log = MagicMock()
    monkeypatch.setattr(syslog_receiver, "logger", log)
    reader, writer = connection([PRIVATE_MARKER, "comment", "valid"])
    await collector._handle_tcp_connection(reader, writer)
    collector.push_events.assert_awaited_once_with([event])
    assert collector.counters["tcp_record_rejections"] == 1
    assert collector.counters["tcp_processing_failures"] == 0
    assert PRIVATE_MARKER not in str(log.mock_calls)
    writer.wait_closed.assert_awaited_once()


async def test_all_valid_records_keep_existing_exactly_once_admission():
    collector, pipe = collector_with_admission()
    reader, writer = connection(["\n", "# comment\n", squid_line(), squid_line("claude.ai")])
    await collector._handle_tcp_connection(reader, writer)
    assert pipe.xadd.call_count == 2
    assert pipe.execute.await_count == 2
    assert collector.counters["tcp_record_rejections"] == 0
    assert collector.counters["tcp_processing_failures"] == 0


async def test_retention_rejection_keeps_next_valid_record():
    collector, pipe = collector_with_admission()
    reader, writer = connection([
        squid_line(timestamp=datetime.now(UTC) - timedelta(days=180)),
        squid_line(),
    ])
    await collector._handle_tcp_connection(reader, writer)
    assert pipe.xadd.call_count == 1
    assert pipe.execute.await_count == 1
    assert collector.counters["tcp_record_rejections"] == 0
    assert collector.counters["tcp_processing_failures"] == 0


@pytest.mark.parametrize("failure", [ValueError(PRIVATE_MARKER), OSError(PRIVATE_MARKER), RuntimeError(PRIVATE_MARKER)])
async def test_delivery_failure_still_closes_connection(failure, monkeypatch):
    collector, _ = collector_with_admission()
    collector.push_events = AsyncMock(side_effect=failure)
    log = MagicMock()
    monkeypatch.setattr(syslog_receiver, "logger", log)
    reader, writer = connection([squid_line(), squid_line("claude.ai")])
    await collector._handle_tcp_connection(reader, writer)
    collector.push_events.assert_awaited_once()
    assert reader.readline.await_count == 1
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    assert PRIVATE_MARKER not in str(log.mock_calls)
    writer.wait_closed.assert_awaited_once()
    assert not collector.connections


async def test_actual_spool_storage_failure_is_not_treated_as_input_rejection():
    collector, pipe = collector_with_admission()
    collector.spool = SimpleNamespace(enqueue=MagicMock(side_effect=ValueError(PRIVATE_MARKER)))
    reader, writer = connection([squid_line(), squid_line("claude.ai")])
    await collector._handle_tcp_connection(reader, writer)
    collector.spool.enqueue.assert_called_once()
    pipe.execute.assert_not_awaited()
    assert reader.readline.await_count == 1
    assert collector.counters["retention_failures"] == 1
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    writer.wait_closed.assert_awaited_once()


async def test_actual_queue_backpressure_failure_is_connection_fatal():
    collector, pipe = collector_with_admission()
    pipe.execute.side_effect = OSError(PRIVATE_MARKER)
    reader, writer = connection([squid_line(), squid_line("claude.ai")])
    await collector._handle_tcp_connection(reader, writer)
    assert reader.readline.await_count == 1
    assert pipe.execute.await_count == 1
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    writer.wait_closed.assert_awaited_once()


async def test_actual_spool_retry_failure_is_connection_fatal():
    collector, pipe = collector_with_admission()
    pipe.execute.side_effect = OSError(PRIVATE_MARKER)
    batch = SimpleNamespace(payload=json.dumps([{"stream": "events:proxy", "fields": {"data": "{}"}}]))
    collector.spool = SimpleNamespace(
        enqueue=MagicMock(),
        claim=MagicMock(return_value=[batch]),
        retry=MagicMock(side_effect=ValueError(PRIVATE_MARKER)),
    )
    reader, writer = connection([squid_line(), squid_line("claude.ai")])
    await collector._handle_tcp_connection(reader, writer)
    collector.spool.retry.assert_called_once_with(batch)
    assert reader.readline.await_count == 1
    assert collector.counters["delivery_failures"] == 1
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    writer.wait_closed.assert_awaited_once()


async def test_parser_programming_failure_remains_connection_fatal():
    collector, _ = collector_with_admission()
    collector.parser = SimpleNamespace(parse=MagicMock(side_effect=RuntimeError(PRIVATE_MARKER)))
    reader, writer = connection(["record", "following record"])
    await collector._handle_tcp_connection(reader, writer)
    assert reader.readline.await_count == 1
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    writer.wait_closed.assert_awaited_once()


async def test_reader_line_limit_failure_remains_connection_fatal():
    collector, pipe = collector_with_admission()
    reader, writer = connection([])
    reader.readline.side_effect = ValueError("Separator is not found, and chunk exceed the limit")
    await collector._handle_tcp_connection(reader, writer)
    pipe.execute.assert_not_awaited()
    assert collector.counters["tcp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    writer.wait_closed.assert_awaited_once()


@pytest.mark.parametrize("stage", ["parser", "delivery"])
async def test_cancellation_propagates_and_reaps_connection(stage):
    collector, _ = collector_with_admission()
    if stage == "parser":
        collector.parser = SimpleNamespace(parse=MagicMock(side_effect=asyncio.CancelledError))
    else:
        collector.push_events = AsyncMock(side_effect=asyncio.CancelledError)
    reader, writer = connection([squid_line(), squid_line("claude.ai")])
    with pytest.raises(asyncio.CancelledError):
        await collector._handle_tcp_connection(reader, writer)
    assert reader.readline.await_count == 1
    assert collector.counters["tcp_processing_failures"] == 0
    assert collector.counters["tcp_record_rejections"] == 0
    writer.close.assert_called_once()
    writer.wait_closed.assert_awaited_once()
    assert not collector.connections


async def test_udp_failure_reporting_and_budget_are_unchanged():
    collector, pipe = collector_with_admission()
    protocol = SyslogUDPProtocol(collector)
    protocol.datagram_received(squid_line(port=PRIVATE_MARKER).encode(), ("192.0.2.10", 1234))
    await asyncio.gather(*protocol.tasks, return_exceptions=True)
    assert collector.counters["udp_processing_failures"] == 1
    assert collector.counters["tcp_record_rejections"] == 0
    pipe.execute.assert_not_awaited()
    protocol.tasks = set(range(1000))
    protocol.datagram_received(squid_line().encode(), ("192.0.2.10", 1234))
    assert collector.counters["udp_task_drops"] == 1
