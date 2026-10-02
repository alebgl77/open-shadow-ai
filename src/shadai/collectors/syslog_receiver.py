"""Syslog TCP+UDP collector."""

from __future__ import annotations

import asyncio

import redis.asyncio as aioredis
import structlog
import yaml
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from shadai.collectors.base import BaseCollector
from shadai.config import load_config
from shadai.engine.catalog_loader import load_database_catalog
from shadai.parsers.base import BaseParser, get_parser

logger = structlog.get_logger()


class SyslogCollector(BaseCollector):
    """Asyncio-based syslog listener supporting TCP and UDP."""

    def __init__(
        self,
        collector_id: str,
        parser: BaseParser,
        redis_client: aioredis.Redis,
        host: str = "0.0.0.0",
        port: int = 1514,
        protocol: str = "tcp",
        catalog_loader=None,
    ):
        super().__init__(collector_id, parser, redis_client, catalog_loader)
        self.host = host
        self.port = port
        self.protocol = protocol.lower()

    async def run(self) -> None:
        if self.protocol == "tcp":
            await self._run_tcp()
        elif self.protocol == "udp":
            await self._run_udp()
        else:
            await asyncio.gather(self._run_tcp(), self._run_udp())

    async def _run_tcp(self) -> None:
        server = await asyncio.start_server(self._handle_tcp_connection, self.host, self.port)
        logger.info("syslog_tcp_started", host=self.host, port=self.port, collector=self.collector_id)
        async with server:
            await server.serve_forever()

    async def _handle_tcp_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        logger.debug("syslog_tcp_connect", peer=str(addr))
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip()
                if line:
                    await self._process_line(line)
        except Exception as e:
            logger.warning("syslog_tcp_error", error_type=type(e).__name__, peer=str(addr))
        finally:
            writer.close()
            await writer.wait_closed()

    async def _run_udp(self) -> None:
        loop = asyncio.get_running_loop()
        protocol = SyslogUDPProtocol(self)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=(self.host, self.port),
        )
        logger.info("syslog_udp_started", host=self.host, port=self.port, collector=self.collector_id)
        try:
            await asyncio.Future()  # Run forever
        finally:
            transport.close()
            for task in protocol.tasks:
                task.cancel()
            await asyncio.gather(*protocol.tasks, return_exceptions=True)

    async def _process_line(self, line: str) -> None:
        event = self.parser.parse(line)
        if event:
            await self.push_events([event])


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, collector: SyslogCollector):
        self.collector = collector
        self.tasks = set()

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        line = data.decode("utf-8", errors="replace").strip()
        if line and len(self.tasks) < 1000:
            task = asyncio.create_task(self.collector._process_line(line))
            self.tasks.add(task)
            task.add_done_callback(self._finished)

    def _finished(self, task):
        self.tasks.discard(task)
        if not task.cancelled() and task.exception():
            logger.warning("syslog_udp_failed", error_type=type(task.exception()).__name__)


# ── Entry point ──────────────────────────────────────────────────
async def main() -> None:
    config = load_config()
    redis_client = aioredis.from_url(config.database.redis_url, decode_responses=True)
    engine = create_async_engine(config.database.postgres_url, pool_pre_ping=True, pool_size=2, max_overflow=0)
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def load_catalog():
        async with sessions() as session:
            return await load_database_catalog(session)

    # Load sources config
    sources_path = "/app/config/sources.yaml"
    try:
        with open(sources_path) as f:
            sources_config = yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("no_sources_config", path=sources_path)
        sources_config = {}

    collectors = []
    for source in sources_config.get("sources", []):
        if source.get("type") != "syslog" or not source.get("enabled", False):
            continue
        parser_name = source["config"]["parser"]
        # Zone for device-local timestamps that carry no offset (IANA name, default UTC).
        parser = get_parser(parser_name, timezone=source["config"].get("timezone", "UTC"))
        collector = SyslogCollector(
            collector_id=source["name"],
            parser=parser,
            redis_client=redis_client,
            host="0.0.0.0",
            port=source["config"].get("listen_port", 1514),
            protocol=source["config"].get("protocol", "tcp"),
            catalog_loader=load_catalog,
        )
        collectors.append(collector.run())

    if not collectors:
        # Default: listen on 1514 TCP+UDP with BIND parser as fallback
        from shadai.parsers.dns.bind import BindQueryLogParser

        parser = BindQueryLogParser()
        collector = SyslogCollector(
            "default-syslog", parser, redis_client, port=1514, protocol="both", catalog_loader=load_catalog
        )
        collectors.append(collector.run())

    logger.info("starting_collectors", count=len(collectors))
    try:
        await asyncio.gather(*collectors)
    finally:
        await redis_client.aclose()
        await engine.dispose()


if __name__ == "__main__":
    # Register all parsers
    import shadai.parsers.dns.bind  # noqa: F401
    import shadai.parsers.dns.windows_dns  # noqa: F401
    import shadai.parsers.proxy.fortigate  # noqa: F401
    import shadai.parsers.proxy.paloalto  # noqa: F401
    import shadai.parsers.proxy.squid  # noqa: F401

    asyncio.run(main())
