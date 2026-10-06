"""Lab-only same-loop suspended handler witness, without event or store data."""

import asyncio
import json

from shadai.workers.probe import ProcessProbe, local_check


async def witness():
    async with ProcessProbe("ingest") as probe:
        probe.mark_initialized()
        probe.poll()
        async with probe.phase("handler"):
            # A never-completing async I/O operation still yields to this exact
            # process' heartbeat loop. A blocking SIGSTOP cannot do that.
            reader = asyncio.StreamReader()
            task = asyncio.create_task(reader.read(1))
            try:
                await asyncio.sleep(12)
                result = {
                    "live": local_check("liveness", "ingest"),
                    "locally_ready": local_check("readiness", "ingest"),
                    "handler_budget_seconds": 10,
                }
                print(json.dumps(result))
                if not result["live"] or result["locally_ready"]:
                    raise RuntimeError("Suspended handler probe contract failed")
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    import os

    os.environ["SHADAI_PROBE_HANDLER_SECONDS"] = "10"
    asyncio.run(witness())
