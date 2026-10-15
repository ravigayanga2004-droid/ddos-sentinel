"""Paced built-in HTTP scenarios. No arbitrary targets, redirects, proxies or packets."""

import asyncio
import time
from collections.abc import Callable
from typing import Any

import httpx

from ddos_sentinel.core.audit import audit
from ddos_sentinel.core.models import new_id
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.service import TemporaryLab

Observer = Callable[[str, float], None]


def endpoint_for(scenario: str, index: int, body_size: int) -> str:
    if body_size:
        return "/api/test"
    special = {
        "endpoint-concentration": "/api/test",
        "slow-request-pattern": "/slow-test",
        "error-spike": "/error-test",
    }
    return special.get(scenario, ("/", "/health", "/api/test")[index % 3])


async def simulate(
    lab: TemporaryLab,
    options: SimulationOptions,
    observer: Observer | None = None,
) -> dict[str, Any]:
    """Run one authorized experiment; finalize status even if its task is cancelled."""
    options.check(lab.config.limits)
    if lab.authorization is None:
        raise ValueError("start an owned temporary service before simulating")
    target = lab.authorization.require(lab.target, options.authorized)
    if lab.simulation_lock.locked():
        raise ValueError("a simulation is already active in this lab")
    async with lab.simulation_lock:
        return await _run(lab, options, target, observer)


async def _run(
    lab: TemporaryLab,
    options: SimulationOptions,
    target: str,
    observer: Observer | None,
) -> dict[str, Any]:
    assert lab.authorization is not None
    simulation_id = new_id()
    dry_run = options.dry_run or lab.config.safety.dry_run
    record: dict[str, Any] = {
        "id": simulation_id,
        "simulation_id": simulation_id,
        "lab_id": lab.id,
        "target": target,
        "timestamp": time.time(),
        "start_time": time.time(),
        "status": "DRY_RUN" if dry_run else "RUNNING",
        "parameters": options.model_dump(exclude={"authorized"}),
        "scheduled": 0,
        "completed": 0,
        "network_errors": 0,
        "skipped": 0,
    }
    lab.db.put("simulations", record)
    audit(
        lab.db,
        "simulation.started",
        simulation_id=simulation_id,
        target=target,
        **options.model_dump(exclude={"authorized"}),
    )
    if dry_run:
        record["end_time"] = time.time()
        lab.db.put("simulations", record)
        audit(lab.db, "simulation.finished", simulation_id=simulation_id, status="DRY_RUN")
        return record
    tasks: set[asyncio.Task[None]] = set()
    start = time.monotonic()
    cpu_start = time.process_time()
    next_observation = start + lab.config.detection.window_seconds
    lab.simulation_id = simulation_id
    headers = {"X-Sentinel-Lab": lab.authorization.token}
    churn = options.scenario == "connection-churn"

    async def request(client: httpx.AsyncClient, index: int) -> None:
        path = endpoint_for(options.scenario, index, options.body_size)
        request_headers = {**headers, "X-Synthetic-Client": f"client-{index % options.clients}"}
        if churn:
            request_headers["Connection"] = "close"
        try:
            await client.request(
                "POST" if options.body_size else "GET",
                path,
                headers=request_headers,
                content=b"x" * options.body_size if options.body_size else None,
            )
            record["completed"] += 1
        except httpx.HTTPError:
            record["network_errors"] += 1

    try:
        async with httpx.AsyncClient(
            base_url=target,
            trust_env=False,
            follow_redirects=False,
            timeout=2,
            limits=httpx.Limits(
                max_connections=options.clients,
                max_keepalive_connections=0 if churn else options.clients,
            ),
        ) as client:
            try:
                async with asyncio.timeout(options.duration):
                    next_request = start
                    index = 0
                    while True:
                        now = time.monotonic()
                        if observer and now >= next_observation:
                            observer(simulation_id, lab.config.detection.window_seconds)
                            next_observation = now + lab.config.detection.window_seconds
                        if now < next_request:
                            await asyncio.sleep(next_request - now)
                        elapsed = time.monotonic() - start
                        if elapsed >= options.duration:
                            break
                        rate = options.rate
                        if options.scenario == "burst" and elapsed < options.duration / 4:
                            rate = max(1, options.rate // 4)
                        # Reset against current time: never catch up with a rapid request burst.
                        next_request = time.monotonic() + 1 / rate
                        if len(tasks) >= options.clients:
                            record["skipped"] += 1
                            continue
                        task = asyncio.create_task(request(client, index))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
                        record["scheduled"] += 1
                        index += 1
            except TimeoutError:
                pass
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        record["status"] = "COMPLETED"
    except asyncio.CancelledError:
        record["status"] = "CANCELLED"
        raise
    except Exception:
        record["status"] = "FAILED"
        raise
    finally:
        # Await the bounded server work already received before removing the simulation label.
        deadline = time.monotonic() + 2.5
        while lab.telemetry.active and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        record["end_time"] = time.time()
        record["elapsed_seconds"] = time.monotonic() - start
        record["process_cpu_seconds"] = time.process_time() - cpu_start
        record["process_memory_bytes"] = None
        lab.simulation_id = None
        samples = [
            sample for sample in lab.telemetry.samples if sample.simulation_id == simulation_id
        ]
        with lab.db.connection() as connection:
            lab.db.put("simulations", record, connection=connection)
            for sample in samples:
                lab.db.put("traffic_samples", sample.model_dump(), connection=connection)
        audit(lab.db, "simulation.finished", simulation_id=simulation_id, status=record["status"])
    return record
