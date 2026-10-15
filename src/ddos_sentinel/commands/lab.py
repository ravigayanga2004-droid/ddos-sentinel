"""Foreground standalone lab management without signals or shelling out to other processes."""

import asyncio
import time

import typer

from ddos_sentinel.commands.context import SentinelGroup, console, context, emit
from ddos_sentinel.lab.runtime import Runtime

app = typer.Typer(cls=SentinelGroup, help="Start or stop a temporary standalone local service.")


@app.command()
def start(ctx: typer.Context) -> None:
    """Start a service in the foreground. Ctrl+C or `lab stop` shuts it down."""
    settings = context(ctx)

    async def run() -> None:
        async with Runtime(settings.config, settings.db) as runtime:
            emit({"lab_id": runtime.lab.id, "target": runtime.lab.target, "status": "RUNNING"})
            console.print("Local test service is running. Ctrl+C or ddossentinel lab stop to stop.")
            while True:
                record = runtime.db.get("labs", runtime.lab.id)
                if record["status"] == "STOPPING":
                    break
                runtime.db.put(
                    "labs", {**record, "managed_by": "lab-command", "heartbeat": time.time()}
                )
                await asyncio.sleep(0.5)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("Local lab stopped.")


@app.command()
def stop(ctx: typer.Context) -> None:
    """Request graceful shutdown of standalone lab commands using this database."""
    db = context(ctx).db
    count = 0
    for record in db.list("labs", status="RUNNING"):
        if record.get("managed_by") == "lab-command":
            db.put("labs", {**record, "status": "STOPPING"})
            count += 1
    emit({"stop_requests": count})
