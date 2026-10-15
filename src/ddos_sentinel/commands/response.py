"""Analyst incident decisions and reversible local controls."""

import json
from pathlib import Path
from typing import Any

import typer

from ddos_sentinel.commands.context import SentinelGroup, context, emit
from ddos_sentinel.core.models import IncidentStatus
from ddos_sentinel.response.incidents import IncidentManager
from ddos_sentinel.response.mitigation import MitigationRequest, Mitigator

incidents = typer.Typer(cls=SentinelGroup, help="Inspect, annotate and close incidents.")
mitigation = typer.Typer(cls=SentinelGroup, help="Manage expiring in-service controls.")


@incidents.command("list")
def list_incidents(ctx: typer.Context) -> None:
    emit(context(ctx).db.list("incidents"))


@incidents.command("show")
def show_incident(ctx: typer.Context, incident_id: str) -> None:
    emit(context(ctx).db.get("incidents", incident_id))


@incidents.command("acknowledge")
def acknowledge(ctx: typer.Context, incident_id: str, notes: str = "") -> None:
    emit(IncidentManager(context(ctx).db).transition(incident_id, "ACKNOWLEDGED", notes))


@incidents.command("resolve")
def resolve(
    ctx: typer.Context, incident_id: str, notes: str = "", false_positive: bool = False
) -> None:
    status: IncidentStatus = "FALSE_POSITIVE" if false_positive else "RESOLVED"
    emit(IncidentManager(context(ctx).db).transition(incident_id, status, notes))


@incidents.command("export")
def export_incident(ctx: typer.Context, incident_id: str, output: Path | None = None) -> None:
    db = context(ctx).db
    payload: dict[str, Any] = {
        "incident": db.get("incidents", incident_id),
        "detections": [
            row
            for row in db.list("detections", limit=100000)
            if row.get("incident_id") == incident_id
        ],
    }
    if output:
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        emit({"output": str(output)})
    else:
        emit(payload)


@mitigation.command("status")
def mitigation_status(ctx: typer.Context) -> None:
    emit(Mitigator(context(ctx).db).status())


@mitigation.command("enable")
def enable(
    ctx: typer.Context,
    mode: str,
    reason: str = typer.Option(..., "--reason"),
    ttl: float = 30,
    rate: int = 5,
    client_id: str | None = None,
    endpoint: str | None = None,
    body_limit: int = 1024,
    incident_id: str | None = None,
) -> None:
    options = MitigationRequest.model_validate(
        {
            "mode": mode,
            "reason": reason,
            "ttl": ttl,
            "rate": rate,
            "client_id": client_id,
            "endpoint": endpoint,
            "body_limit": body_limit,
            "incident_id": incident_id,
        }
    )
    emit({"action_id": Mitigator(context(ctx).db).enable(options)})


@mitigation.command("disable")
def disable(ctx: typer.Context, mode: str) -> None:
    emit({"disabled": Mitigator(context(ctx).db).disable(mode)})


@mitigation.command("reset")
def reset(ctx: typer.Context, yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        typer.confirm("Disable all local mitigation actions?", abort=True)
    emit({"disabled": Mitigator(context(ctx).db).reset()})


@mitigation.command("unblock")
def unblock(ctx: typer.Context, client_id: str) -> None:
    emit({"unblocked": Mitigator(context(ctx).db).unblock(client_id)})
