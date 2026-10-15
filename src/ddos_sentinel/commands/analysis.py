"""Baseline and detection inspection commands."""

from pathlib import Path

import typer

from ddos_sentinel.analysis.baseline import BaselineStore
from ddos_sentinel.commands.context import SentinelGroup, context, emit

baseline = typer.Typer(cls=SentinelGroup, help="Learn and manage an explicit normal baseline.")
detections = typer.Typer(
    cls=SentinelGroup, help="Inspect measured anomalies and their explanations."
)


def store(ctx: typer.Context) -> BaselineStore:
    return BaselineStore(context(ctx).db)


@baseline.command("create")
def create(ctx: typer.Context, simulation_id: str | None = None) -> None:
    value = store(ctx).create(simulation_id, context(ctx).config.detection.baseline_window_seconds)
    emit(value.model_dump())


@baseline.command("show")
def show(ctx: typer.Context) -> None:
    value = store(ctx).current()
    emit(value.model_dump() if value else {"baseline": None, "message": "No learned baseline."})


@baseline.command("reset")
def reset(ctx: typer.Context, yes: bool = typer.Option(False, "--yes")) -> None:
    if not yes:
        typer.confirm("Reset the learned baseline?", abort=True)
    store(ctx).reset()
    emit({"baseline": None})


@baseline.command("export")
def export_baseline(ctx: typer.Context, output: Path) -> None:
    store(ctx).export(output)
    emit({"output": str(output)})


@baseline.command("import")
def import_baseline(ctx: typer.Context, source: Path) -> None:
    emit(store(ctx).import_file(source).model_dump())


@detections.command("list")
def list_detections(ctx: typer.Context) -> None:
    emit(context(ctx).db.list("detections"))


@detections.command("show")
def show_detection(ctx: typer.Context, detection_id: str) -> None:
    emit(context(ctx).db.get("detections", detection_id))
