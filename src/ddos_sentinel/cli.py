"""DDoS Sentinel command line. All simulations create and own a temporary local lab."""

import asyncio
import logging
from pathlib import Path

import typer
import uvicorn

from ddos_sentinel import __version__
from ddos_sentinel.api.app import create_app
from ddos_sentinel.commands import analysis, lab, response
from ddos_sentinel.commands.context import Context, SentinelGroup, console, context, emit
from ddos_sentinel.core.config import LabConfig, load_config
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.reports.reporting import write_report

app = typer.Typer(
    cls=SentinelGroup,
    no_args_is_help=True,
    help="DDoS Sentinel: authorized, bounded, localhost-only defensive lab.",
)
app.add_typer(lab.app, name="lab")
app.add_typer(analysis.baseline, name="baseline")
app.add_typer(analysis.detections, name="detections")
app.add_typer(response.incidents, name="incidents")
app.add_typer(response.mitigation, name="mitigation")


@app.callback()
def configure(
    ctx: typer.Context,
    config: Path | None = typer.Option(None, "--config"),
    database: Path = typer.Option(Path(".sentinel/sentinel.db"), "--database"),
    json_output: bool = typer.Option(False, "--json"),
    version: bool = typer.Option(False, "--version", is_eager=True),
) -> None:
    """Global options precede the command; JSON data is emitted on stdout."""
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    ctx.obj = Context(load_config(config), database, json_output)


@app.command("init")
def initialize(config: Path) -> None:
    """Write a validated JSON configuration without overwriting existing files."""
    if config.exists():
        raise ValueError("configuration already exists")
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(LabConfig().model_dump_json(indent=2) + "\n", encoding="utf-8")
    emit({"configuration": str(config)})


@app.command("validate")
def validate(config: Path) -> None:
    emit({"valid": True, "configuration": load_config(config).model_dump()})


@app.command("status")
def status(ctx: typer.Context) -> None:
    settings = context(ctx)
    db = settings.db
    emit(
        {
            "version": __version__,
            "configuration": settings.config.model_dump(),
            "labs": db.list("labs", limit=20),
            "simulations": db.list("simulations", limit=10),
            "mitigations": response.Mitigator(db).status(),
        }
    )


@app.command("simulate")
def simulate(
    ctx: typer.Context,
    scenario: str,
    duration: float = 10,
    rate: int = 10,
    clients: int = 5,
    body_size: int = 0,
    dry_run: bool = typer.Option(False, "--dry-run"),
    yes: bool = typer.Option(False, "--yes"),
) -> None:
    """Authorize one bounded scenario; the temporary target is selected by the application."""
    settings = context(ctx)
    options = SimulationOptions(
        scenario=scenario,
        duration=duration,
        rate=rate,
        clients=clients,
        body_size=body_size,
        dry_run=dry_run,
        authorized=True,
    )
    options.check(settings.config.limits)
    if not yes:
        typer.confirm(
            "Authorize this bounded simulation against an owned loopback test service?", abort=True
        )

    async def run() -> None:
        async with Runtime(settings.config, settings.db) as runtime:
            safety = {
                "target": runtime.lab.target,
                "scope": "owned localhost service",
                "parameters": options.model_dump(exclude={"authorized"}),
                "limits": settings.config.limits.model_dump(),
            }
            if settings.json_output:
                import json

                typer.echo(json.dumps(safety), err=True)
            else:
                console.print("[bold green]Authorized localhost experiment[/bold green]")
                console.print(safety)
            emit(await runtime.run(options))

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        console.print("Simulation cancelled; clients and temporary service stopped.")
        raise typer.Exit(130) from None


@app.command("report")
def report(ctx: typer.Context, format: str = "json", output: Path | None = None) -> None:
    settings = context(ctx)
    extension = {"json": "json", "markdown": "md", "html": "html"}.get(format)
    if extension is None:
        raise ValueError("report format must be json, markdown or html")
    destination = output or Path("reports") / f"sentinel-report.{extension}"
    write_report(settings.db, settings.config, format, destination)
    emit({"output": str(destination), "format": format})


@app.command("serve")
def serve(ctx: typer.Context, port: int = typer.Option(8765, min=1, max=65535)) -> None:
    """Serve the local dashboard and its owned temporary service. Ctrl+C cleans up."""
    settings = context(ctx)
    console.print(f"Dashboard: http://127.0.0.1:{port} — authorized local labs only")
    uvicorn.run(
        create_app(settings.config, settings.db),
        host="127.0.0.1",
        port=port,
        access_log=False,
        log_level="warning",
        timeout_graceful_shutdown=5,
    )


def main() -> None:
    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    app()


if __name__ == "__main__":
    main()
