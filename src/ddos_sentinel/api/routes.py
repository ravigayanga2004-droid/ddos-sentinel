"""Read-only metadata and confirmed, CSRF-protected local actions."""

import asyncio
from pathlib import Path
from typing import Any, Literal, cast

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from ddos_sentinel import __version__
from ddos_sentinel.analysis.metrics import evaluation_metrics
from ddos_sentinel.core.config import StrictModel
from ddos_sentinel.core.safety import SCENARIOS, SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.reports.reporting import build_report, render_report
from ddos_sentinel.response.mitigation import MitigationRequest

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).parents[1] / "web" / "templates")


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)


class Confirmation(StrictModel):
    confirmed: Literal[True]


class SimulationStart(StrictModel):
    options: SimulationOptions
    confirmed: Literal[True]


class IncidentUpdate(StrictModel):
    status: Literal["ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"]
    notes: str = ""


def runtime_for(request: Request) -> Runtime:
    return cast(Runtime, request.app.state.runtime)


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "version": __version__}


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> Response:
    runtime = runtime_for(request)
    response = templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "lab_name": runtime.config.lab_name,
            "csrf": request.app.state.csrf,
            "scenarios": SCENARIOS,
            "limits": runtime.config.limits,
        },
    )
    response.set_cookie("sentinel_csrf", request.app.state.csrf, httponly=True, samesite="strict")
    return response


@router.get("/api/status")
async def status(request: Request) -> dict[str, Any]:
    runtime = runtime_for(request)
    baseline = runtime.baselines.current()
    incidents = runtime.db.list("incidents", limit=100)
    simulations = runtime.db.list("simulations", limit=50)
    return {
        "version": __version__,
        "lab": {
            "id": runtime.lab.id,
            "target": runtime.lab.target,
            "name": runtime.config.lab_name,
            "active": bool(runtime.lab.authorization and runtime.lab.authorization.active),
        },
        "configuration": runtime.config.model_dump(),
        "telemetry": runtime.lab.telemetry.window().model_dump(),
        "active_connections": runtime.lab.telemetry.active,
        "completed_requests": runtime.lab.telemetry.completed,
        "baseline": baseline.model_dump() if baseline else None,
        "incidents": incidents,
        "detections": runtime.db.list("detections", limit=100),
        "simulations": simulations,
        "mitigations": runtime.mitigator.status(),
        "timeline": runtime.db.list("service_health", limit=120)[::-1],
        "evaluation": evaluation_metrics(simulations, incidents),
        "running": request.app.state.simulation_task is not None
        and not request.app.state.simulation_task.done(),
        "last_error": request.app.state.last_error,
    }


@router.get("/api/{collection}")
async def collection(request: Request, collection: str) -> list[dict[str, Any]]:
    if collection not in {"detections", "incidents", "simulations", "mitigation_actions"}:
        raise HTTPException(404, "unknown collection")
    return runtime_for(request).db.list(collection)


@router.post("/api/simulations", status_code=202)
async def start_simulation(request: Request, body: SimulationStart) -> dict[str, str]:
    runtime = runtime_for(request)
    body.options.check(runtime.config.limits)
    existing = request.app.state.simulation_task
    if existing is not None and not existing.done():
        raise HTTPException(409, "a simulation is already running")
    request.app.state.last_error = None
    task = asyncio.create_task(runtime.run(body.options))
    runtime.tasks.add(task)

    def finished(completed: asyncio.Task[dict[str, Any]]) -> None:
        runtime.tasks.discard(completed)
        if not completed.cancelled() and completed.exception() is not None:
            request.app.state.last_error = "Simulation failed; inspect local audit history."

    task.add_done_callback(finished)
    request.app.state.simulation_task = task
    return {"status": "scheduled"}


@router.post("/api/simulations/cancel")
async def cancel_simulation(request: Request, body: Confirmation) -> dict[str, str]:
    task = request.app.state.simulation_task
    if task is not None and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    return {"status": "stopped"}


@router.post("/api/baseline/create")
async def create_baseline(request: Request, body: Confirmation) -> dict[str, Any]:
    runtime = runtime_for(request)
    return runtime.baselines.create(
        window_seconds=runtime.config.detection.baseline_window_seconds
    ).model_dump()


@router.post("/api/mitigation/enable")
async def enable_mitigation(request: Request, body: MitigationRequest) -> dict[str, str]:
    return {"id": runtime_for(request).mitigator.enable(body)}


@router.post("/api/mitigation/reset")
async def reset_mitigation(request: Request, body: Confirmation) -> dict[str, int]:
    return {"disabled": runtime_for(request).mitigator.reset()}


@router.post("/api/incidents/{incident_id}")
async def update_incident(
    request: Request, incident_id: str, body: IncidentUpdate
) -> dict[str, Any]:
    return runtime_for(request).incidents.transition(incident_id, body.status, body.notes)


@router.get("/reports/{format}")
async def report(request: Request, format: str) -> Response:
    if format not in {"json", "markdown", "html"}:
        raise HTTPException(404, "unknown report format")
    runtime = runtime_for(request)
    data = build_report(runtime.db, runtime.config)
    if format == "json":
        return JSONResponse(data)
    content = render_report(data, format)
    suffix = "html" if format == "html" else "md"
    return Response(
        content,
        media_type="text/html" if format == "html" else "text/markdown",
        headers={"Content-Disposition": f'attachment; filename="sentinel-report.{suffix}"'},
    )


@router.get("/safety", response_class=HTMLResponse)
async def safety(request: Request) -> Response:
    return templates.TemplateResponse(request=request, name="safety.html")
