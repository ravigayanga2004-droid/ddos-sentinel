import json
from pathlib import Path

from typer.testing import CliRunner

from ddos_sentinel.cli import app
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.reports.reporting import build_report, render_report

runner = CliRunner()


def test_help_and_init_validate(tmp_path: Path) -> None:
    assert runner.invoke(app, ["--help"]).exit_code == 0
    version = runner.invoke(app, ["--version"])
    assert version.exit_code == 0 and version.stdout.strip() == "0.1.0"
    config = tmp_path / "lab.json"
    assert runner.invoke(app, ["init", str(config)]).exit_code == 0
    assert runner.invoke(app, ["init", str(config)]).exit_code != 0
    result = runner.invoke(app, ["validate", str(config)])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["valid"]
    config.write_text('{"target": {"host": "8.8.8.8"}}')
    result = runner.invoke(app, ["validate", str(config)])
    assert result.exit_code != 0 and "only 127.0.0.1" in result.output


def test_cli_scenarios_baseline_and_report(tmp_path: Path) -> None:
    common = ["--database", str(tmp_path / "cli.db"), "--json"]
    result = runner.invoke(app, [*common, "simulate", "normal", "--duration", "0.4", "--yes"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["status"] == "COMPLETED"
    assert runner.invoke(app, [*common, "baseline", "create"]).exit_code == 0
    assert runner.invoke(app, [*common, "baseline", "show"]).exit_code == 0
    assert runner.invoke(app, [*common, "status"]).exit_code == 0
    for format in ("json", "markdown", "html"):
        output = tmp_path / f"report.{format}"
        result = runner.invoke(
            app, [*common, "report", "--format", format, "--output", str(output)]
        )
        assert result.exit_code == 0, result.output
        assert output.exists()
    result = runner.invoke(app, [*common, "simulate", "burst", "--dry-run", "--yes"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["scheduled"] == 0
    result = runner.invoke(app, [*common, "simulate", "normal"], input="n\n")
    assert result.exit_code != 0


def test_report_structure_and_privacy(tmp_path: Path) -> None:
    report = build_report(Database(tmp_path / "empty.db"), LabConfig())
    for key in ("executive_summary", "timeline", "baseline", "evaluation", "limitations"):
        assert key in report
    for format in ("json", "markdown", "html"):
        output = render_report(report, format)
        assert "DDoS Sentinel" in output
        assert "X-Sentinel-Lab" not in output
