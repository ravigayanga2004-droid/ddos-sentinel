"""Verify a freshly built wheel and smoke-test imports without the editable source tree."""

import argparse
import subprocess
import sys
import sysconfig
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory

SMOKE = """
import asyncio
import sys
from pathlib import Path
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import httpx
import ddos_sentinel
from ddos_sentinel.api.app import create_app
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.reports.reporting import build_report, render_report

async def smoke():
    assert Path(ddos_sentinel.__file__).is_relative_to(Path(sys.argv[1]))
    db = Database(Path('packaged.db'))
    app = create_app(LabConfig(), db)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 50000))
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1',
                                     trust_env=False) as client:
            for path in ['/', '/health', '/static/dashboard.js', '/static/dashboard.css']:
                assert (await client.get(path)).status_code == 200
        result = await app.state.runtime.run(SimulationOptions(
            duration=0.4, rate=10, authorized=True))
        assert result['status'] == 'COMPLETED' and result['completed'] > 0
        report = build_report(db, LabConfig())
        for format in ['json', 'markdown', 'html']:
            assert 'DDoS Sentinel' in render_report(report, format)
    assert all(row['status'] == 'STOPPED' for row in db.list('labs'))
asyncio.run(smoke())
print('Isolated wheel smoke passed: imports, service, dashboard assets, reports, cleanup.')
"""


def check(wheel: Path) -> None:
    source = Path(__file__).parents[1] / "src"
    with TemporaryDirectory(prefix="sentinel-wheel-") as directory:
        root = Path(directory)
        payload = root / "package"
        with zipfile.ZipFile(wheel) as archive:
            for entry in archive.namelist():
                destination = (payload / entry).resolve()
                if not destination.is_relative_to(payload.resolve()):
                    raise ValueError("wheel contains an unsafe archive path")
                if entry.startswith("ddos_sentinel/") and not entry.endswith("/"):
                    file = source / entry
                    if not file.is_file() or archive.read(entry) != file.read_bytes():
                        raise ValueError(f"wheel is stale or unexpected: {entry}; rebuild it")
            archive.extractall(payload)
        dependencies = sysconfig.get_paths()["purelib"]
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", SMOKE, str(payload), dependencies],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(result.stderr or result.stdout)
        print(result.stdout.strip())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wheel", type=Path)
    check(parser.parse_args().wheel)
