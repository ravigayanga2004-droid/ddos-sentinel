"""Harmless, self-cleaning end-to-end demo. All network traffic stays on loopback."""

import argparse
import asyncio
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.core.safety import SimulationOptions
from ddos_sentinel.lab.runtime import Runtime
from ddos_sentinel.reports.reporting import build_report, write_report
from ddos_sentinel.response.mitigation import MitigationRequest


async def demo(yes: bool, output: Path | None = None) -> None:
    with TemporaryDirectory(prefix="sentinel-demo-") as directory:
        root = Path(directory)
        db = Database(root / "demo.db")
        config = LabConfig()
        async with Runtime(config, db) as runtime:

            async def run(scenario: str, rate: int) -> dict:
                print(
                    f"Authorize {scenario}: target={runtime.lab.target}, "
                    f"duration=1.5s, rate<={rate}/s, clients=5, body<=65536 bytes"
                )
                consent = yes or input("Authorize this local experiment? [y/N] ").lower() == "y"
                if not consent:
                    raise ValueError("demo authorization declined")
                return await runtime.run(
                    SimulationOptions(
                        scenario=scenario, duration=1.5, rate=rate, clients=5, authorized=True
                    )
                )

            await run("normal", 6)
            baseline = runtime.baselines.create()
            print(f"Learned baseline: {baseline.average_rps:.1f} req/s")
            await run("error-spike", 20)
            incidents = db.list("incidents")
            if not incidents:
                raise RuntimeError("demo did not produce expected findings")
            runtime.mitigator.enable(
                MitigationRequest(
                    mode="global-throttle",
                    rate=3,
                    reason="Demonstrate reversible local throttling",
                    ttl=30,
                    incident_id=incidents[0]["id"],
                )
            )
            mitigated = await run("normal", 20)
            if mitigated["metrics"]["requests_throttled"] == 0:
                raise RuntimeError("demo did not observe throttling")
            runtime.mitigator.reset()
            recovered = await run("normal", 6)
            if recovered["metrics"]["requests_throttled"]:
                raise RuntimeError("mitigation reset failed")
            for format, suffix in (("json", "json"), ("markdown", "md"), ("html", "html")):
                write_report(db, config, format, root / f"report.{suffix}")
                if output:
                    write_report(db, config, format, output / f"demo-report.{suffix}")
            print(json.dumps(build_report(db, config)["executive_summary"], indent=2))
        if any(row["status"] != "STOPPED" for row in db.list("labs")):
            raise RuntimeError("temporary service did not stop")
    if root.exists():
        raise RuntimeError("temporary state was not removed")
    print("Demo passed. Temporary services, database and working reports removed.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Explicitly authorize each of the four predefined local experiments",
    )
    parser.add_argument("--output", type=Path, help="Optionally retain exported reports here")
    args = parser.parse_args()
    try:
        asyncio.run(demo(args.yes, args.output))
    except (ValueError, KeyboardInterrupt) as exc:
        raise SystemExit(f"Demo stopped safely: {exc}") from None


if __name__ == "__main__":
    main()
