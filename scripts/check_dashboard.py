"""Optional headless browser smoke test against an ephemeral loopback dashboard."""

import argparse
import asyncio
import re
import socket
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from playwright.async_api import async_playwright

from ddos_sentinel.api.app import create_app
from ddos_sentinel.core.config import LabConfig
from ddos_sentinel.core.database import Database
from ddos_sentinel.lab.service import EmbeddedServer


async def check(output: Path | None, channel: str | None) -> None:
    with TemporaryDirectory(prefix="sentinel-browser-") as directory:
        db = Database(Path(directory) / "ui.db")
        application = create_app(LabConfig(), db)
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)
        target = f"http://127.0.0.1:{listener.getsockname()[1]}"
        import uvicorn

        server = EmbeddedServer(
            uvicorn.Config(
                application, log_level="error", access_log=False, timeout_graceful_shutdown=3
            )
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if task.done():
                        await task
                    await asyncio.sleep(0.02)
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True, channel=channel)
                try:
                    page = await browser.new_page(viewport={"width": 1440, "height": 1100})
                    errors: list[str] = []
                    page.on("pageerror", lambda error: errors.append(str(error)))

                    async def local_only(route) -> None:
                        if route.request.url.startswith(target + "/"):
                            await route.continue_()
                        else:
                            errors.append("attempted external browser request")
                            await route.abort()

                    await page.route("**/*", local_only)
                    await page.goto(target)
                    await page.get_by_text("Lab online", exact=True).wait_for()
                    assert await page.title() == "DDoS Sentinel · Local defense lab"
                    await page.locator("#duration").fill("1")
                    await page.locator("#authorization").check()
                    page.on("dialog", lambda dialog: dialog.accept())
                    await page.locator("#run").click()
                    await (
                        page.locator("#history")
                        .get_by_text("1s · COMPLETED", exact=True)
                        .wait_for()
                    )
                    await page.locator("#learn").click()
                    await page.get_by_text(re.compile(r"^Normal average")).wait_for()
                    if output:
                        output.parent.mkdir(parents=True, exist_ok=True)
                        await page.evaluate("window.scrollTo(0,0)")
                        await page.screenshot(path=str(output), full_page=True)
                    await page.set_viewport_size({"width": 390, "height": 844})
                    await page.wait_for_timeout(200)
                    assert await page.evaluate(
                        "document.documentElement.scrollWidth <= window.innerWidth"
                    ), "mobile page overflows horizontally"
                    assert not errors, errors
                    print(
                        "Dashboard browser test passed: JS, consent, simulation, baseline, mobile."
                    )
                finally:
                    await browser.close()
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 8)
            listener.close()
        assert all(row["status"] == "STOPPED" for row in db.list("labs"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Optional screenshot destination")
    parser.add_argument("--channel", default="msedge" if sys.platform == "win32" else None)
    arguments = parser.parse_args()
    asyncio.run(check(arguments.output, arguments.channel))
