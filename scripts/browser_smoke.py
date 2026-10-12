"""Optional real browser smoke against a running local demo server."""

from pathlib import Path
import json
from playwright.sync_api import expect, sync_playwright


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path="/usr/bin/chromium", headless=True)
        page = browser.new_page(viewport={"width": 1500, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto("http://127.0.0.1:8000/", wait_until="networkidle")
        assert "entities" in page.locator("#status").inner_text()
        page.locator("#query").fill("c2.example")
        page.locator("#search button").click()
        page.locator("#results button").first.wait_for()
        page.locator("#results button").first.click()
        page.locator(".graph-node").first.wait_for()
        assert page.locator(".graph-edge").count() > 0
        page.locator("#edge-list button").first.click()
        expect(page.locator("#details")).to_contain_text("evidence_id")
        assert "rationale" in page.locator("#details").inner_text()
        page.locator("#depth").fill("2")
        page.locator("#expand").click()
        expect(page.locator("#status")).to_contain_text("claims")
        page.locator("#investigation").select_option(index=1)
        page.locator("#open-case").click()
        expect(page.locator("#status")).to_contain_text("Investigation:")
        with page.expect_download() as info:
            page.locator("#export-json").click()
        output = Path("local/browser-export.json")
        info.value.save_as(output)
        report = json.loads(output.read_text())
        assert report["evidence"] and report["edges"]
        screenshot = Path("local/interface.png")
        page.screenshot(path=str(screenshot), full_page=True)
        assert not errors, errors
        print(
            json.dumps(
                {
                    "status": "passed",
                    "rendered_nodes": page.locator(".graph-node").count(),
                    "rendered_edges": page.locator(".graph-edge").count(),
                    "javascript_errors": errors,
                    "checks": [
                        "search",
                        "graph rendering",
                        "edge evidence",
                        "expansion",
                        "saved investigation",
                        "JSON download",
                    ],
                    "screenshot": str(screenshot),
                },
                indent=2,
            )
        )
        browser.close()


if __name__ == "__main__":
    main()
