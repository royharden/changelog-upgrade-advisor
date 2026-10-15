"""Literal, escaped local artifacts. No scripts, remote assets or generated actions."""

import html
import json
import re
from pathlib import Path


def md(value):
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~\-])", r"\\\1", html.escape(str(value)))


def coverage_summary(package):
    coverage = package.get("coverage")
    if coverage is None:
        return "Unknown; source coverage could not be established."
    return (
        f"Expected entries: {coverage['selected_total']}; "
        f"omitted by cap: {coverage['capped_count']}; "
        f"missing releases: {', '.join(coverage['missing_releases']) or 'none'}; "
        f"ambiguous releases: {', '.join(coverage['ambiguous_releases']) or 'none'}; "
        f"empty releases: {', '.join(coverage['empty_releases']) or 'none'}; "
        f"unclassified sections: {coverage['unknown_sections']}."
    )


def render_markdown(report):
    lines = [
        "# Dependency upgrade checklist",
        "",
        f"Workflow: {md(report['workflow_status'])}",
        f"Method: {md(report['method'])}; semantic quality: unmeasured; provider calls: 0.",
        "",
    ]
    for package in report["packages"]:
        lines += ["## " + md(package["package"]), "", "Status: " + md(package["status"]), ""]
        if "window" in package:
            w = package["window"]
            lines += [
                f"Pin {md(w['pin'])} → target {md(w['target'])}; releases: "
                + md(", ".join(w["releases"])),
                "",
            ]
        if package.get("reason"):
            lines += [md(package["reason"]), ""]
        if gap := package.get("version_gap"):
            lines += [
                "Version gap: "
                + md(gap["kind"])
                + "; major versions crossed: "
                + md(gap["major_versions_crossed"]),
                "",
            ]
        lines += ["Coverage: " + md(coverage_summary(package)), ""]
        for entry in package["entries"]:
            judgment = entry.get("judgment", {}).get("judgment") or {}
            lines += [
                "- " + md(entry["status"]) + ": " + md(judgment.get("category", "unknown")),
                "",
            ]
            quote = entry.get("evidence", {}).get("resolution", {}).get("excerpt")
            if quote:
                lines += ["> " + md(line) for line in quote.splitlines()] + [""]
            lines += [
                "  Span: " + md(entry["span_id"]),
                "  Source SHA256: " + md(entry["source_sha256"]) + "; lines: " + md(entry["lines"]),
                "  Literal resolution: "
                + md(entry.get("evidence", {}).get("resolution", {}).get("status", "unsupported")),
                "",
            ]
        lines += [
            "Advisory sources: "
            + md(package.get("advisories", {}).get("source_status", "not_fetched")),
            "",
        ]
        for advisory in package.get("advisories", {}).get("rows", []):
            lines += [
                "- Advisory "
                + md(", ".join(advisory.get("ids", [])))
                + ": membership "
                + md(advisory["membership"])
                + "; conditional usage "
                + md(advisory["usage_impact"]),
                "",
            ]
    lines += ["## Limits", ""] + ["- " + md(value) for value in report["limitations"]]
    return "\n".join(lines) + "\n"


def render_html(report):
    def escape(value):
        return html.escape(str(value), quote=True)

    parts = [
        "<!doctype html><html lang='en'><meta charset='utf-8'>",
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Dependency upgrade checklist</title><style>"
        "body{font:16px/1.5 system-ui;max-width:1000px;margin:3rem auto;padding:0 1rem;"
        "background:#f5f6fa;color:#172138}article,details{background:white;padding:1rem;"
        "margin:.75rem 0;border:1px solid #bbc5d8;border-radius:8px}pre{white-space:pre-wrap;"
        "overflow-wrap:anywhere}small{color:#465572}h2{margin-top:2.5rem}</style>",
        "<h1>Dependency upgrade checklist</h1><p>Workflow: "
        + escape(report["workflow_status"])
        + " · Method: "
        + escape(report["method"])
        + " · Semantic quality: unmeasured</p>",
        "<p>No provider calls. Review potential changes before upgrading.</p>",
    ]
    for package in report["packages"]:
        parts += [
            "<section><h2>"
            + escape(package["package"])
            + "</h2><p>Status: "
            + escape(package["status"])
            + "</p>"
        ]
        if "window" in package:
            w = package["window"]
            parts += [
                "<p>Pin "
                + escape(w["pin"])
                + " → "
                + escape(w["target"])
                + " · crossed releases: "
                + escape(", ".join(w["releases"]))
                + "</p>"
            ]
        if package.get("reason"):
            parts += ["<p>" + escape(package["reason"]) + "</p>"]
        if gap := package.get("version_gap"):
            parts += [
                "<p>Version gap: "
                + escape(gap["kind"])
                + " · major versions crossed: "
                + escape(gap["major_versions_crossed"])
                + "</p>"
            ]
        parts += ["<p>Coverage: " + escape(coverage_summary(package)) + "</p>"]
        for entry in package["entries"]:
            value = entry.get("judgment", {}).get("judgment") or {}
            label = escape(entry["status"] + " · " + value.get("category", "unknown"))
            quiet = entry["status"] == "nonbreaking"
            parts += [
                "<details><summary>" + label + "</summary>"
                if quiet
                else "<article><h3>" + label + "</h3>"
            ]
            resolution = entry.get("evidence", {}).get("resolution", {})
            if resolution.get("excerpt"):
                parts += ["<pre>" + escape(resolution["excerpt"]) + "</pre>"]
            parts += [
                "<small>Span "
                + escape(entry["span_id"])
                + " · literal resolution: "
                + escape(resolution.get("status", "unsupported"))
                + " · source SHA256: "
                + escape(entry["source_sha256"])
                + " · lines: "
                + escape(entry["lines"])
                + "</small>",
                "</details>" if quiet else "</article>",
            ]
        advisory = package.get("advisories", {})
        parts += [
            "<p>Advisory sources: " + escape(advisory.get("source_status", "not_fetched")) + "</p>"
        ]
        for row in advisory.get("rows", []):
            parts += [
                "<article><h3>Advisory "
                + escape(", ".join(row.get("ids", [])))
                + "</h3><p>Installed membership: "
                + escape(row["membership"])
                + " · target membership: "
                + escape(row.get("target_membership", "unknown"))
                + " · conditional usage: "
                + escape(row["usage_impact"])
                + "</p>",
                "<p>" + escape(row.get("usage_reason", row.get("reason", "unknown"))) + "</p>",
            ]
            for evidence in row.get("evidence", []):
                if evidence["resolution"].get("excerpt"):
                    parts += ["<pre>" + escape(evidence["resolution"]["excerpt"]) + "</pre>"]
            parts += ["</article>"]
        parts += ["</section>"]
    parts += ["<h2>Limits</h2><ul>"] + ["<li>" + escape(s) + "</li>" for s in report["limitations"]]
    parts += [
        "</ul><details><summary>Complete evidence and coverage</summary><pre>"
        + escape(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
        + "</pre></details></html>"
    ]
    return "\n".join(parts) + "\n"


def write_reports(report, output: Path):
    """Refuse an existing directory; preserve every unrelated file and prior result."""
    output = output.resolve()
    rendered = {
        "checklist.json": json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        "checklist.md": render_markdown(report),
        "checklist.html": render_html(report),
    }
    output.mkdir(parents=True, exist_ok=False)
    for name, text in rendered.items():
        with (output / name).open("x", encoding="utf8", newline="\n") as stream:
            stream.write(text)
    return {name: str(output / name) for name in rendered}
