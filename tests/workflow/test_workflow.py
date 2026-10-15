"""what_bug_this_catches: incomplete input looks safe, evidence vanishes or HTML executes source."""

import copy
import hashlib
import io
import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from changelog_advisor.__main__ import main
from changelog_advisor.pipeline import (
    PackageInput,
    _advisories,
    advisory_evidence,
    analyze_bundle,
    read_bundle,
)
from changelog_advisor.report import render_html, render_markdown, write_reports
from changelog_advisor.shared.cited.models import AdvisoryLocator, AdvisoryPointer
from changelog_advisor.shared.versions.osv import normalize_osv
from changelog_advisor.shared.versions.runtime import NodeSemver, VersionRuntimeError

ROOT = Path(__file__).resolve().parents[2]


def bundle(name="normal"):
    return read_bundle((ROOT / f"fixtures/demo-seeded/{name}.json").read_bytes())


@pytest.fixture(scope="module")
def npm():
    # Cache actual canonical npm replies only; no Python comparator or expected-answer table.
    with NodeSemver() as actual:

        class ActualReplyCache:
            def __init__(self):
                self.cache = {}

            def __getattr__(self, name):
                assert name in (
                    "validate_many",
                    "satisfies_many",
                    "compare_pairs",
                    "sort",
                    "between",
                )

                def call(*args, **kwargs):
                    key = json.dumps((name, args, kwargs), sort_keys=True)
                    if key not in self.cache:
                        self.cache[key] = getattr(actual, name)(*args, **kwargs)
                    return copy.deepcopy(self.cache[key])

                return call

        yield ActualReplyCache()


def test_actual_five_dependency_two_advisory_workflow_and_exact_citations(npm):
    got = analyze_bundle(bundle(), runtime=npm)
    assert got["workflow_status"] == "review_required"
    assert got["counts"]["packages"] == 5 and got["counts"]["advisory_records"] == 2
    assert got["counts"]["processed_entries"] == got["counts"]["selected_entries_expected"] == 10
    assert got["counts"]["judged_entries"] == 10 and got["provider_calls"] == 0
    assert got["semantic_quality"] == "unmeasured"
    for package in got["packages"]:
        assert package["installed_pin"] == "1.0.0"
        assert package["version_gap"]["kind"] == "major"
        assert package["version_gap"]["major_versions_crossed"] == 1
        assert package["version_gap"]["authority"] == "npm-semver/7.8.5"
        assert package["window"]["releases"] == ("1.1.0", "2.0.0")
        for entry in package["entries"]:
            assert entry["finding"]["verdict"] == "partial"
            assert entry["required_evidence_count"] == entry["resolved_evidence_count"] == 1
            assert entry["evidence"]["resolution"]["status"] == "resolved"
            assert entry["evidence"]["resolution"]["excerpt"] == entry["judgment"]["literal_quote"]
    advisories = [a for p in got["packages"] for a in p["advisories"]["rows"]]
    assert {a["membership"] for a in advisories} == {"affected", "not_affected"}
    assert {a["target_membership"] for a in advisories} == {"not_affected"}
    assert {a["usage_impact"] for a in advisories} == {"unknown", "does_not_apply"}
    assert all(
        a["resolved_evidence_count"] == a["required_evidence_count"] == 1 for a in advisories
    )
    assert all(a["usage_calls"] == 0 for a in advisories)


def test_refusal_workflow_preserves_packages_advisory_denominator_and_held_entry(npm):
    got = analyze_bundle(bundle("refusal"), runtime=npm)
    assert got["workflow_status"] == "partial" and got["counts"]["packages"] == 5
    assert got["counts"]["advisory_records"] == 2
    packages = {p["package"]: p for p in got["packages"]}
    assert packages["demo-vector"]["status"] == "unresolved_pin"
    assert packages["demo-vector"]["advisories"]["rows"][0]["membership"] == "unknown"
    assert packages["demo-router"]["reason"] == "registry_snapshot_not_supplied"
    assert packages["demo-cache"]["reason"] == "release_notes_not_supplied"
    held = [e for e in packages["demo-mapper"]["entries"] if e["judgment"]["status"] == "review"]
    assert len(held) == 1 and held[0]["judgment"]["judgment"] is None
    assert held[0]["evidence"]["resolution"]["status"] == "resolved"
    assert got["provider_calls"] == 0


@pytest.mark.parametrize("method", ["typed", "generative"])
def test_no_fake_model_or_keyword_fallback_and_all_original_spans_retained(npm, method):
    got = analyze_bundle(bundle(), method=method, runtime=npm)
    assert got["workflow_status"] == "partial"
    assert got["counts"]["processed_entries"] == 10 and got["counts"]["judged_entries"] == 0
    assert got["counts"]["entry_statuses"] == {"unavailable": 10}
    assert all(
        e["judgment"]["execution"]["origin"] == "not_run"
        for p in got["packages"]
        for e in p["entries"]
    )


def test_absent_advisory_snapshot_and_malformed_record_never_empty_success(npm):
    original = bundle().model_dump(mode="json")
    original["packages"][0]["advisories"]["osv"] = None
    original["packages"][1]["advisories"]["ghsa"] = ["not-json"]
    got = analyze_bundle(read_bundle(json.dumps(original).encode()), runtime=npm)
    assert got["workflow_status"] == "partial"
    assert got["packages"][0]["advisories"]["source_status"]["osv"] == "not_fetched"
    assert "not\\_fetched" in render_markdown(got)
    assert "not_fetched" in render_html(got)
    malformed = got["packages"][1]["advisories"]
    assert malformed["records_expected"] == malformed["invalid_records"] == 1
    assert malformed["rows"][0]["membership"] == "unknown"
    assert got["counts"]["advisory_records"] == 2


def test_unavailable_node_never_fabricates_unaffected(npm):
    class MissingRuntime:
        def validate_many(self, _):
            raise VersionRuntimeError("node_unavailable")

    got = analyze_bundle(bundle(), runtime=MissingRuntime())
    assert got["workflow_status"] == "partial" and got["counts"]["packages"] == 5
    assert got["counts"]["advisory_records"] == 2
    assert all(p["status"] == "unresolved_pin" for p in got["packages"])
    assert all(
        a["membership"] == "unknown" for p in got["packages"] for a in p["advisories"]["rows"]
    )


def test_actual_501_span_cap_keeps_original_expected_denominator(npm):
    original = bundle().model_dump(mode="json")
    original["selected"] = ["demo-vector"]
    data = original["packages"][0]
    data["registry_json"] = json.dumps(
        {
            "name": data["name"],
            "versions": {"1.0.0": {}, "2.0.0": {}},
            "dist-tags": {"latest": "2.0.0"},
        }
    )
    data["notes"] = "## 2.0.0\n" + "\n".join(
        f"- Added optional item {index}." for index in range(501)
    )
    got = analyze_bundle(read_bundle(json.dumps(original).encode()), runtime=npm)
    assert got["workflow_status"] == "partial"
    assert got["counts"]["selected_entries_expected"] == 501
    assert got["counts"]["processed_entries"] == 500 and got["counts"]["span_cap_remaining"] == 0
    assert got["packages"][0]["coverage"]["capped_count"] == 1


@pytest.mark.parametrize(
    "changes", ["duplicate", "extra_action", "wrong_package", "too_many_advisories"]
)
def test_bundle_refusals_before_node_or_effects(changes):
    original = bundle().model_dump(mode="json")
    if changes == "duplicate":
        with pytest.raises(ValueError):
            read_bundle(b'{"edition":1,"edition":2}')
        return
    if changes == "extra_action":
        original["action"] = "execute"
    if changes == "wrong_package":
        original["packages"][0]["name"] = "not-direct"
    if changes == "too_many_advisories":
        original["packages"][0]["advisories"]["osv"] = ["{}"] * 1001
    with pytest.raises(ValueError):
        analyze_bundle(read_bundle(json.dumps(original).encode()))


def test_advisory_current_namespace_quote_hash_and_id_guards(npm):
    data = bundle().packages[0]
    record = normalize_osv(data.advisories.osv[0].encode(), origin="synthetic")
    registry, context, metadata = advisory_evidence((record,), "local-unit")
    source = next(iter(metadata.values()))
    import hashlib

    pointer = AdvisoryPointer(
        kind="advisory:id",
        source_type="advisory_record",
        locator_subtype="id",
        source_id=source.source_id,
        source_sha256=source.source_sha256,
        source_revision=source.source_revision,
        evidence_artifact_sha256=source.evidence_artifact_sha256,
        locator=AdvisoryLocator(
            advisory_id=record.id,
            quote=record.summary,
            excerpt_sha256=hashlib.sha256(record.summary.encode()).hexdigest(),
        ),
    )
    assert registry.resolve(pointer, context).status == "resolved"
    assert (
        registry.resolve(pointer, context.model_copy(update={"namespace_id": "foreign"})).status
        == "unsupported"
    )
    assert (
        registry.resolve(pointer.model_copy(update={"source_sha256": "f" * 64}), context).status
        == "stale"
    )
    bad = pointer.locator.model_copy(update={"advisory_id": "other-id"})
    assert (
        registry.resolve(pointer.model_copy(update={"locator": bad}), context).status == "invalid"
    )
    duplicate = PackageInput.model_validate(
        {**data.model_dump(), "advisories": {"osv": (data.advisories.osv[0],) * 2, "ghsa": ()}}
    )
    rows = _advisories(duplicate, data.name, "1.0.0", "2.0.0", npm, "synthetic", "local-unit")
    assert rows["records_expected"] == 2 and rows["duplicate_records"] == 1
    assert rows["records_analyzed"] == 1


def test_static_artifacts_escape_real_source_and_refuse_overwrite(npm, tmp_path):
    got = analyze_bundle(bundle(), runtime=npm)
    html = render_html(got)
    markdown = render_markdown(got)

    class Tags(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
            self.attributes = []

        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)
            self.attributes.extend(attrs)

    parser = Tags()
    parser.feed(html)
    assert "script" not in parser.tags and "details" in parser.tags
    assert not any(k in ("src", "href") or k.startswith("on") for k, _ in parser.attributes)
    assert "&lt;script&gt;" in html and "<script>" not in markdown
    paths = write_reports(got, tmp_path / "report")
    assert set(paths) == {"checklist.json", "checklist.md", "checklist.html"}
    before = {n: Path(p).read_bytes() for n, p in paths.items()}
    with pytest.raises(FileExistsError):
        write_reports(got, tmp_path / "report")
    assert before == {n: Path(p).read_bytes() for n, p in paths.items()}


def test_cli_invalid_bundle_refuses_without_output(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"action":"execute"}')
    assert main(["analyze", "--bundle", str(path), "--out", str(tmp_path / "no-output")]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "refused"
    assert not (tmp_path / "no-output").exists()


def test_unresolvable_quote_downgrades_actual_joined_pipeline(npm, monkeypatch):
    """what_bug_this_catches: a broken quote keeps a positive finding or disappears."""
    from changelog_advisor import pipeline

    original = pipeline.span_pointer

    def broken_quote(source, span):
        pointer = original(source, span)
        return pointer.model_copy(
            update={
                "locator": pointer.locator.model_copy(
                    update={
                        "quote": "absent quote",
                        "excerpt_sha256": hashlib.sha256(b"absent quote").hexdigest(),
                    }
                )
            }
        )

    monkeypatch.setattr(pipeline, "span_pointer", broken_quote)
    got = analyze_bundle(bundle(), runtime=npm)
    entries = [entry for package in got["packages"] for entry in package["entries"]]
    assert got["workflow_status"] == "partial" and len(entries) == 10
    assert got["counts"]["selected_entries_expected"] == 10
    assert all(entry["status"] == "unsupported" for entry in entries)
    assert all(entry["finding"]["verdict"] == "unsupported" for entry in entries)
    assert all(entry["resolved_evidence_count"] == 0 for entry in entries)
    assert all(entry["required_evidence_count"] == 1 for entry in entries)
    assert "unsupported" in render_html(got) and "unsupported" in render_markdown(got)
    assert got["provider_calls"] == 0


def test_stdin_bundle_is_bounded_and_runs_same_pipeline(npm, monkeypatch, tmp_path, capsys):
    """what_bug_this_catches: '-' is treated as a filename or stdin bypasses validation."""
    from types import SimpleNamespace

    from changelog_advisor import cli

    actual = cli.analyze_bundle
    monkeypatch.setattr(cli, "analyze_bundle", lambda b, **kw: actual(b, runtime=npm, **kw))
    raw = (ROOT / "fixtures/demo-seeded/normal.json").read_bytes()
    monkeypatch.setattr("sys.stdin", SimpleNamespace(buffer=io.BytesIO(raw)))
    assert main(["analyze", "--bundle", "-", "--out", str(tmp_path / "stdin")]) == 0
    assert json.loads(capsys.readouterr().out)["counts"]["packages"] == 5
    monkeypatch.setattr("sys.stdin", SimpleNamespace(buffer=io.BytesIO(b'{"action":"execute"}')))
    assert main(["analyze", "--bundle", "-", "--out", str(tmp_path / "invalid")]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "refused"
    assert not (tmp_path / "invalid").exists()
