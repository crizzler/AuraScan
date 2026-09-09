"""Project-boundary regressions using private roots and inert file contents."""

from pathlib import Path

import pytest

import aurascan.core.instruction_guard as guard


def _tree(tmp_path, config_text):
    selected = tmp_path / "selected"
    project = selected / "project"
    config_dir = project / ".codewhale"
    config_dir.mkdir(parents=True)
    config = config_dir / "config.toml"
    config.write_text(config_text, encoding="utf-8")
    return selected, project, config, tmp_path / "private-state"


def _read_spy(monkeypatch):
    captured = []
    original = guard._safe_read_candidate

    def read(path, root, limits):
        result = original(path, root, limits)
        if result.data:
            captured.append(Path(path))
        return result

    monkeypatch.setattr(guard, "_safe_read_candidate", read)
    return captured


def _scan(selected, state, max_candidates=100):
    return guard.scan_instruction_files(
        selected,
        state_root=state,
        ai_enabled=False,
        machine_binding="codewhale-boundary-fixture",
        limits=guard.InstructionGuardLimits(max_candidates=max_candidates),
    )


def _finish_pages(selected, state, first, max_candidates=1):
    pages = [first]
    for _ in range(12):
        if not pages[-1].continuation_pending:
            return pages
        pages.append(_scan(selected, state, max_candidates=max_candidates))
    pytest.fail("bounded fixture continuation did not complete")


def _findings(pages):
    return [
        finding
        for page in pages
        for findings in [page.findings] + [item.findings for item in page.candidates]
        for finding in findings
    ]


def test_deferred_instruction_keeps_literal_hash_in_filename(tmp_path, monkeypatch):
    selected, project, config, state = _tree(
        tmp_path, 'instructions = ["note#part.md"]\n'
    )
    intended = project / "note#part.md"
    intended.write_text("Use clear prose.\n", encoding="utf-8")
    decoy = project / "note"
    decoy.write_text("Unrelated inert decoy.\n", encoding="utf-8")
    captured = _read_spy(monkeypatch)

    first = _scan(selected, state, max_candidates=1)
    assert first.continuation_pending
    assert config in captured and intended not in captured
    pages = _finish_pages(selected, state, first)

    assert intended in captured
    assert decoy not in captured
    assert any(
        item.relative_path == "project/note#part.md" and not item.read_error
        for page in pages for item in page.candidates
    )


@pytest.mark.parametrize("destination", ["another-project", "credential-file"])
def test_deferred_instruction_revalidates_project_and_credential_boundary(
    tmp_path, monkeypatch, destination
):
    selected, project, config, state = _tree(
        tmp_path, 'instructions = ["notes.txt"]\n'
    )
    imported = project / "notes.txt"
    imported.write_text("Use clear prose.\n", encoding="utf-8")
    if destination == "another-project":
        target = selected / "other-project" / "notes.txt"
    else:
        target = project / ".aws" / "credentials"
    target.parent.mkdir(parents=True)
    target.write_text("FAKE_CREDENTIAL_BYTES_FOR_TEST_ONLY\n", encoding="utf-8")
    captured = _read_spy(monkeypatch)

    first = _scan(selected, state, max_candidates=1)
    assert first.continuation_pending
    assert config in captured and imported not in captured
    imported.unlink()
    imported.symlink_to(target)
    pages = _finish_pages(selected, state, first)

    assert target not in captured
    assert any(finding.severity == "HIGH" for finding in _findings(pages))


def test_project_config_symlink_does_not_read_credential_target(tmp_path, monkeypatch):
    selected, project, config, state = _tree(tmp_path, "")
    target = project / ".aws" / "credentials"
    target.parent.mkdir()
    target.write_text('token = "FAKE_TOKEN_FOR_TEST_ONLY"\n', encoding="utf-8")
    config.unlink()
    config.symlink_to(target)
    captured = _read_spy(monkeypatch)

    report = _scan(selected, state)

    assert target not in captured
    assert any(finding.severity == "HIGH" for finding in _findings([report]))


def test_cancelled_symlink_component_cannot_select_a_different_instruction_file(
    tmp_path, monkeypatch
):
    selected, project, _config, state = _tree(
        tmp_path, 'instructions = ["link/../notes.md"]\n'
    )
    outside_parent = selected / "other-project"
    (outside_parent / "nested").mkdir(parents=True)
    (project / "link").symlink_to(outside_parent / "nested", target_is_directory=True)
    outside = outside_parent / "notes.md"
    outside.write_text("Outside inert text.\n", encoding="utf-8")
    normalized_decoy = project / "notes.md"
    normalized_decoy.write_text("Unrelated inert decoy.\n", encoding="utf-8")
    captured = _read_spy(monkeypatch)

    report = _scan(selected, state)

    assert normalized_decoy not in captured
    assert outside not in captured
    config = next(item for item in report.candidates if item.relative_path.endswith("config.toml"))
    assert any(finding.severity in {"MEDIUM", "HIGH"} for finding in config.findings)


def test_recursive_project_import_cannot_read_credentials_in_broader_selected_root(
    tmp_path, monkeypatch
):
    selected, project, _config, state = _tree(
        tmp_path, 'instructions = ["notes.md"]\n'
    )
    notes = project / "notes.md"
    notes.write_text("@../.aws/credentials\n", encoding="utf-8")
    target = selected / ".aws" / "credentials"
    target.parent.mkdir()
    target.write_text("FAKE_CREDENTIAL_BYTES_FOR_TEST_ONLY\n", encoding="utf-8")
    captured = _read_spy(monkeypatch)

    report = _scan(selected, state)

    assert notes in captured
    assert target not in captured
    assert any(finding.severity == "HIGH" for finding in _findings([report]))


def test_recursive_project_import_uses_importing_files_actual_parent(tmp_path, monkeypatch):
    selected, project, _config, state = _tree(
        tmp_path, 'instructions = ["docs/notes.md"]\n'
    )
    (project / "docs").mkdir()
    notes = project / "docs" / "notes.md"
    notes.write_text("@policy.md\n", encoding="utf-8")
    intended = project / "docs" / "policy.md"
    intended.write_text("Use clear prose.\n", encoding="utf-8")
    decoy = project / "policy.md"
    decoy.write_text("Unrelated inert decoy.\n", encoding="utf-8")
    captured = _read_spy(monkeypatch)

    _scan(selected, state)

    assert notes in captured and intended in captured
    assert decoy not in captured


def test_multiple_project_import_findings_keep_each_lines_observed_role(tmp_path):
    selected, _project, _config, state = _tree(
        tmp_path,
        "instructions = [\n"
        "  '../outside.md',\n"
        "  '../.aws/credentials',\n"
        "]\n",
    )

    report = _scan(selected, state)

    finding = next(
        finding for finding in _findings([report])
        if finding.rule_id == "IG-CONFIG-PROJECT-INSTRUCTION-ESCAPE"
    )
    assert "credential-access" in finding.behavior_families
    assert {location["start_line"] for location in finding.evidence_locations} == {2, 3}
    ordinary_escape = next(
        location for location in finding.evidence_locations if location["start_line"] == 2
    )
    credential_escape = next(
        location for location in finding.evidence_locations if location["start_line"] == 3
    )
    assert "credential-access" not in ordinary_escape["behavior_families"]
    assert "credential-access" in credential_escape["behavior_families"]
