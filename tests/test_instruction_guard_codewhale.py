"""CodeWhale project settings are data; no agent, hook or payload is executed."""
import pytest

from aurascan.core import instruction_guard as guard


def setup_project(tmp_path, text, directory='.codewhale'):
    selected = tmp_path / 'selected'
    project = selected / 'repo'
    config = project / directory / 'config.toml'
    config.parent.mkdir(parents=True)
    config.write_text(text, encoding='utf-8')
    return selected, project, config, tmp_path / 'state'


def scan(selected, state, **kwargs):
    return guard.scan_instruction_files(
        selected, state_root=state, ai_enabled=False,
        machine_binding='inert-test-machine', **kwargs,
    )


def config_candidate(report):
    return next(c for c in report.candidates if c.surface == 'codewhale-project-configuration')


def ids(candidate):
    return {f.rule_id for f in candidate.findings}


@pytest.mark.parametrize('directory', ['.codewhale', '.deepseek'])
@pytest.mark.parametrize('text', [
    '',
    '# allow_shell = true\n# instructions = ["../../private.txt"]\n',
    'allow_shell = false\ninstructions = []\n',
    'model = "allow_shell = true"\n[example]\nallow_shell = true\ninstructions = ["../../private.txt"]\n',
])
def test_neutral_project_config_is_baseline_work_not_a_threat(tmp_path, directory, text):
    selected, project, config, state = setup_project(tmp_path, text, directory)
    report = scan(selected, state)
    candidate = config_candidate(report)
    assert candidate.baseline and not candidate.disable_eligible
    assert candidate.integrity_state == 'first-seen'
    assert candidate.findings == []
    assert guard.instruction_report_attention(report)['security_attention_required'] is False
    guard.approve_candidate(candidate.file_id, state_root=state, machine_binding='inert-test-machine')
    again = config_candidate(scan(selected, state))
    assert again.integrity_state == 'approved'
    assert not again.hash_reused  # Path-bearing settings are revalidated.
    assert not again.findings


@pytest.mark.parametrize('directory', ['.codewhale', '.deepseek'])
@pytest.mark.parametrize('key', ['allow_shell', '"allow_shell"', '"allow_\\u0073hell"'])
def test_project_shell_request_has_exact_line_without_claiming_execution(tmp_path, directory, key):
    selected, project, config, state = setup_project(tmp_path, '# harmless comment\n' + key + ' = true\n', directory)
    candidate = config_candidate(scan(selected, state))
    finding = next(f for f in candidate.findings if f.rule_id == 'IG-CONFIG-PROJECT-SHELL-ENABLE')
    assert finding.severity == 'HIGH'
    assert finding.evidence_locations == [
        {'start_line': 2, 'end_line': 2, 'behavior_families': ['broad-tool-grant']},
    ]
    assert 'does not establish execution' in finding.reason
    assert 'Fixed CodeWhale versions ignore' in finding.reason
    assert not candidate.disable_eligible


@pytest.mark.parametrize('text', [
    'allow_shell = "true"',
    'allow_shell = true\nallow_shell = false',
    'instructions = [true]',
    'instructions = ["guide.txt"',
    'prompt = """allow_shell = true"""',
])
def test_invalid_or_unsupported_toml_is_coverage_not_a_malware_match(tmp_path, text):
    selected, project, config, state = setup_project(tmp_path, text)
    report = scan(selected, state)
    candidate = config_candidate(report)
    assert ids(candidate) == {'IG-CONFIG-INVALID-TOML'}
    attention = guard.instruction_report_attention(report)
    assert attention['coverage_action_required']
    assert not attention['security_attention_required']


def test_imports_use_workspace_and_preserve_literal_hash_and_space(tmp_path):
    selected, project, config, state = setup_project(
        tmp_path, 'instructions = [\n "guide#section.txt",\n " leading.txt",\n "rules.txt",\n]\n',
    )
    for name in ['guide#section.txt', ' leading.txt', 'rules.txt']:
        (project / name).write_text('Use clear variable names.\n')
    (config.parent / 'guide#section.txt').write_text('Inert different-file sentinel.\n')
    report = scan(selected, state)
    assert config_candidate(report).findings == []
    names = {c.relative_path for c in report.candidates}
    assert {'repo/guide#section.txt', 'repo/ leading.txt', 'repo/rules.txt'} <= names
    assert 'repo/.codewhale/guide#section.txt' not in names
    assert all(not c.findings for c in report.candidates)


@pytest.mark.parametrize('reference', [
    '../private.txt', '/outside/fixture-only.txt', '~/.ssh/id_fixture',
    '.aws/credentials', '.ssh/id_fixture', '.codex/auth.json', '.env',
    '\\u002e\\u002e/private.txt',
])
def test_unsafe_instruction_references_are_not_read_or_persisted(tmp_path, monkeypatch, reference):
    # Every real file here is an inert sentinel in a temporary tree.
    selected, project, config, state = setup_project(
        tmp_path, 'instructions = [\n "' + reference + '",\n]\n',
    )
    sensitive_files = [selected / 'private.txt', project / '.aws/credentials',
                       project / '.ssh/id_fixture', project / '.codex/auth.json', project / '.env']
    for f in sensitive_files:
        f.parent.mkdir(exist_ok=True)
        f.write_text('INERT_PRIVATE_CONTENT_MARKER')
    original = guard._safe_read_candidate
    observed = []
    def checked_read(path, root, limits):
        assert path not in sensitive_files
        observed.append(path)
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked_read)
    report = scan(selected, state)
    candidate = config_candidate(report)
    assert ids(candidate) == {'IG-CONFIG-PROJECT-INSTRUCTION-ESCAPE'}
    finding = candidate.findings[0]
    assert finding.severity == 'HIGH'
    assert finding.evidence_locations[0]['start_line'] == 2
    assert observed == [config]
    saved = '\n'.join(f.read_text() for f in state.rglob('*.json'))
    assert 'INERT_PRIVATE_CONTENT_MARKER' not in saved
    assert reference not in saved
    assert '.aws/credentials' not in saved and '.ssh/id_fixture' not in saved


@pytest.mark.parametrize('kind', ['file', 'directory', 'credential'])
def test_import_links_do_not_expand_project_boundary(tmp_path, monkeypatch, kind):
    selected, project, config, state = setup_project(tmp_path, 'instructions = ["linked/rules.txt"]\n' if kind == 'directory' else 'instructions = ["linked.txt"]\n')
    target = selected / 'outside' / 'rules.txt'
    if kind == 'credential':
        target = project / '.aws' / 'credentials'
    target.parent.mkdir(parents=True)
    target.write_text('DO_NOT_READ_INERT_SENTINEL')
    link = project / ('linked' if kind == 'directory' else 'linked.txt')
    link.symlink_to(target.parent if kind == 'directory' else target, target_is_directory=kind == 'directory')
    original = guard._safe_read_candidate
    def checked(path, root, limits):
        assert path != target
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked)
    candidate = config_candidate(scan(selected, state))
    assert candidate.findings and max(f.severity for f in candidate.findings) == 'HIGH'
    assert any(f.evidence_locations and f.evidence_locations[0]['start_line'] == 1 for f in candidate.findings)


@pytest.mark.parametrize('directory', ['.codewhale', '.deepseek'])
def test_symlinked_control_directory_is_reported_without_traversal(tmp_path, directory):
    selected = tmp_path / 'selected'
    selected.mkdir()
    target = tmp_path / 'outside'
    target.mkdir()
    (target / 'config.toml').write_text('allow_shell = true\n')
    (selected / directory).symlink_to(target, target_is_directory=True)
    report = scan(selected, tmp_path / 'state')
    assert not report.candidates
    assert 'IG-INTEGRITY-CONTROL-DIRECTORY-SYMLINK' in {f.rule_id for f in report.findings}


def test_config_link_to_other_workspace_is_not_read(tmp_path, monkeypatch):
    selected, project, config, state = setup_project(tmp_path, '')
    outside = selected / 'other-config.txt'
    outside.write_text('INERT_OTHER_WORKSPACE_MARKER')
    config.unlink()
    config.symlink_to(outside)
    original = guard._safe_read_candidate
    def checked(path, root, limits):
        assert path != outside
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked)
    report = scan(selected, state)
    assert 'IG-INTEGRITY-SYMLINK-ESCAPE' in ids(config_candidate(report))


def test_import_replacement_after_config_approval_is_rechecked(tmp_path):
    selected, project, config, state = setup_project(tmp_path, 'instructions = ["rules.txt"]\n')
    source = project / 'rules.txt'
    source.write_text('Use clear names.\n')
    first = config_candidate(scan(selected, state))
    guard.approve_candidate(first.file_id, state_root=state, machine_binding='inert-test-machine')
    outside = selected / 'private.txt'
    outside.write_text('INERT_NEVER_READ')
    source.unlink()
    source.symlink_to(outside)
    second = config_candidate(scan(selected, state))
    assert not second.hash_reused
    assert 'IG-INTEGRITY-SYMLINK-ESCAPE' in ids(second)


def test_unrelated_config_toml_and_global_xdg_settings_are_not_project_controls(tmp_path):
    selected = tmp_path / 'selected'
    for relative in ['config.toml', '.config/codewhale/config.toml', '.codewhale/example.toml']:
        f = selected / relative
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text('allow_shell = true\n')
    assert scan(selected, tmp_path / 'state').candidates == []


@pytest.mark.parametrize('max_candidates', [1, 100])
@pytest.mark.parametrize('all_markdown', [False, True])
def test_independent_control_discovery_keeps_project_boundary_before_config_page(
    tmp_path, monkeypatch, max_candidates, all_markdown,
):
    selected = tmp_path / 'selected'
    project = selected / 'repo'
    project.mkdir(parents=True)
    # Create the independently discovered control before the config directory.
    (project / 'AGENTS.md').write_text('@../.aws/credentials\n')
    config = project / '.codewhale/config.toml'
    config.parent.mkdir()
    config.write_text('instructions = ["AGENTS.md"]\n')
    target = selected / '.aws/credentials'
    target.parent.mkdir()
    target.write_text('INERT_OUTSIDE_CREDENTIAL_MARKER')
    original = guard._safe_read_candidate
    def checked(path, root, limits):
        assert path != target
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked)
    state = tmp_path / 'state'
    pages = []
    for _ in range(12):
        report = scan(selected, state, all_markdown=all_markdown,
                      limits=guard.InstructionGuardLimits(max_candidates=max_candidates))
        pages.append(report)
        if not report.continuation_pending:
            break
    else:
        pytest.fail('bounded continuation did not finish')
    assert any(f.severity == 'HIGH' for page in pages for c in page.candidates for f in c.findings)


def test_all_markdown_import_becomes_baseline_without_enrolling_unrelated_text(tmp_path):
    selected, project, config, state = setup_project(tmp_path, 'instructions = ["notes.md"]\n')
    (project / 'notes.md').write_text('Use clear names.\n')
    (project / 'ordinary.md').write_text('Ordinary documentation.\n')
    report = scan(selected, state, all_markdown=True)
    by_name = {c.relative_path: c for c in report.candidates}
    assert by_name['repo/notes.md'].baseline
    assert not by_name['repo/ordinary.md'].baseline


def test_same_line_escapes_merge_roles_and_bound_large_location_sets(tmp_path):
    selected, project, config, state = setup_project(
        tmp_path, "instructions = ['../outside.txt', '../.aws/credentials']\n",
    )
    finding = config_candidate(scan(selected, state)).findings[0]
    assert finding.evidence_locations == [
        {'start_line': 1, 'end_line': 1, 'behavior_families': ['credential-access', 'integrity']},
    ]
    config.write_text('instructions = [\n' + '\n'.join(
        "'../outside.txt'," if i % 2 else "'../.aws/credentials'," for i in range(40)
    ) + '\n]\n')
    finding = next(f for f in config_candidate(scan(selected, state)).findings
                   if f.rule_id == 'IG-CONFIG-PROJECT-INSTRUCTION-ESCAPE')
    assert len(finding.evidence_locations) == guard.MAX_EVIDENCE_LOCATIONS
    assert finding.evidence_truncated


def test_pending_context_dedup_prefers_narrowest_project_and_keeps_literal_identity():
    path = 'outer/inner/note#part.md'
    outer = {'path': path, 'project_config': 'outer/.codewhale/config.toml', 'line': 2}
    inner = {'path': path, 'project_config': 'outer/inner/.codewhale/config.toml', 'line': 3}
    assert guard._coalesce_pending_candidates([path, outer, inner, path, outer]) == [inner]


def test_legacy_cursor_resumes_and_upgrades_without_dropping_candidates(tmp_path):
    import json
    selected = tmp_path / 'selected'
    selected.mkdir()
    for name in ['one', 'two', 'three']:
        directory = selected / name
        directory.mkdir()
        (directory / 'AGENTS.md').write_text('Use clear names.\n')
    state = tmp_path / 'state'
    first = scan(selected, state, limits=guard.InstructionGuardLimits(max_directories=1))
    assert first.continuation_pending
    path = next((state / 'cursors').glob('*.json'))
    cursor = json.loads(path.read_text())
    cursor['schema'] = 'instruction_guard_cursor/1.0'
    path.write_text(json.dumps(cursor))
    pages = [first]
    for _ in range(8):
        pages.append(scan(selected, state, limits=guard.InstructionGuardLimits(max_directories=1)))
        if path.exists():
            assert json.loads(path.read_text())['schema'] == 'instruction_guard_cursor/1.1'
        if not pages[-1].continuation_pending:
            break
    else:
        pytest.fail('legacy continuation did not finish')
    assert {c.relative_path for c in pages[-1].candidates} == {
        'one/AGENTS.md', 'two/AGENTS.md', 'three/AGENTS.md',
    }


@pytest.mark.parametrize('change', [
    {'project_config': '../.codewhale/config.toml'},
    {'project_config': 'repo/ordinary.toml'},
    {'path': 'outside/rules.txt'},
    {'line': True},
    {'line': -1},
    {'extra': 'unrecognized'},
])
def test_project_cursor_rejects_invalid_boundary_context(change):
    value = {'path': 'repo/rules.txt', 'project_config': 'repo/.codewhale/config.toml', 'line': 2}
    value.update(change)
    with pytest.raises(ValueError):
        guard._pending_candidate_relative(value)


def test_removing_project_config_does_not_reuse_empty_project_import_cache(tmp_path):
    selected, project, config, state = setup_project(tmp_path, 'instructions = ["AGENTS.md"]\n')
    instructions = project / 'AGENTS.md'
    instructions.write_text('@policy.txt\n')
    (project / 'policy.txt').write_text('Use clear names.\n')
    first = scan(selected, state)
    source = next(c for c in first.candidates if c.relative_path == 'repo/AGENTS.md')
    guard.approve_candidate(source.file_id, state_root=state, machine_binding='inert-test-machine')
    config.unlink()
    second = scan(selected, state)
    source = next(c for c in second.candidates if c.relative_path == 'repo/AGENTS.md')
    assert not source.hash_reused
    assert any(c.relative_path == 'repo/policy.txt' for c in second.candidates)
    child = next(c for c in second.candidates if c.relative_path == 'repo/policy.txt')
    assert not child.read_error
    assert all(f.file_id != child.file_id for f in second.findings if f.rule_id == 'IG-INTEGRITY-CONTROL-MISSING')


def test_boundary_inference_does_not_probe_through_symlinked_parent(tmp_path, monkeypatch):
    selected, project, config, state = setup_project(tmp_path, '')
    outside = tmp_path / 'outside'
    (outside / '.codewhale').mkdir(parents=True)
    (outside / '.codewhale/config.toml').write_text('allow_shell = true\n')
    (project / 'linked').symlink_to(outside, target_is_directory=True)
    assert guard._containing_project_config(project / 'linked/AGENTS.md', selected, float('inf')) == 'repo/.codewhale/config.toml'


def test_project_boundary_deadline_retains_unread_candidate(tmp_path, monkeypatch):
    selected, project, config, state = setup_project(tmp_path, 'instructions = []\n')
    original = guard._containing_project_config
    def deadline_once(path, root, deadline, user_home=None):
        raise TimeoutError('inert deadline injection')
    monkeypatch.setattr(guard, '_containing_project_config', deadline_once)
    first = scan(selected, state)
    assert first.continuation_pending and first.truncated and not first.candidates
    monkeypatch.setattr(guard, '_containing_project_config', original)
    second = scan(selected, state)
    assert config_candidate(second).relative_path == 'repo/.codewhale/config.toml'
    assert not second.continuation_pending


@pytest.mark.parametrize('directory', ['.codewhale', '.deepseek'])
def test_user_global_auth_config_is_neither_read_nor_treated_as_project_grant(tmp_path, monkeypatch, directory):
    selected = tmp_path / 'fake-home'
    global_config = selected / directory / 'config.toml'
    global_config.parent.mkdir(parents=True)
    global_config.write_text('allow_shell = true\napi_key = "FAKE_GLOBAL_CREDENTIAL"\n')
    # A real repository nested under the selected home still gets project rules.
    project_config = selected / 'repo' / directory / 'config.toml'
    project_config.parent.mkdir(parents=True)
    project_config.write_text('allow_shell = true\n')
    original = guard._safe_read_candidate
    def checked(path, root, limits):
        assert path != global_config
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked)
    state = tmp_path / 'private-state'
    report = scan(selected, state, env={'HOME': str(selected)})
    assert len(report.candidates) == 1
    assert ids(config_candidate(report)) == {'IG-CONFIG-PROJECT-SHELL-ENABLE'}
    assert 'FAKE_GLOBAL_CREDENTIAL' not in '\n'.join(f.read_text() for f in state.rglob('*.json'))
    assert guard._containing_project_config(selected / 'AGENTS.md', selected, float('inf'), selected) == ''


def test_explicit_import_of_user_global_config_remains_unread(tmp_path, monkeypatch):
    selected = tmp_path / 'fake-home'
    global_config = selected / '.codewhale/config.toml'
    global_config.parent.mkdir(parents=True)
    global_config.write_text('api_key = "FAKE_GLOBAL_CREDENTIAL"\n')
    (selected / 'AGENTS.md').write_text('@.codewhale/config.toml\n')
    original = guard._safe_read_candidate
    def checked(path, root, limits):
        assert path != global_config
        return original(path, root, limits)
    monkeypatch.setattr(guard, '_safe_read_candidate', checked)
    report = scan(selected, tmp_path / 'private-state', env={'HOME': str(selected)})
    imported = next(c for c in report.candidates if c.relative_path == '.codewhale/config.toml')
    assert imported.read_error and imported.findings
    assert 'IG-CONFIG-PROJECT-SHELL-ENABLE' not in ids(imported)
