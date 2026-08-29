from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def workflow_text() -> str:
    return CI_WORKFLOW.read_text(encoding="utf-8")


def test_ci_workflow_runs_for_supported_change_paths():
    text = workflow_text()

    assert text.startswith("name: CI\n")
    assert "\non:\n" in text
    assert "\n  push:\n" in text
    assert "\n  pull_request:\n" in text
    assert "\n  workflow_dispatch:\n" in text
    assert "\npermissions:\n  contents: read\n" in text
    assert "\nconcurrency:\n" in text
    assert "  cancel-in-progress: true\n" in text


def test_ci_workflow_covers_oldest_and_current_supported_python():
    text = workflow_text()

    assert 'python-version: ["3.8", "3.14"]' in text
    assert "runs-on: ubuntu-latest" in text
    assert "fail-fast: false" in text


def test_ci_workflow_keeps_all_release_test_gates():
    text = workflow_text()
    required_commands = (
        'python -m pip install -e ".[test]"',
        "python -m compileall aurascan tests tools",
        "python -m pytest -q",
        "python tools/audit_presenter_coverage.py --strict",
        "python tools/audit_presenter_coverage.py --strict-medium",
    )

    for command in required_commands:
        assert command in text
    assert "continue-on-error: true" not in text


def test_ci_workflow_never_configures_or_starts_live_ai():
    text = workflow_text()

    assert 'AURASCAN_AI_ENABLED: "0"' in text
    assert 'AURASCAN_AI_ENABLED: "1"' not in text
    assert "--check-ai" not in text
    forbidden_live_ai_configuration = (
        "AURASCAN_AI_KEY:",
        "AURASCAN_OPENAI_API_KEY:",
        "AURASCAN_ANTHROPIC_API_KEY:",
        "AURASCAN_DEEPSEEK_API_KEY:",
        "AURASCAN_GEMINI_API_KEY:",
        "AURASCAN_OPENROUTER_API_KEY:",
        "AURASCAN_LOCAL_AI_API_KEY:",
        "AURASCAN_AI_BASE_URL:",
        "AURASCAN_AI_PROVIDER:",
        "llama-server",
        "lms server start",
        "services:",
    )
    for value in forbidden_live_ai_configuration:
        assert value not in text
