"""Anti-cheat anchors: corpus hash, label audit provenance, probe compile set, selftest deltas."""

import hashlib
import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import injection_corpus_export as exporter  # noqa: E402
import injection_label_audit as audit  # noqa: E402
import injection_parity as parity  # noqa: E402

from aurascan.analyzers.injection import encoded, override  # noqa: E402

PROBE_DIR = os.path.join(TOOLS, "injection_probe")
LABEL_LISTS = os.path.join(ROOT, "tests", "fixtures", "injection_corpus", "csharp_label_lists.txt")


def test_corpus_hash_is_reproducible_from_the_retained_raw_tree():
    derived = exporter.derive_bytes()
    assert hashlib.sha256(derived).hexdigest() == exporter.pinned_sha256()


def test_retained_raw_tree_holds_every_sample():
    assert len(exporter._walk_raw(exporter.RAW)) == 550


def test_corpus_shape_is_exactly_the_harness_counts():
    samples, benign = exporter.derive_records()
    assert len(samples) == 240
    assert len(benign) == 310
    assert exporter.shape_of(samples) == {
        "instruction-override": 50,
        "persona-hijack": 40,
        "data-exfiltration": 40,
        "encoded-obfuscated": 50,
        "multilingual": 40,
        "tool-command": 10,
        "delimiter-escape": 10,
    }


def test_harvest_metadata_names_the_commit_and_a_clean_status():
    with open(exporter.HARVEST, "r", encoding="utf-8") as handle:
        harvest = json.load(handle)
    assert len(harvest["anticopy_head"]) == 40
    assert harvest["anticopy_status_porcelain"] == ""
    assert harvest["sample_counts"]["total"] == 550
    assert harvest["tree_sha256"] == exporter.tree_digest()


def test_label_audit_lists_are_literal_copies_not_the_detector_objects():
    assert audit.OVERRIDE_LITERAL_PHRASES is not override.LITERAL_PHRASES
    assert audit.OVERRIDE_LITERAL_IDS is not override.LITERAL_IDS
    assert isinstance(audit.OVERRIDE_LITERAL_PHRASES, tuple)
    assert isinstance(override.LITERAL_PHRASES, tuple)


def test_label_audit_block_hash_is_pinned():
    assert audit.label_block_sha256() == audit.LABEL_BLOCK_SHA256


def test_csharp_label_lists_extract_is_pinned():
    with open(LABEL_LISTS, "rb") as handle:
        assert hashlib.sha256(handle.read()).hexdigest() == audit.CSHARP_LABEL_LISTS_SHA256


def test_tables_hash_is_stable_and_separate_from_the_label_hash():
    assert parity.tables_sha256() == parity.tables_sha256()
    assert parity.tables_sha256() != audit.LABEL_BLOCK_SHA256


def test_label_audit_passes_over_the_harvested_corpus():
    samples, _ = exporter.derive_records()

    class _Sample(object):
        __slots__ = ("class_id", "path", "content")

        def __init__(self, record):
            self.class_id = record["class"]
            self.path = record["path"]
            self.content = record["content"]

    wrapped = [_Sample(record) for record in samples]
    assert audit.audit_injection_labels(wrapped) is None


def test_label_audit_flags_exactly_the_five_honest_paraphrases():
    samples, _ = exporter.derive_records()

    class _Sample(object):
        __slots__ = ("class_id", "path", "content")

        def __init__(self, record):
            self.class_id = record["class"]
            self.path = record["path"]
            self.content = record["content"]

    wrapped = [_Sample(record) for record in samples]
    unreachable = [path.rsplit("/", 1)[-1] for path in audit.audit_override_labels(wrapped)]
    assert unreachable == ["sample-45.cs", "sample-46.cs", "sample-47.cs", "sample-48.cs", "sample-49.cs"]


def test_label_audit_catches_an_exfil_sample_without_a_verb():
    class _Bad(object):
        class_id = "data-exfiltration"
        path = "x.md"
        content = "The .env file is described here."

    assert "no sensitive-artifact" in audit.audit_injection_labels([_Bad()])


# --- probe compile set -----------------------------------------------------------------------------

def test_probe_compile_set_is_exactly_core_and_runtime():
    with open(os.path.join(PROBE_DIR, "Probe.csproj"), "r", encoding="utf-8") as handle:
        text = handle.read()
    includes = [line.strip() for line in text.splitlines() if line.strip().startswith("<Compile Include=")]
    assert len(includes) == 3
    assert any('Include="Program.cs"' in line for line in includes)
    assert any('Core/**/*.cs"' in line for line in includes)
    assert any('Runtime/**/*.cs"' in line for line in includes)
    removals = [line.strip() for line in text.splitlines() if line.strip().startswith("<Compile Remove")]
    assert removals == []
    assert "$(AntiCopyRoot)" in text


def test_probe_directory_holds_no_shadow_source_files():
    entries = sorted(name for name in os.listdir(PROBE_DIR) if name.endswith((".cs", ".csproj")))
    assert entries == ["Probe.csproj", "Program.cs"]


# --- selftest --------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def loaded():
    injections, controls = parity.load_corpus()
    return injections, controls, parity.load_golden()


def test_selftest_reports_the_pinned_deltas(loaded, capsys):
    injections, controls, golden = loaded
    assert parity.run_selftest(injections, controls, golden) == parity.EXIT_PASS
    out = capsys.readouterr().out
    assert "override.tp expected=45 actual=43 delta=-2" in out
    assert "override.matches expected=45 actual=65 delta=+20" in out
    assert "benign.high_findings expected=0 actual=12 delta=+12" in out
    assert "override.tp expected=45 actual=41 delta=-4" in out
    assert "encoded.tp expected=43 actual=37 delta=-6" in out
    assert "encoded.tp expected=43 actual=45 delta=+2" in out


def test_encoded_mutants_patch_the_production_tables(loaded, capsys):
    injections, controls, golden = loaded
    original = encoded.LEET_MAP
    snapshot = dict(original)
    with parity.mutant_leet_without_5():
        assert "5" not in encoded.LEET_MAP
        assert encoded.LEET_MAP is not original
    assert encoded.LEET_MAP is original
    assert encoded.LEET_MAP == snapshot

    with parity.mutant_no_leet_count_guard():
        assert encoded.LEET_MIN_HITS == 0
    assert encoded.LEET_MIN_HITS == 2


def test_baseline_reproduces_before_any_mutant_runs(loaded):
    injections, controls, golden = loaded
    rows, differing = parity.measure(injections, controls, golden)
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_PASS


def test_inert_mutant_exits_six(loaded, capsys):
    injections, controls, golden = loaded
    inert = {"name": "M0", "what": "deliberately inert", "factory": parity.mutant_inert, "expected": {}}
    assert parity.run_selftest(injections, controls, golden, extra_mutants=(inert,)) == parity.EXIT_SELFTEST
    assert "inert mutant moved nothing, so it proves nothing" in capsys.readouterr().out


def test_wrong_expected_delta_exits_six(loaded, capsys):
    injections, controls, golden = loaded
    wrong = {
        "name": "M0",
        "what": "inert but declares a delta",
        "factory": parity.mutant_inert,
        "expected": {"override.tp": 44},
    }
    assert parity.run_selftest(injections, controls, golden, extra_mutants=(wrong,)) == parity.EXIT_SELFTEST
    assert "INERT" in capsys.readouterr().out


def test_each_mutant_restores_the_original_table():
    before = (override.LITERAL_PHRASES, override.LITERAL_IDS, override.STEM_FAMILY_PATTERN, override._overlaps)
    for mutant in parity.MUTANTS:
        with mutant["factory"]():
            assert override.LITERAL_PHRASES is not None
    after = (override.LITERAL_PHRASES, override.LITERAL_IDS, override.STEM_FAMILY_PATTERN, override._overlaps)
    assert before == after


def test_mutants_patch_the_production_module_not_a_copy():
    original = override.LITERAL_PHRASES
    with parity.mutant_drop_literal_16():
        assert override.LITERAL_PHRASES is not original
        assert len(override.LITERAL_PHRASES) == 17
    assert override.LITERAL_PHRASES is original


# --- the gate's own failure paths ------------------------------------------------------------------

def test_gate_exits_two_on_a_real_metric_delta(loaded):
    injections, controls, golden = loaded
    rows, differing = parity.measure(injections, controls, golden)
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_PASS

    rows["encoded.tp"] = rows["encoded.tp"] + 1
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_METRIC


def test_gate_exits_four_on_a_golden_mismatch(loaded):
    injections, controls, golden = loaded
    rows, differing = parity.measure(injections, controls, golden)
    rows["golden.sample_mismatches"] = 3
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_GOLDEN


def test_gate_exits_five_on_a_shape_mismatch(loaded):
    injections, controls, golden = loaded
    rows, differing = parity.measure(injections, controls, golden)
    rows["corpus.samples_total"] = 549
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_SHAPE


def test_reported_only_rows_never_fail_the_gate(loaded):
    injections, controls, golden = loaded
    rows, differing = parity.measure(injections, controls, golden)
    rows["report.unknown.high_findings"] = 0
    _lines, code = parity.compare_rows(rows, differing)
    assert code == parity.EXIT_PASS


def test_check_anchors_detects_a_one_byte_corpus_drift(tmp_path, monkeypatch):
    raw = str(tmp_path / "raw")
    shutil.copytree(exporter.RAW, raw)
    target = os.path.join(raw, "Assets", "Corpus", "Injection", "override", "sample-0.cs")
    with open(target, "ab") as handle:
        handle.write(b"\n//drift\n")

    monkeypatch.setattr(parity, "RAW", raw)
    assert parity.check_anchors() == parity.EXIT_CORPUS


def test_check_anchors_detects_a_dirty_anticopy_checkout(tmp_path, monkeypatch):
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    subprocess.run(["git", "-C", repo, "init", "-q"], check=True)
    with open(os.path.join(repo, "dirty.txt"), "w", encoding="utf-8") as handle:
        handle.write("untracked\n")

    monkeypatch.setattr(parity, "ANTICOPY", repo)
    assert parity.check_anchors() == parity.EXIT_CORPUS


def _anticopy_is_clean() -> bool:
    if not os.path.isdir(parity.ANTICOPY):
        return False
    result = subprocess.run(
        ["git", "-C", parity.ANTICOPY, "status", "--porcelain"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.returncode == 0 and not result.stdout.strip()


@pytest.mark.skipif(
    not _anticopy_is_clean(), reason="AntiCopy checkout is absent or dirty"
)
def test_check_anchors_detects_a_golden_anchor_mismatch(tmp_path, monkeypatch):
    with open(parity.GOLDEN, "r", encoding="utf-8") as handle:
        golden = json.load(handle)
    golden["anticopy_head"] = "0" * 40
    drifted = tmp_path / "spans.json"
    drifted.write_text(json.dumps(golden), encoding="utf-8")

    monkeypatch.setattr(parity, "GOLDEN", str(drifted))
    assert parity.check_anchors() == parity.EXIT_GOLDEN
