import importlib.util
from pathlib import Path


TOOLS_PATH = Path(__file__).resolve().parents[1] / "tools" / "aur_warning_tune.py"
spec = importlib.util.spec_from_file_location("aur_warning_tune", TOOLS_PATH)
aur_warning_tune = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aur_warning_tune)


def fake_fetcher(url: str) -> str:
    if "PKGBUILD" in url:
        return 'pkgname=demo\npkgver=1\nsource=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n'
    if ".SRCINFO" in url:
        return "pkgbase = demo\n\tsource = http://example.invalid/src.tar.gz\n\tsha256sums = SKIP\n"
    raise aur_warning_tune.AurFetchError(url)


def noisy_fetcher(url: str) -> str:
    if "PKGBUILD" in url:
        return (
            'pkgname=demo\npkgver=1\nsource=("http://example.invalid/src.tar.gz")\n'
            'sha256sums=(SKIP)\n'
            'package() {\n'
            '  install -Dm644 demo.service "$pkgdir/usr/lib/systemd/system/demo.service"\n'
            '  systemctl enable demo.service\n'
            '  crontab - < fixture.cron\n'
            '  eval "$generated_command"\n'
            '}\n'
        )
    if ".SRCINFO" in url:
        return "pkgbase = demo\n\tsource = http://example.invalid/src.tar.gz\n\tsha256sums = SKIP\n"
    raise aur_warning_tune.AurFetchError(url)


def test_aur_plain_url_points_to_metadata_only_endpoint():
    url = aur_warning_tune.aur_plain_url("demo", "PKGBUILD")

    assert url == "https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=demo"


def test_fetch_package_metadata_uses_fake_fetcher(tmp_path: Path):
    pkgbuild = aur_warning_tune.fetch_package_metadata("demo", tmp_path, fetcher=fake_fetcher)

    assert pkgbuild.exists()
    assert (pkgbuild.parent / ".SRCINFO").exists()
    assert "source" in pkgbuild.read_text()


def test_fetch_text_wraps_os_errors_as_fetch_errors(monkeypatch):
    def broken_urlopen(*_args, **_kwargs):
        raise OSError("network broke")

    monkeypatch.setattr(aur_warning_tune.urllib.request, "urlopen", broken_urlopen)

    try:
        aur_warning_tune.fetch_text("https://example.invalid/PKGBUILD", timeout=1)
    except aur_warning_tune.AurFetchError as exc:
        assert "network broke" in str(exc)
    else:
        raise AssertionError("expected AurFetchError")


def test_analyze_pkgbuild_counts_visible_warning_groups(tmp_path: Path):
    pkgbuild = aur_warning_tune.fetch_package_metadata("demo", tmp_path, fetcher=fake_fetcher)

    result = aur_warning_tune.analyze_pkgbuild("demo", pkgbuild)

    assert result["package"] == "demo"
    assert result["visible_group_count"] >= 1
    assert "SOURCE-META-HTTP-NOT-HTTPS" in result["rule_counts"]


def test_analyze_pkgbuild_counts_new_rule_families(tmp_path: Path):
    pkgbuild = aur_warning_tune.fetch_package_metadata("demo", tmp_path, fetcher=noisy_fetcher)

    result = aur_warning_tune.analyze_pkgbuild("demo", pkgbuild)

    assert result["rule_families"]["eval"] is True
    assert result["rule_families"]["systemd_unit"] is True
    assert result["rule_families"]["systemd_auto"] is True
    assert result["rule_families"]["cron"] is True
    assert "EXEC-EVAL-001" in result["rule_counts"]
    assert "SYS-SYSTEMD-AUTO-001" in result["rule_counts"]
    assert "SYS-CRONTAB-001" in result["rule_counts"]


def test_summarize_reports_family_package_counts(tmp_path: Path):
    pkgbuild = aur_warning_tune.fetch_package_metadata("demo", tmp_path, fetcher=noisy_fetcher)
    result = aur_warning_tune.analyze_pkgbuild("demo", pkgbuild, warning_budget=1)

    summary = aur_warning_tune.summarize([result], warning_budget=1)

    assert summary["median_visible_groups"] >= 1
    assert summary["p95_visible_groups"] >= 1
    assert summary["visible_groups_by_package"]["demo"] == result["visible_group_count"]
    assert summary["packages_with_eval_warnings"] == ["demo"]
    assert summary["packages_with_systemd_unit_notes"] == ["demo"]
    assert summary["packages_with_systemd_auto_warnings"] == ["demo"]
    assert summary["packages_with_cron_warnings"] == ["demo"]
    assert summary["eval_finding_count"] == 1
    assert summary["systemd_unit_finding_count"] == 1
    assert summary["systemd_auto_finding_count"] == 1
    assert summary["cron_finding_count"] == 1
    assert summary["manual_review_count"] >= 1
    assert summary["hard_blocker_count"] == 0
    assert summary["source_metadata_finding_count"] >= 1
    assert summary["packages_over_warning_budget"] == ["demo"]
    assert summary["top_noisy_rule_ids"]
    assert summary["top_noisy_rule_families"]
    assert summary["rule_examples"]["SYS-SYSTEMD-AUTO-001"] == ["demo"]
    assert summary["suggested_tuning_notes"]


def test_run_uses_fake_fetcher_without_network(capsys):
    status = aur_warning_tune.run(["demo"], fetcher=fake_fetcher)
    output = capsys.readouterr().out

    assert status == 0
    assert "Packages scanned: 1" in output
    assert "SOURCE-META-HTTP-NOT-HTTPS" in output
    assert "Packages with eval warnings:" in output


def test_run_writes_json_and_markdown_reports_without_network(tmp_path: Path):
    json_path = tmp_path / "report.json"
    markdown_path = tmp_path / "report.md"

    status = aur_warning_tune.run(
        ["demo"],
        output_json_path=json_path,
        output_markdown_path=markdown_path,
        category_label="unit-test",
        include_hidden_notes=True,
        fetcher=fake_fetcher,
    )

    assert status == 0
    payload = json_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    assert '"median_visible_groups"' in payload
    assert '"rule_examples"' in payload
    assert "# AuraScan AUR Warning Tuning Report" in markdown
    assert "Category: `unit-test`" in markdown
    assert "| Package | Visible Groups | Hidden Notes | Visible Titles |" in markdown


def test_run_threshold_failures_return_nonzero_without_network():
    status = aur_warning_tune.run(
        ["demo"],
        fail_if_any_package_over_budget=0,
        fail_if_average_visible_warnings_above=0,
        fetcher=noisy_fetcher,
    )

    assert status == 2


def test_collect_packages_supports_option_file_and_limit(tmp_path: Path):
    sample_file = tmp_path / "packages.txt"
    sample_file.write_text("# comment\nfile-one\nfile-two\n", encoding="utf-8")

    packages = aur_warning_tune.collect_packages(
        ["positional"],
        option_packages=["from-option"],
        sample_file=sample_file,
        limit=3,
    )

    assert packages == ["positional", "from-option", "file-one"]
