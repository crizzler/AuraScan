import io
import json
import os
from datetime import date
from pathlib import Path

from aurascan.core.recovery_boot import iso_manifest_status, load_iso_manifest
from aurascan.core.recovery_cli import _print_status


def manifest(
    *,
    application_version="0.10.3",
    image_version="0.10.3",
    disposition="recovery-bearing",
    status="release-ready",
):
    filename = f"aurascan-recovery-{image_version}-x86_64.iso"
    ready = status == "release-ready"
    return {
        "schema": "aurascan_recovery_iso/2.0",
        "application_version": application_version,
        "release_disposition": disposition,
        "version": image_version,
        "architecture": "x86_64",
        "filename": filename,
        "released_at": "2026-09-01",
        "url": (
            f"https://github.com/crizzler/AuraScan/releases/download/v{image_version}/{filename}"
            if ready
            else ""
        ),
        "sha256": "a" * 64 if ready else "",
        "status": status,
    }


def write_manifest(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_release_ready_recovery_manifest_is_exact_and_downloadable(tmp_path):
    path = tmp_path / "iso.json"
    write_manifest(path, manifest())

    state = load_iso_manifest(path, expected_application_version="0.10.3")

    assert state["valid"] is True
    assert state["ready"] is True
    assert state["release_disposition"] == "recovery-bearing"
    assert "pins its validated Recovery ISO" in state["message"]


def test_build_required_manifest_is_valid_but_not_downloadable(tmp_path):
    path = tmp_path / "iso.json"
    write_manifest(path, manifest(status="build-required"))

    state = load_iso_manifest(path, expected_application_version="0.10.3-dev")

    assert state["valid"] is True
    assert state["ready"] is False
    assert state["status"] == "build-required"
    assert "built, validated, and pinned" in state["message"]


def test_package_only_manifest_names_the_retained_recovery_image():
    state = iso_manifest_status(
        manifest(
            application_version="0.10.4",
            image_version="0.10.3",
            disposition="package-only",
        ),
        expected_application_version="0.10.4",
    )

    assert state["valid"] is True
    assert state["ready"] is True
    assert "intentionally retains Recovery ISO 0.10.3" in state["message"]


def test_package_only_manifest_rejects_same_or_future_image_version():
    same = iso_manifest_status(
        manifest(disposition="package-only"),
        expected_application_version="0.10.3",
    )
    future = iso_manifest_status(
        manifest(
            application_version="0.10.3",
            image_version="0.10.4",
            disposition="package-only",
        ),
        expected_application_version="0.10.3",
    )

    assert same["valid"] is False
    assert future["valid"] is False
    assert "earlier Recovery ISO version" in same["message"]


def test_retained_image_age_is_exposed_without_disabling_verified_downloads():
    at_boundary = iso_manifest_status(
        manifest(
            application_version="0.10.4",
            image_version="0.10.3",
            disposition="package-only",
        ),
        expected_application_version="0.10.4",
        today=date(2026, 11, 30),
    )
    state = iso_manifest_status(
        manifest(
            application_version="0.10.4",
            image_version="0.10.3",
            disposition="package-only",
        ),
        expected_application_version="0.10.4",
        today=date(2026, 12, 1),
    )

    assert at_boundary["age_days"] == 90
    assert at_boundary["stale"] is False
    assert state["valid"] is True
    assert state["ready"] is True
    assert state["stale"] is True
    assert state["age_days"] == 91
    assert "exceeds AuraScan's 90-day refresh window" in state["message"]


def test_manifest_accepts_one_day_of_utc_clock_skew_without_negative_age():
    candidate = manifest()
    candidate["released_at"] = "2026-09-02"

    state = iso_manifest_status(candidate, today=date(2026, 9, 1))

    assert state["valid"] is True
    assert state["ready"] is True
    assert state["age_days"] == 0
    assert state["stale"] is False
    assert "clock-skew tolerance" in state["message"]


def test_manifest_rejects_a_materially_future_release_date():
    candidate = manifest()
    candidate["released_at"] = "2026-09-03"

    state = iso_manifest_status(candidate, today=date(2026, 9, 1))

    assert state["valid"] is False
    assert state["ready"] is False
    assert "clock-skew tolerance" in state["message"]


def test_manifest_release_date_has_one_cross_version_iso_shape():
    for alternate in ("20260901", "2026-W36-2", "2026-9-01", "2026-09-1"):
        candidate = manifest()
        candidate["released_at"] = alternate

        state = iso_manifest_status(candidate, today=date(2026, 9, 1))

        assert state["valid"] is False, alternate
        assert state["ready"] is False, alternate
        assert "release date is invalid" in state["message"], alternate


def test_manifest_rejects_version_filename_url_digest_and_disposition_mismatches():
    mutations = (
        {"application_version": "0.10.2"},
        {"application_version": f"{'9' * 7000}.10.3"},
        {"architecture": "aarch64"},
        {"filename": "recovery.iso"},
        {"url": "https://example.invalid/recovery.iso"},
        {"sha256": "A" * 64},
        {"release_disposition": "implicit"},
        {"released_at": "not-a-date"},
        {"status": "draft"},
    )

    for mutation in mutations:
        candidate = manifest()
        candidate.update(mutation)
        state = iso_manifest_status(candidate, expected_application_version="0.10.3")
        assert state["valid"] is False, mutation
        assert state["ready"] is False, mutation


def test_manifest_rejects_unknown_missing_duplicate_and_symlinked_input(tmp_path):
    candidate = manifest()
    candidate["extra"] = "not-schema-2.0"
    assert iso_manifest_status(candidate)["valid"] is False

    candidate = manifest()
    del candidate["filename"]
    assert iso_manifest_status(candidate)["valid"] is False

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema":"aurascan_recovery_iso/2.0","schema":"aurascan_recovery_iso/2.0"}',
        encoding="utf-8",
    )
    assert load_iso_manifest(duplicate)["valid"] is False

    target = tmp_path / "target.json"
    write_manifest(target, manifest())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    assert load_iso_manifest(link)["valid"] is False


def test_legacy_schema_is_rejected_and_derived_status_is_memory_only(tmp_path):
    legacy = {
        "schema": "aurascan_recovery_iso/1.0",
        "version": "0.6.0",
        "architecture": "x86_64",
        "url": "https://github.com/crizzler/AuraScan/releases/download/v0.6.0/aurascan-recovery-0.6.0-x86_64.iso",
        "sha256": "a" * 64,
        "status": "release-ready",
    }
    legacy_path = tmp_path / "legacy.json"
    write_manifest(legacy_path, legacy)

    legacy_state = load_iso_manifest(legacy_path)
    in_memory_state = iso_manifest_status(manifest(), today=date(2026, 9, 1))
    persisted_status = tmp_path / "persisted-status.json"
    write_manifest(persisted_status, in_memory_state)

    assert legacy_state["valid"] is False
    assert legacy_state["message"] == "Recovery ISO manifest schema is unsupported."
    assert iso_manifest_status(in_memory_state, today=date(2026, 9, 1))["ready"] is True
    disk_state = load_iso_manifest(persisted_status)
    assert disk_state["valid"] is False
    assert "fields do not match schema 2.0" in disk_state["message"]


def test_manifest_rejects_oversized_invalid_encoding_and_nonregular_input(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (64 * 1024) + b"}")
    invalid_encoding = tmp_path / "invalid.json"
    invalid_encoding.write_bytes(b"\xff\xfe")
    directory = tmp_path / "manifest-directory"
    directory.mkdir()
    fifo = tmp_path / "manifest-fifo"
    os.mkfifo(fifo)

    for candidate in (oversized, invalid_encoding, directory, fifo):
        state = load_iso_manifest(candidate)
        assert state["valid"] is False
        assert state["ready"] is False


def test_status_output_discloses_recovery_release_disposition():
    output = io.StringIO()
    _print_status(
        {
            "policy": {"enabled": False},
            "image": {"installed": False, "bootloader": {}},
            "profile_installed": True,
            "refresh_hook_installed": True,
            "iso_manifest": iso_manifest_status(
                manifest(
                    application_version="0.10.4",
                    image_version="0.10.3",
                    disposition="package-only",
                )
            ),
        },
        output,
    )

    text = output.getvalue()
    assert "Release recovery: package-only | application: 0.10.4 | ISO: 0.10.3 (ready)" in text
    assert "intentionally retains Recovery ISO 0.10.3" in text
