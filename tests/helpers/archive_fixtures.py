import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


@dataclass(frozen=True)
class TarEntry:
    name: str
    content: bytes = b""
    mode: int = 0o644
    kind: str = "file"
    linkname: str = ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_tar_archive(path: Path, entries: Iterable[TarEntry]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w") as archive:
        for entry in entries:
            info = tarfile.TarInfo(entry.name)
            info.mode = entry.mode
            info.linkname = entry.linkname
            if entry.kind == "dir":
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            elif entry.kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.size = 0
                archive.addfile(info)
            elif entry.kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(entry.content)
                archive.addfile(info, io.BytesIO(entry.content))
    return path


def write_deep_static_archive(path: Path, scenario: str) -> Path:
    entries = _scenario_entries(scenario)
    return write_tar_archive(path, entries)


def _scenario_entries(scenario: str) -> Iterable[TarEntry]:
    if scenario == "archive_path_traversal":
        return [
            TarEntry("safe/readme.txt", b"safe fixture content\n"),
            TarEntry("../evil.txt", b"defanged traversal fixture\n"),
        ]
    if scenario == "archive_absolute_path":
        return [
            TarEntry("safe/readme.txt", b"safe fixture content\n"),
            TarEntry("/tmp/aurascan-absolute-escape.txt", b"defanged absolute path fixture\n"),
        ]
    if scenario == "archive_symlink_escape":
        return [
            TarEntry("safe/readme.txt", b"safe fixture content\n"),
            TarEntry("safe/outside-link", kind="symlink", linkname="../../outside.txt"),
        ]
    if scenario == "archive_hardlink_escape":
        return [
            TarEntry("safe/readme.txt", b"safe fixture content\n"),
            TarEntry("safe/outside-hardlink", kind="hardlink", linkname="../../outside.txt"),
        ]
    if scenario == "archive_too_many_files":
        return [TarEntry(f"many/file-{index}.txt", b"x\n") for index in range(5)]
    if scenario == "archive_oversized":
        return [TarEntry("large/payload.txt", b"x" * 128)]
    if scenario == "archive_nested_depth":
        nested = _nested_tar_bytes()
        return [TarEntry("nested/inner.tar", nested)]
    if scenario == "source_setup_py":
        return [
            TarEntry(
                "pkg/setup.py",
                b"import subprocess\nsubprocess.run(['echo', 'defanged setup marker'])\n",
                0o644,
            )
        ]
    if scenario == "source_package_json":
        return [
            TarEntry(
                "pkg/package.json",
                b'{"scripts": {"postinstall": "node scripts/postinstall.js"}}\n',
            ),
            TarEntry("pkg/scripts/postinstall.js", b"console.log('defanged fixture');\n"),
        ]
    if scenario == "source_token_reference":
        return [
            TarEntry(
                "pkg/config.py",
                b"GITHUB_TOKEN = 'fixture-only-token-name'\nAPI_KEY = 'fixture-only-key-name'\n",
            )
        ]
    if scenario == "source_vendored_deps":
        return [
            TarEntry("pkg/vendor/example_dep.py", b"print('vendored fixture')\n"),
            TarEntry("pkg/src/main.py", b"print('main fixture')\n"),
        ]
    if scenario == "source_minified_file":
        minified = ("var a=1;" * 180).encode("ascii") + b"\n"
        return [TarEntry("pkg/dist/app.min.js", minified)]
    if scenario == "deep_static_systemd_unit_file":
        return [
            TarEntry(
                "pkg/fixture.service",
                b"[Unit]\nDescription=AuraScan fixture\n[Service]\nExecStart=/usr/bin/fixture\n",
            )
        ]
    if scenario == "deep_static_systemd_auto_enable":
        return [TarEntry("pkg/script.sh", b"systemctl enable fixture.service\n")]
    if scenario == "deep_static_systemd_user_persistence":
        return [
            TarEntry(
                "pkg/script.sh",
                b"install -Dm644 fixture.service \"$HOME/.config/systemd/user/fixture.service\"\n",
            )
        ]
    if scenario == "systemd_docs_no_warning":
        return [TarEntry("pkg/script.sh", b"# Documentation: systemctl enable fixture.service\n")]
    if scenario == "cron_docs_no_warning":
        return [TarEntry("pkg/script.sh", b"# Documentation: @reboot curl https://example.invalid/fixture\n")]
    if scenario in {
        "pgp_valid_signature",
        "pgp_invalid_signature",
        "pgp_signer_mismatch",
        "pgp_key_unavailable",
        "pgp_weak_validpgpkeys",
    }:
        return [TarEntry("pkg/readme.txt", b"harmless signed source fixture\n")]
    raise ValueError(f"unknown deep-static archive scenario: {scenario}")


def _nested_tar_bytes() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("inner/readme.txt")
        payload = b"nested archive fixture\n"
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def write_signature_fixture(path: Path, marker: Optional[str] = None) -> Path:
    path.write_text(marker or "fixture detached signature\n", encoding="utf-8")
    return path


def write_public_key_fixture(path: Path, fingerprint: str) -> Path:
    path.write_text(
        "\n".join([
            "-----BEGIN PGP PUBLIC KEY BLOCK-----",
            f"Comment: AuraScan test fixture key {fingerprint}",
            "ZmFrZS1wdWJsaWMta2V5LWZpeHR1cmU=",
            "-----END PGP PUBLIC KEY BLOCK-----",
            "",
        ]),
        encoding="utf-8",
    )
    return path
