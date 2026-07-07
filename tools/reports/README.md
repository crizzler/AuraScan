# Generated Tuning Reports

This directory is for opt-in metadata-only AUR warning tuning output.

Generated `.json` and `.md` reports are ignored by default so live samples do
not clutter the source tree unintentionally. Keep a report only when it is
small, useful for release notes, and clearly treated as illustrative rather than
authoritative.

The tuning helper must remain metadata-only. It fetches PKGBUILD and `.SRCINFO`
text only. It must not run makepkg, execute package code, install packages,
download declared sources, clone repositories, fetch PGP keys, or run GPG.
It must not download declared sources.
It must not run GPG.
