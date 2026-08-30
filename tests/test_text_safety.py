import pytest

from aurascan.core.text_safety import (
    advisory_text_or_fallback,
    validate_model_advisory_text,
)


@pytest.mark.parametrize(
    "text",
    [
        "The evidence indicates a possible integrity mismatch.",
        "A stale package database may explain the deterministic finding.",
        "The hook may execute downloaded content.",
        "The pacman preview reported a dependency conflict.",
        "The package manager reported a dependency conflict.",
        "A terminal invocation of pacman was present in the captured evidence.",
        "The observed operation invoked pacman during the failed transaction.",
        "Package-manager metadata indicates a dependency transition.",
        "Invocation evidence is incomplete.",
        "Credential access and outbound transfer behavior are correlated.",
        "Confidence is limited because inspection was incomplete.",
    ],
)
def test_model_advisory_text_accepts_declarative_interpretation(text):
    assert validate_model_advisory_text(text, max_chars=500, allow_empty=False) == text


@pytest.mark.parametrize(
    "text",
    [
        "You might download the update from the maintainer.",
        "The operator could try to run the helper.",
        "A prudent user may install the package.",
        "It would be prudent to install the helper.",
        "It could help to paste the diagnostic output.",
        "The user is encouraged to install the package.",
        "Feel free to open the downloaded file.",
        "It is okay to execute the installer.",
        "The next step is using the install helper.",
        "One option would be to execute the file.",
        "To fix this issue, install the helper.",
        "The workaround involves running the installer.",
        "Consider installing the package.",
        "Installation is recommended.",
        "Use pacman to resolve the issue.",
        "Use the package manager to install the helper.",
        "Inspect the bounded evidence before continuing.",
        "Review local state and proceed with the operation.",
        "Verify the archive before opening it.",
        "Consult the package manager documentation.",
        "Navigate to the provider page.",
        "The package manager can install the helper.",
        "Installing through the package manager resolves the issue.",
        "The next operation consists of invoking pacman Syu.",
        "A terminal invocation of pacman Syu resolves the issue.",
        "The operation consists of invoking the installer.",
        "The package can be installed with yay.",
        "pacman -S fixture may resolve it.",
        "Copy the API key into the form.",
        "Credentials can be shared with support.",
        "Sharing credentials is recommended.",
        "Supply the password to support.",
        "The terminal command is echo diagnostic-output.",
        "Details are at support.example.",
        "Details are at support[.]example.",
        "Details are at support dot example.",
        "Contact team@example.com.",
        "Connect to 192.0.2.1.",
        "Connect to [2001:db8::1].",
        "Check ｅｖｉｌ．ｅｘａｍｐｌｅ for details.",
        "Would a package reinstall help?",
    ],
)
def test_model_advisory_text_rejects_actionable_or_destination_bearing_prose(text):
    with pytest.raises(ValueError):
        validate_model_advisory_text(text, max_chars=500, allow_empty=False)


def test_model_advisory_text_normalizes_compatibility_unicode_before_returning():
    assert (
        validate_model_advisory_text("The ﬁnding overlaps local evidence.", max_chars=500)
        == "The finding overlaps local evidence."
    )


def test_rejected_model_prose_uses_fixed_fallback_without_retaining_input():
    unsafe = "You should share credentials with support.example."

    result = advisory_text_or_fallback(
        unsafe,
        max_chars=500,
        fallback="Model interpretation was rejected by the guarded advisory contract.",
    )

    assert result == "Model interpretation was rejected by the guarded advisory contract."
    assert "credentials" not in result
    assert "support.example" not in result
