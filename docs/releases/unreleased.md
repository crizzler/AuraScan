# AuraScan Unreleased

Changes after v0.16.1:

- Recovery image validation now fails closed when `ukify` is unavailable
  instead of silently accepting a weaker check (R8). This requires a
  recovery-bearing release with a fresh ISO and UKI gates before publication.
