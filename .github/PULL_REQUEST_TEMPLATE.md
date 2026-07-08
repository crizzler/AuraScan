## Summary

-

## Validation

- [ ] `python -m compileall aurascan tests tools`
- [ ] `.venv/bin/python -m pytest -q`
- [ ] `.venv/bin/python tools/audit_presenter_coverage.py --strict`
- [ ] `.venv/bin/python tools/audit_presenter_coverage.py --strict-medium`

## Safety Notes

- [ ] This change does not weaken hard blockers.
- [ ] This change does not silently send additional sensitive data to network AI.
- [ ] User-facing safety limits are documented when behavior changes.
