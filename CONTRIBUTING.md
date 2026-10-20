# Contributing

This project is licensed under Apache-2.0. Contributions intentionally submitted for inclusion are subject to section 5 of [LICENSE](LICENSE), unless they are explicitly marked “Not a Contribution” or covered by a separate written agreement. Submit only work you created or are authorized to contribute; the project's license selection does not grant rights to third-party material you do not control.

## Safe contribution basics

- Use synthetic fixtures. Do not commit real inspection evidence, generated reports, logs, local profiles, model files, credentials, certificates, or machine-specific configuration.
- Preserve the separation between deterministic facts/findings and AI advisory output. Do not relax evidence, hash, reference, or failure validation to make an example pass.
- Keep collection read-only. Do not add automatic remediation, privilege elevation, or unapproved target access.
- Make focused changes and describe scope, user-visible effect, validation performed, and remaining limits.

## Local checks

Use Python 3.10 or later with Tkinter for Windows source GUI development. The default offline suite is:

```powershell
python -B tests\run_unit_tests.py
```

For build-script changes, also run its contract tests:

```powershell
python -B tests\test_restart_build.py
```

Tests should use synthetic fixtures and must not require real evidence, external network access, or an AI request. Source tests alone do not establish clean-Windows, administrator, or broad cross-platform acceptance.

## Review notes

Describe synthetic and machine-derived inputs clearly. Report `PARTIAL` and `FAILED` accurately; neither is a pass. Never upload evidence or logs to an issue without the data owner's explicit approval.
