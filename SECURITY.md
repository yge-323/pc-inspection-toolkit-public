# Security and data protection

PC Inspection Toolkit is a Preview tool for systems and evidence that the operator is authorized to inspect. Collection workflows are designed to be read-only. The tool does not automatically remediate or elevate privileges. A Preview build is not a security certification and may miss issues.

## Evidence handling

- Treat evidence, analysis files, reports, screenshots, and logs as potentially sensitive.
- Keep source evidence and generated reports on the inspected computer or an owner-approved local destination. Do not commit real inspection data or attach it to public issues or AI services.
- Web-AI export is user initiated. Review the package and obtain permission for the specific data and destination before uploading it.
- Local Ollama analysis is experimental and opt-in. A local-provider selection is not an independent guarantee of model provenance or network isolation.
- AI output is advisory and must not replace evidence, deterministic findings, severity, or status.
- Never commit local profiles, credentials, certificates, model files, caches, generated reports, or execution logs.

## Reporting a security issue

Report security vulnerabilities through [GitHub private vulnerability reporting](https://github.com/yge-323/pc-inspection-toolkit-public/security/advisories/new). Do not post unpatched vulnerability details in public issues. If GitHub does not offer the private report form, do not disclose details publicly; no alternative private reporting channel has been verified.

Send only a minimal redacted reproduction. Do not include credentials, access data, real inspection evidence, or customer/host details.
