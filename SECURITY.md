# Security Policy

## Supported Versions

This project is pre-1.0. Security fixes target the latest commit on `main`.

## Reporting

Do not open public issues that include API keys, webhook secrets, incident data, customer names, or other sensitive details.

Use GitHub private vulnerability reporting if enabled for this repository. If it is not enabled, contact the maintainer through the GitHub profile for a private reporting path.

## Secret Handling

- Do not paste PhishFort API keys into prompts, issue comments, logs, or commits.
- Prefer `PHISHFORT_API_KEY_FILE` over `PHISHFORT_API_KEY`.
- Webhook secrets returned by PhishFort are one-time values. This server writes them to a local `0600` file and returns only the filename and checksum prefix.

## Scope

This is an unofficial local MCP server. It is not affiliated with PhishFort. Reports about the PhishFort API itself should be sent to PhishFort through their official channels.
