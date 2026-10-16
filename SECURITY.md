# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

If you believe you have found a security issue in Agent Security Contract (ASC), please report it privately by emailing the maintainer associated with this repository (GitHub user `justrunme`) or by using GitHub's private vulnerability reporting for this project.

Please include:

- a description of the issue and its impact
- reproduction steps (policy + trace fixtures when possible)
- whether the issue bypasses a fail-closed path (missing policy, digest mismatch, unknown tool, malformed trace)

Do not open a public issue for vulnerabilities that could weaken gate enforcement until a fix is available.

## Scope notes

ASC is a **static** policy evaluator for tool-call traces. It is not a runtime sandbox, network enforcer, or model-alignment system. Findings that require runtime isolation are outside the MVP threat model; see the README threat-model section.
