# Possible upstream contributions to OWASP projects

Concrete, scoped ideas where Agent Security Contract (ASC) work could feed back into OWASP GenAI / Agentic Security deliverables. Each item links to the living upstream surface.

## 1. ACS Instrument: CI fixture for `toolCallRequest` dispositions

Propose a small, language-neutral fixture pack that exercises Guardian decisions on `toolCallRequest` (ALLOW / DENY / ASK) using static traces — complementary to the ACS reference Guardian.

- Spec hooks: [Supported Hooks](https://genai-security-project.github.io/agent-control-standard/docs/spec/instrument/hooks/)
- Spec root: [Agent Control Standard](https://github.com/GenAI-Security-Project/agent-control-standard)
- OWASP landing: [ACS resource (2026-09-01)](https://genai.owasp.org/resource/agent-control-standard-acs/)

## 2. ACS Trace / evidence envelope crosswalk

Contribute a documented mapping from ACS audit-chain fields to a minimal CI evidence envelope (`schema_version`, policy digest, verdict, `trace_id`, commit, timestamp) so regression gates can store portable proofs.

- Instrument specification: [ACS specification](https://genai-security-project.github.io/agent-control-standard/docs/spec/instrument/specification/)
- Conformance profiles: [ACS Conformance](https://genai-security-project.github.io/agent-control-standard/docs/spec/conformance/)

## 3. Agentic Top 10: executable “control-gate” examples

Add short, runnable examples under each relevant Agentic Top 10 risk showing a **pre-execution deny** (not only a detection finding), with expected disposition tables.

- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) (download resource)
- Initiative: [Agentic Security Initiative](https://genai.owasp.org/initiatives/agentic-security-initiative/)

## 4. MCP cheat sheets: capability-digest pinning pattern

Upstream a short pattern for pinning MCP tool description/schema digests and failing closed on catalog drift (tool poisoning), with a sample policy + negative test.

- [CheatSheet — Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers/)
- [Practical Guide for Secure MCP Server Development v1.0](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/)

## 5. Agent Security Regression Harness: enforcement-gate profile

Propose an optional harness profile that treats a fail-closed policy gate as a first-class oracle (critical false-ALLOW = hard fail; benign false-BLOCK reported), distinct from prompt-level attack success metrics.

- Track upstream harness discussions via the Agentic Security Initiative hub: [ASI](https://genai.owasp.org/initiatives/agentic-security-initiative/)
- Related navigator context: [Agentic Threats Navigator](https://genai.owasp.org/resource/owasp-gen-ai-security-project-agentic-threats-navigator/)

## Contribution hygiene

- Prefer small patches with fixtures and tests over narrative-only PRs.
- Cite ACS hook names and Agentic risk IDs explicitly.
- Keep claims scoped to the contributed corpus (“on this corpus of N scenarios”).
