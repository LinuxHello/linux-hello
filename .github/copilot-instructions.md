# Copilot instructions

Follow [AGENTS.md](../AGENTS.md) at the repository root. It is the single source of rules for every coding agent in this repository and takes precedence over anything here.

The rules most relevant to completions and chat:

- No `unsafe` outside the TPM FFI and PAM entry-point modules.
- Never weaken a gate, lint or test to get green.
- Every security behaviour has a test whose name states the property.
- Never write secrets, personal data or details of anyone's machine into the repository.
- Commit trailer for substantial Copilot output: `Assisted-by: GitHub Copilot`.
