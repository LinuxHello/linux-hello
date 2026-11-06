# Security policy

Linux Hello decides who gets into a machine and who may use its passkeys. We treat every weakness as serious, including ones that only weaken a defence in depth.

> **Status: pre-alpha.** Nothing in this repository authenticates anyone yet. Do not use it to protect real accounts. No release has had an external security audit, and none will be called stable before one has.

## Reporting a vulnerability

Report privately through GitHub's **private vulnerability reporting**: open the [Security tab](https://github.com/LinuxHello/linux-hello/security), then **Report a vulnerability**.

Do not open a public issue, pull request or discussion, and do not post details anywhere public before a fix is out.

Please include:

- the affected component (crate, profile, policy or document) and the commit or version;
- what an attacker needs: local user, other local user, same session, physical access, root;
- reproduction steps or a proof of concept;
- the impact, measured against the [security model](#security-model) below.

A partial report is welcome. Send what you have.

## What happens next

| Step | Target |
| :-- | :-- |
| Acknowledgement | within 7 days |
| First assessment (accepted, needs info, or out of scope, with reasons) | within 14 days |
| Fix or mitigation published | within 90 days of the report |
| Public advisory | once a fix is out, or at 90 days, whichever comes first |

The project has a single maintainer. These are targets, not guarantees. If one slips, we tell you why and agree a new date with you.

- We coordinate disclosure with you and credit you in the advisory, unless you ask us not to.
- Advisories and CVE IDs are issued through [GitHub Security Advisories](https://github.com/LinuxHello/linux-hello/security/advisories).
- If the root cause is in an upstream component, we report it to that project, and the embargo follows their process as well as ours.
- There is no bug bounty.

## Verifying a release

Every release file is built by this repository's release workflow from a tagged commit on `main` that passed the quality gate. Each file carries Sigstore-signed attestations ([ADR-0006](https://github.com/LinuxHello/architecture/blob/main/adr/0006-attested-quality-gates-and-releases.md)). Verify a file before you use it (GitHub CLI 2.49 or later):

```sh
# Provenance: built by release.yml from this tag on a GitHub-hosted runner
gh attestation verify <file> --repo LinuxHello/linux-hello \
  --signer-workflow LinuxHello/linux-hello/.github/workflows/release.yml \
  --source-ref refs/tags/<tag> --deny-self-hosted-runners

# SBOM: the attested dependency list for a binary or the source archive
gh attestation verify <file> --repo LinuxHello/linux-hello \
  --signer-workflow LinuxHello/linux-hello/.github/workflows/release.yml \
  --predicate-type https://cyclonedx.org/bom
```

`<tag>.cdx.json` in the release is the CycloneDX SBOM, and `SHA256SUMS` lists every file's digest. A file that fails verification did not come from this project: do not use it, and report it as a vulnerability.

## Supported versions

| Version | Supported |
| :-- | :-- |
| `main` | Yes, best effort |
| Tagged releases | None exist yet |

Once releases exist, the latest minor release of each crate receives security fixes.

## Security model

These properties are the yardstick for a report. Breaking any of them is a vulnerability.

1. **The PIN is the root.** Every TPM-bound passkey hangs off a per-user TPM 2.0 root key that the PIN authorises. TPM anti-hammering limits PIN guessing. One user's failed attempts must not lock out another user (P-12, P-14, P-16).
2. **Biometrics are a shortcut, not the root.** Face or fingerprint only satisfies a TPM policy. A daemon flag or D-Bus call that unlocks keys without the TPM policy is a vulnerability. An unlock ends after its configured duration and when the session locks (P-06, P-07, P-15).
3. **Keys sign, never leave.** Passkey private keys never leave the TPM or KeePassXC. The Secret Service stores tokens, never passkey private keys. A signature needs a user-presence confirmation, and the PIN and key material never reach a log (P-08, P-09, P-10, P-11, P-13).
4. **Callers are verified.** Every caller of the Agent's D-Bus API is checked by peer credentials. A request for one relying party is never answered with another relying party's credential. Method state is never broadcast to other users (P-01, P-02, P-03, P-04, P-05).
5. **Fail closed.** If the policy cannot be parsed, only the PIN is allowed. A daemon whose AppArmor profile is not loaded in enforce mode refuses to start. The PAM module never reports success when the Agent is unreachable. No fallback silently weakens authentication (the routing-policy properties, P-20, P-21, P-24).
6. **Reset is destructive.** The account password authorises a reset only. A reset wipes the root key and every TPM-bound passkey, and never unlocks them ([ADR-0003](https://github.com/LinuxHello/architecture/blob/main/adr/0003-destructive-reset.md)) (P-17, P-18, P-19).
7. **Evidence and confinement.** Every unlock, signature, PIN change and reset is audited. Only the Agent and the TPM provider open the TPM device, no Linux Hello process opens an internet socket, and nothing may trace the daemons (P-25, P-26, P-27).

The ids in brackets are properties in [`docs/security/properties.md`](docs/security/properties.md), each with a test named after it; the reasoning is in the [threat model](docs/security/threat-model.md). Both are drafts: the tests are `#[ignore]`d placeholders until the code exists, and the threat model lists the questions the design has not settled. Use the security model above when describing a report's impact.

## Scope

**In scope:** everything in this repository:

- the Agent, `pam_linuxhello`, the TPM credential provider, the KeePassXC provider bridge, `linuxhello-ctl` and the Plasma integration;
- AppArmor profiles, Tetragon policies and alert rules in `security/`;
- the policy schema and the default and example policies in `policy/`;
- the CI configuration and supply chain: dependencies, `cargo-deny` rules, GitHub Actions workflows;
- documentation that would lead a user or administrator into an insecure configuration.

**Upstream components:** report vulnerabilities in credentialsd, libwebauthn, Howdy, fprintd, KeePassXC, xdg-desktop-portal, KDE Plasma, tpm2-tss or the kernel TPM stack to that project. Tell us as well if Linux Hello is affected or could mitigate it.

**Out of scope:**

- attacks that need root or a kernel compromise on the target machine, unless Linux Hello claims to resist them;
- a biometric false match that stays within the sensor's or Howdy's documented error rate (a bypass of IR anti-spoofing is in scope);
- denial of service by a user against their own session;
- reports from automated scanners with no demonstrated impact.

## Safe harbour

We will not take legal action against research done in good faith, on systems you own or are authorised to test, that follows this policy. Stop and contact us if you reach data that is not yours.
