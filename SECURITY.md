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

## Supported versions

| Version | Supported |
| :-- | :-- |
| `main` | Yes, best effort |
| Tagged releases | None exist yet |

Once releases exist, the latest minor release of each crate receives security fixes.

## Security model

These properties are the yardstick for a report. Breaking any of them is a vulnerability.

1. **The PIN is the root.** Every key hangs off a per-user TPM 2.0 root key that the PIN authorises. TPM anti-hammering limits PIN guessing.
2. **Biometrics are a shortcut, not the root.** Face or fingerprint only satisfies a TPM policy. A daemon flag or D-Bus call that unlocks keys without the TPM policy is a vulnerability.
3. **Keys sign, never leave.** Passkey private keys never leave the TPM or KeePassXC. The Secret Service stores tokens, never passkey private keys.
4. **Callers are verified.** Every caller of the Agent's D-Bus API is checked by peer credentials. A request for one relying party is never answered with another relying party's credential.
5. **Fail closed.** If the policy cannot be parsed, only the PIN is allowed. A daemon whose AppArmor profile is not loaded in enforce mode refuses to start. No fallback silently weakens authentication.
6. **Reset is destructive.** The account password authorises a reset only. A reset wipes the root key and every TPM-bound passkey, and never unlocks them ([ADR-0003](docs/adr/0003-destructive-reset.md)).

The full threat model and the list of security properties live in [`docs/security/`](docs/security/). Each property has a test named after it.

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
