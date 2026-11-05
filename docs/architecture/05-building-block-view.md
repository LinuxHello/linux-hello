---
type: architecture
subject: "Arc42 section 5: building block view of Linux Hello (containers and components in the C4 workspace)"
artifact: arc42-05-building-block-view
status: active
owner: "@atterdag"
concepts: [c4, containers, components, arc42]
tags: [architecture, arc42, c4]
sources: ["README.md", "workspace.dsl", "../adr/0008-code-documentation-mapped-to-c4.md", "https://docs.arc42.org/section-5/"]
date: 2026-11-05
---

# 5. Building block view

Part of the [Arc42 architecture documentation](README.md). C4 diagrams live only in [workspace.dsl](workspace.dsl) ([ADR-0008](../adr/0008-code-documentation-mapped-to-c4.md)); this section names the views and does not redraw them. The code names the container or component it implements, and CI checks it against the workspace.

Levels: System Context ([section 3](03-context-and-scope.md)), Container, and one Component view per container. Code level deferred until a Rust skeleton exists. DSL **untested**: validate with the Structurizr CLI before committing.

## 5.1 Level 1: containers

C4 view: `container linuxHello "Containers"` in [workspace.dsl](workspace.dsl).

| Container | Technology | Responsibility |
| :-- | :-- | :-- |
| Linux Hello Agent | Rust daemon, D-Bus (session) | Unlock state, auth state, routing policy, PIN, enrolment and reset orchestration |
| PAM module `pam_linuxhello` | Rust `cdylib` | Runs face, fingerprint and PIN in parallel; PIN verified against the TPM root key; reports state to the Agent |
| TPM Credential Provider | Rust daemon; attachment to credentialsd per ADR-0005 (no provider API at v0.3.1) | Creates and uses device-bound passkeys under the per-user TPM root key |
| KeePassXC Provider Bridge | Rust daemon; attachment to credentialsd per ADR-0005 (no provider API at v0.3.1) | Serves portable passkeys from KeePassXC over its browser protocol |
| Plasma Integration | Rust/cxx-qt, QML, KCM | Prompts, greeter and lock-screen integration, enrolment, PIN and settings |
| `linuxhello-ctl` | Rust CLI | Enrol, change PIN, reset trust chain (ADR-0003), inspect policy |
| User Policy | TOML (`~/.config/linuxhello/policy.toml`) | User layer of the policy |
| Admin Policy | TOML (`/etc/linuxhello/policy.d/*.toml`) | Admin layer; locked keys win |
| Security Profiles | AppArmor, Tetragon, alert rules | Confinement and detection shipped with Linux Hello |

Where each container lives in the repository: the path table in [AGENTS.md](../../AGENTS.md#what-this-is).

## 5.2 Level 2: components

One C4 component view per container in [workspace.dsl](workspace.dsl):

| View | Container id |
| :-- | :-- |
| `Agent` | `agent` |
| `PAM` | `pamModule` |
| `TPMProvider` | `tpmProvider` |
| `KeePassXCBridge` | `kpxcBridge` |
| `Plasma` | `plasma` |
| `CLI` | `cli` |
| `SecurityProfiles` | `secProfiles` |

The components that the user-experience design adds are listed in [section 8, Additions to the C4 model](08-crosscutting-concepts.md#additions-to-the-c4-model).

## 5.3 Level 3: code

Code level (class diagrams): deferred until the Rust skeleton exists; first candidates are the Routing Policy Engine and the TPM Key Service. Until then every item carries a doc comment ([ADR-0008](../adr/0008-code-documentation-mapped-to-c4.md)).
