---
type: architecture
subject: "Arc42 section 7: deployment view of Linux Hello"
artifact: arc42-07-deployment-view
status: draft
owner: "@atterdag"
concepts: [deployment, arc42]
tags: [architecture, arc42, arc42-gap]
sources: ["README.md", "workspace.dsl", "https://docs.arc42.org/section-7/"]
date: 2026-11-05
---

# 7. Deployment view

Part of the [Arc42 architecture documentation](README.md).

**Gap.** [workspace.dsl](workspace.dsl) has no deployment view, and no note yet says how the containers are packaged and installed (systemd units, D-Bus service files, the PAM stack entry, AppArmor profiles, policy directories). When it is written, the C4 deployment view goes into `workspace.dsl` and this section names it ([ADR-0008](../adr/0008-code-documentation-mapped-to-c4.md)).

What exists today:

- The systemd sandboxing and AppArmor confinement each daemon runs under: [section 8, Security hardening](08-crosscutting-concepts.md#security-hardening).
- How releases are built and attested: [ADR-0006](../adr/0006-attested-quality-gates-and-releases.md).
