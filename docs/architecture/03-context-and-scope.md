---
type: architecture
subject: "Arc42 section 3: context and scope of Linux Hello"
artifact: arc42-03-context-and-scope
status: draft
owner: "@atterdag"
concepts: [c4, system-context, arc42]
tags: [architecture, arc42, c4]
sources: ["README.md", "workspace.dsl", "../adr/0008-code-documentation-mapped-to-c4.md", "https://docs.arc42.org/section-3/"]
date: 2026-11-05
---

# 3. Context and scope

Part of the [Arc42 architecture documentation](README.md). C4 diagrams live only in [workspace.dsl](workspace.dsl) ([ADR-0008](../adr/0008-code-documentation-mapped-to-c4.md)); this section names the views and does not redraw them.

## 3.1 Business context

C4 view: `systemContext linuxHello "Context"` in [workspace.dsl](workspace.dsl).

Linux Hello is the only software system modelled inside; everything it reuses is an external software system, shown only by how Linux Hello consumes it. The people are the desktop user and the administrator; the external systems are credentialsd, xdg-desktop-portal, KeePassXC, fprintd, Howdy, Linux-PAM, TPM 2.0, the camera via PipeWire, the Secret Service, the Plasma login manager, kscreenlocker, KDE System Settings, browsers, native and Electron apps, relying parties, AppArmor, Tetragon, systemd-journald, a log stack and future device management.

## 3.2 Technical context

**Gap.** The protocol and channel of each external relationship (D-Bus, PAM stack, `/dev/tpmrm0`, the KeePassXC browser protocol over a Unix socket, the PipeWire camera portal) is recorded as the technology of the relationships in [workspace.dsl](workspace.dsl), but not yet described here as a channel-to-interface mapping.
