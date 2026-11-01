---
type: adr
subject: Repository topology: one monorepo with split guardrails
artifact: adr
status: accepted
owner: "@atterdag"
concepts: [repository-topology, governance]
tags: [adr, one-way-door]
sources: ["../../GOVERNANCE.md"]
date: 2026-11-01
---

# ADR-0001: Monorepo with split guardrails

## Status

Accepted, 2026-11-01.

## Context

The containers (Agent, PAM module, TPM provider, KeePassXC bridge, Plasma integration, CLI) share the Agent's D-Bus API, the auth-state signals and the policy schema. Their boundaries are not yet validated: Milestone 0 spikes may move them. The security tests need all daemons running together.

## Decision

One repository, `LinuxHello/linux-hello`, as a Cargo workspace with one crate per container. Guardrails keep a later split mechanical: interface-only coupling, per-crate versions and tags, path-filtered CI, a `container:` label on every issue. A crate is split out when it gets its own maintainer, release cadence or distro packaging; reviewed before 1.0 at the latest.

## Consequences

Easier: atomic cross-container changes; one pipeline for property, AppArmor and Tetragon tests; boundaries can move after Milestone 0.

Harder: per-container ownership is weaker (CODEOWNERS per directory); the guardrails need discipline from day one; the split trigger must actually be reviewed.
