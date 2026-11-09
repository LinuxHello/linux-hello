---
type: architecture
subject: Semantics of the Linux Hello routing policy (schema, defaults, layering, fail-closed loading, queries)
artifact: policy-semantics
status: draft
owner: "@atterdag"
concepts: [policy, fail-closed, routing-policy]
tags: [architecture, policy]
sources: ["https://github.com/LinuxHello/architecture/blob/main/arc42/08-crosscutting-concepts.md", "../../policy/policy.example.toml"]
date: 2026-11-01
---

# Policy semantics

This note makes the [Policy concept in Arc42 section 8](https://github.com/LinuxHello/architecture/blob/main/arc42/08-crosscutting-concepts.md#policy) precise enough to implement and test. The Routing Policy Engine lives in the Agent (`crates/linuxhello-agent`, module `policy`). Every rule below has a security property and a named test in [docs/security/](../security/README.md).

## Schema

A policy file is TOML. Every table and key is optional. Any key, table or value not listed here makes the whole file **unparseable** (strict parsing, no unknown keys).

| Table | Key | Type and range |
| :-- | :-- | :-- |
| `[pin]` | `min_length` | integer, 4–64 |
| | `max_length` | integer, 4–127, and ≥ `min_length` after merging |
| | `digits`, `lowercase`, `uppercase`, `special` | `"required"`, `"allowed"` or `"disallowed"` |
| | `history` | integer, 0–50 (0: no history) |
| | `expiry_days` | integer, 1–730 (absent: never expires) |
| | `lockout_attempts` | integer, 1–32 |
| | `lockout_minutes` | integer, 1–1440 |
| `[methods]` | `biometrics_allowed`, `face_requires_ir`, `require_hardware_tpm` | boolean |
| `[context.<name>]` | `<name>` | one of `login`, `unlock`, `sudo`, `session` |
| | `methods` | non-empty array of `"pin"`, `"fingerprint"`, `"face"`, no duplicates |
| | `factors` | integer, 1–2 |
| | `reverify_after` | duration string: integer followed by `s`, `m`, `h` or `d`; 1 s to 30 d |
| `[rp_class.<name>]` | `<name>` | 1–64 characters, `[a-z0-9_-]` |
| | `match` | non-empty array of relying-party patterns (below) |
| | `provider` | `"tpm"`, `"keepassxc"` or `"any"` |
| | `prompt` | `"none"`, `"presence"` or `"reverify"` |
| | `factors` | integer, 1–2 |
| | `require_second_credential` | boolean |

A relying-party pattern is either an exact domain (`bank.example`) or `*.` followed by a domain (`*.bank.example`), which matches every subdomain but not the domain itself. Domains are compared in lower case, without a trailing dot. Any other pattern, including `*` alone, a `*` anywhere else, or an empty label, makes the file unparseable.

## Built-in defaults

| Setting | Default |
| :-- | :-- |
| PIN | `min_length` 6, `max_length` 127, `digits` required, other classes allowed, `history` 0, no expiry, `lockout_attempts` 5, `lockout_minutes` 15 |
| Methods | `biometrics_allowed` true, `face_requires_ir` true, `require_hardware_tpm` true |
| Every context | `methods` = pin, fingerprint, face; `factors` 1; no `reverify_after` |
| Relying parties | no classes; decision defaults are provider `any`, prompt `presence`, factors 1, no second credential. These apply to unmatched relying parties and to decision fields still absent after merging explicit settings from the selected matching classes, including specificity ties |

## Restrictiveness

Merging uses "most restrictive" per key:

| Key | More restrictive is |
| :-- | :-- |
| `min_length`, `history`, `lockout_minutes`, `factors` | larger |
| `max_length`, `expiry_days`, `lockout_attempts`, `reverify_after` | smaller (an absent `expiry_days` or `reverify_after` is the least restrictive) |
| character classes | `required` and `disallowed` both beat `allowed`; `required` against `disallowed` is a **conflict** |
| `biometrics_allowed` | false |
| `face_requires_ir`, `require_hardware_tpm`, `require_second_credential` | true |
| `methods` | the intersection |
| `provider` | `tpm`, then `keepassxc`, then `any` |
| `prompt` | `reverify`, then `presence`, then `none` |
| `match` (same class name in several files) | the union |

## Layering

1. Merge all admin files (`/etc/linuxhello/policy.d/*.toml`, in name order) into one admin layer, most restrictive per key.
2. For each key: if the admin layer sets it, the admin value is effective and the key is **managed**. Otherwise the effective value is the most restrictive of the default and the user value (the user's layer, kept by the Agent in `/var/lib/linuxhello/users/<uid>/policy.toml` and set over D-Bus, [ADR-0018](https://github.com/LinuxHello/architecture/blob/main/adr/0018-user-policy-layer.md)). The user can tighten the defaults, never loosen them; only an admin can loosen a default.
3. Then apply the invariants below.

The Agent stores a user layer only if it parses with this schema and is at most 64 KiB, so the stored file is loadable; a stored file that is later damaged still fails closed (*Fail closed*). A user reads and sets only their own layer, and there is no home-directory file: nothing is read from `~/.config/linuxhello/`.

## Invariants after merging

- **PIN is always allowed.** `pin` is added to every context's `methods` (invariant 1: the PIN is the root).
- **Biometrics off means PIN only.** If `biometrics_allowed` is false, `fingerprint` and `face` are removed from every context.
- **Two factors need two methods.** A context with `factors` 2 and only `pin` left keeps `factors` 2 and is unsatisfiable until a biometric method is enrolled; the engine reports it, it does not lower the factor count.

## Fail closed

The engine enters the **PIN-only state** when any of these hold:

- a policy file exists but cannot be read, is not a regular file (a symbolic link included), is larger than 1 MiB, is not valid UTF-8, does not parse, or breaks the schema, or an existing admin policy directory cannot be enumerated;
- the admin directory, its parent or the user's file cannot be examined for any reason other than not existing;
- an admin file, the admin directory or its parent is not owned by root, or is writable by group or others;
- the merged result is contradictory (`max_length` < `min_length`, `required` against `disallowed`, or all four PIN character classes are `disallowed`).

In the PIN-only state every context allows only `pin` with `factors` 1, PIN rules are the built-in defaults, relying parties get provider `tpm` and prompt `reverify`, and the engine reports why. A missing file is not an error: it contributes nothing. Only "does not exist" counts as missing; a path that cannot be examined is a failure.

## Queries

| Query | Answer |
| :-- | :-- |
| `methods_for(context)` | methods, factors, `reverify_after` |
| `decision_for(rp_id)` | provider, prompt, factors, `require_second_credential`; from the most specific matching class (exact domain beats `*.`, longer suffix beats shorter); ties merge most restrictive |
| `pin_rules()` | the PIN settings |
| `effective()` | every effective value with its `managed` flag, and the PIN-only reason if any |

## Open points

- The defaults and ranges above are proposals for the maintainer to confirm before implementation starts.
- The user layer only tightens. This differs from a plain "later layer wins" reading of the target architecture, which allowed the user to set any value an admin has not locked.
