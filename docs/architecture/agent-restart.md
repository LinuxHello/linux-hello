# What a client does when the Agent restarts

The Agent keeps its prompts and subscriptions in memory, so a restart (a crash, an update, `systemctl restart`) loses all of them. The state API does not try to hide that ([ADR-0014](https://github.com/LinuxHello/linux-hello-architecture/blob/main/adr/0014-agent-bus.md)); every client follows the same rule, and `linuxhello_dbus::restart` applies it.

## The rule

A client watches `NameOwnerChanged` for `io.github.LinuxHello.Agent1`.

| Signal | What it means | What the client does |
| :-- | :-- | :-- |
| The name loses its owner | The Agent stopped; its prompts are gone | Nothing yet. Remember that the name is lost |
| The name gets an owner after it was lost, or changes owner without a gap | The Agent restarted | The opener of a prompt calls `OpenPrompt` again with the same prompt id and subject, then `Subscribe` if it had subscribed. A client that only follows a prompt calls `Subscribe` |
| The name gets an owner and was never lost | The Agent started before or with the client | Nothing: the client opens its prompt as it would anyway |

A prompt that has ended is not reopened. A `Closed` signal, or the client closing the prompt itself, ends it.

## Order and retries

The opener reopens first. A follower that subscribes before the prompt is back is refused (`AccessDenied`, the same answer as for a prompt that never existed), so it retries after 250 ms, doubling up to five seconds, until the subscription is accepted or the client gives up (`retry_delay`).

## What does not survive

Nothing of the state: the methods, the active method and the result of the prompt are reported again by the opener once it has reopened the prompt. The PIN lockout counter is not part of this state; it is kept in a file (P-29) and survives a restart.

## Where this is tested

`a_restart_of_the_agent_is_followed_by_a_reopen`, `a_subscriber_only_resubscribes`, `the_first_appearance_of_the_agent_is_not_a_restart`, `another_name_is_ignored`, `a_prompt_that_ended_is_not_reopened` and `retry_delay_grows_and_stops_at_five_seconds`, in `crates/linuxhello-dbus/src/restart.rs`. The rule is a state machine with no bus connection of its own; a client wires `NameOwnerChanged` and the calls to it.
