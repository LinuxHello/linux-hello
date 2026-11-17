@AGENTS.md

## Claude Code

The rules above are binding. These additions apply only to Claude Code, whether it runs against Anthropic's API or a local model.

- Run the gates from [AGENTS.md](AGENTS.md#gates) yourself before reporting a change as done, and quote the result.
- Before you write or change a note, a README or a guide, read [Write for a reader who is new to the subject](AGENTS.md#write-for-a-reader-who-is-new-to-the-subject), and before you report the document as done, read it once as that reader and say that you did.
- Use `gh` for GitHub; never ask for or handle a token.
- Commit trailer: `Assisted-by: Claude Code (<model>)`. For a local model, name its family and size at most.
- Personal settings (model, endpoint, permissions) belong in `~/.claude/` or `.claude/settings.local.json`, which is git-ignored. Never commit them.
