Write the commit message for Linux Hello like this:

- Subject line: imperative mood, at most 72 characters, no trailing full stop, no type prefix. Example: "Refuse callers from another origin".
- Blank line, then a body wrapped at 72 characters that says what changed in behaviour and why. Name the tests added.
- Mention the issue as "Refs #N" or "Closes #N" when the staged change belongs to one.
- Never write a Signed-off-by line; git adds it with `git commit -s`.
- Add "Assisted-by: GitHub Copilot" as the last line.
- Never include host names, home paths, hardware details, tokens or personal data.
