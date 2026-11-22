# Puts one Linux Hello line into a PAM file (used by install.sh, tested by scripts/ci/test-pam-insert.sh).
#
#   awk -v line='auth ... pam_linuxhello.so context=sudo # mark' -v mark='# mark' -f pam-insert.awk FILE
#
# An earlier Linux Hello line (one that holds `mark`) is dropped. The new line goes directly before
# `@include common-auth` when the file has one: Ubuntu's login and kde files check /etc/nologin
# (pam_nologin) and set the delay after a failure (pam_faildelay) before it, and a Linux Hello line
# in front of them would skip both (#359). A file without that include gets the line before its first
# `auth` line. A file with neither is an error (exit status 3).
{ lines[NR] = $0 }
END {
  anchor = 0
  for (i = 1; i <= NR; i++) {
    if (index(lines[i], mark)) continue
    if (lines[i] ~ /^@include[ \t]+common-auth([ \t]|$)/) { anchor = i; break }
  }
  if (!anchor) {
    for (i = 1; i <= NR; i++) {
      if (index(lines[i], mark)) continue
      split(lines[i], word, /[ \t]+/)
      if (word[1] == "auth") { anchor = i; break }
    }
  }
  if (!anchor) exit 3
  for (i = 1; i <= NR; i++) {
    if (index(lines[i], mark)) continue
    if (i == anchor) print line
    print lines[i]
  }
}
