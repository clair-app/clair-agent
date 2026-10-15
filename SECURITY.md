# Security policy

The Clair agent is a blind tunnel: it carries Claude Code's hooks from the dev machine to a paired
phone, end-to-end encrypted, through a relay that only ever sees ciphertext. Security reports are
taken seriously, but the project ships **as is, with no warranty or guaranteed response** (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Reporting a vulnerability

**Please do not open a public issue or pull request for a vulnerability.** Report it privately
through GitHub's [private vulnerability reporting][report]: the "Report a vulnerability" button on
the repository's *Security* tab opens a draft advisory that only the maintainers can see. Include:

- a description of the issue and its impact,
- steps to reproduce, or a proof of concept, and
- the affected version (`clair version`) or commit.

Please allow reasonable time for a fix before any public disclosure.

[report]: https://github.com/clair-app/clair-agent/security/advisories/new

## What is in scope

- The envelope: key agreement, sealing, replay counters and the pairing payload
  (`internal/envelope`, `internal/identity`, `internal/pairing`).
- The loopback hook server and its bearer tokens (`internal/hookserver`, `internal/ctl`).
- How a phone's answer is checked before it reaches Claude Code (`internal/hookout`), and how a
  phone-supplied hook snippet is rebuilt (`internal/claudecfg`).
- The self-update: release signature verification and the binary swap (`internal/update`).
- Anything that writes plaintext of a hook to a log or to the relay.

## Design trade-offs, not vulnerabilities

- **The relay sees routing metadata.** It never holds a traffic key, but it sees pair ids,
  timing, sizes and the coarse `wake` hint the agent attaches so the phone can be woken.
- **A paired phone answers permission prompts.** That is the product. The agent checks every
  answer against the request it holds and rebuilds it, but a compromised paired phone can still
  approve what Claude Code asks.
- **The loopback bearer is readable by the same user.** It lives in the user's config directory
  with owner-only permissions; another process running as that user is out of scope.
