# Contributing to the Clair agent

Thanks for your interest in `clair`, the host-side agent that carries Claude Code's prompts,
end-to-end encrypted, to the Clair app on a Wear OS watch or Android phone.

## Support expectations

The agent is released **as is** under the [Apache License 2.0](LICENSE) and developed on a
best-effort basis, with **no support, warranty or response-time guarantee**. That is the
license's own "AS IS" clause, stated plainly:

- Issues and pull requests are welcome, but may not be triaged, answered or accepted.
- There is no commitment to fix a bug or review a contribution on any timeline.

## Ground rules

- **License.** By contributing, you agree that your contribution is licensed under the Apache
  License 2.0, the same as the project (section 5 of the license).
- **Sign your commits (DCO).** Add a `Signed-off-by: Your Name <you@example.com>` trailer to each
  commit (`git commit -s`), certifying the [Developer Certificate of Origin](DCO), version 1.1.
  The trailer's email must match the commit author's. Only submit work you have the right to
  license under Apache 2.0.
- **Dependencies are an allow-list.** The binary links the Go standard library and four modules,
  all BSD-licensed. Read [`.agents/context/toolchain.md`](.agents/context/toolchain.md) before
  proposing another, and update [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) in the same
  change when the dependency set moves.
- **Security reports go private.** See [`SECURITY.md`](SECURITY.md).

## Development

[`AGENTS.md`](AGENTS.md) and the `.agents/` files it routes to are the single source of truth for
commands, the toolchain, the design map and the decision records. In short:

- Go 1.26 and `make` are required. `make tools` installs the pinned linters into `./bin` once
  per clone.
- `make check` is the gate: tidy, format, lint, `go test -race`, `govulncheck` and the ADR router
  check. CI runs the same targets, so a red job reproduces locally with one command.
- The wire format must match the phone byte for byte. The golden vectors under `testdata/` are
  compared exactly, and a change that moves one is a protocol change, not a test fix.
- A change that makes an architectural or scope choice comes with a decision record:
  `go run ./tools/adr new "<title>" -topics a,b`, then `go run ./tools/adr index`.
- `make hooks` opts the clone into `.githooks`, whose `pre-commit` refuses an ADR commit whose
  generated router is out of sync.

Run `make check` before opening a pull request, and match the surrounding code style.
