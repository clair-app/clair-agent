#!/usr/bin/env bash
# Stop hook: enforce the `lintorama` container (bundled yamllint + shellcheck + hadolint + markdownlint +
# luacheck + ruff + actionlint + check-jsonschema + editorconfig-checker, plus its JSON/JSONC/TOML syntax
# check) before Claude finishes a turn — the same hook lintorama itself, clair, clair-server and clair-web
# run. It covers the files around the Go code (Markdown, YAML, shell, JSON, `.editorconfig`); Go itself
# is `make check`'s job.
#
# lintorama clean        -> exit 0, Claude stops normally.
# lintorama finds issues -> exit 2 with the findings on stderr, which Claude Code feeds back to the
#                           model so it keeps working and fixes them.
#
# Honors `stop_hook_active` so a genuinely un-fixable finding can't trap the session in an unbounded
# fix loop: after one enforced round we let the turn end. Also no-ops (exit 0) if docker is missing, or
# the published image isn't cached and can't be pulled (e.g. offline), so the linter never wedges a session.

set -uo pipefail

input=$(cat)

if [ "$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)" = "true" ]; then
  exit 0
fi

project_dir="${CLAUDE_PROJECT_DIR:-$(pwd)}"
cd "$project_dir" || exit 0

# The linter ships as a published image on Docker Hub; pull it once on first use.
image="zaventh/lintorama:9"

# Skip cleanly if docker is missing, or the image isn't cached and can't be pulled (don't block a turn
# on missing tooling / no network).
command -v docker >/dev/null 2>&1 || exit 0
docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null 2>&1 || exit 0

# Mount the repo's shared Git dir at its host path so a worktree's `.git` file (which points into
# it) resolves inside the container. Only mount it if git finds one: docker would otherwise create
# the missing host path as an empty root-owned directory.
mounts=(-v "$project_dir":/code)
if gitdir=$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null); then
  mounts+=(-v "$gitdir":"$gitdir")
fi

output=$(docker run --rm "${mounts[@]}" "$image" 2>&1)
status=$?

if [ "$status" -ne 0 ]; then
  {
    echo "Stop blocked: \`lintorama\` found lint issues (exit $status). Fix them, then finish:"
    echo
    printf '%s\n' "$output"
  } >&2
  exit 2
fi

exit 0
