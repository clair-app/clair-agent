---
id: "2026-09.zvs8"
slug: releases-are-tag-pipelines-that-upload-to-the-package-registry
title: "releases are tag pipelines that upload to the package registry, and claircode.app serves them pinned by hash"
date: 2026-09-24
topics: [release, install, ci]
---

# ADR 2026-09.zvs8 — releases are tag pipelines that upload to the package registry, and claircode.app serves them pinned by hash

Status: Accepted (2026-09-24)

**What was observed.** On 2026-09-24 the agent had no tags and no published builds, and this
project is private: anonymous requests redirect to a login, so no public URL could serve a
binary. `clair service install` (ADR 2026-09.ahq8) leaves putting the binary somewhere stable
to an installer, and RELAY.md §15 still listed where releases live as open. The same day
claircode.app took the installers: `https://claircode.app/install.sh` and `/install.ps1`,
downloading from `https://claircode.app/releases/` (clair-web ADR 2026-09.e7ky). `make
build-all` stamps the build time into every binary (`-X main.date`), so two builds of one
commit never hash the same.

**What changed.**

- A `vX.Y.Z` tag runs the `release` job. It runs `make dist VERSION=$CI_COMMIT_TAG`, which
  cross-compiles the six platforms, refuses a version that isn't a release tag or that the
  host's build doesn't report, and writes `dist/SHA256SUMS.txt`. The job uploads the six
  builds and the checksums to this project's generic package registry as
  `packages/generic/clair/<tag>/<file>`, with `CI_JOB_TOKEN`.
- The registry is the source, not the storefront. clair-web pins each release's hashes in
  `agent-release.json`, taken from the uploaded files, and its deploy fetches them with its
  own job token and refuses a mismatch. A build reaches users only through a reviewed commit
  there, so a re-upload here, or a compromised token, fails the site's deploy instead of
  shipping.
- The job builds from the tag instead of reusing the `build` job's artifacts, because those
  are stamped with `git describe`, which a shallow clone may not resolve to the tag.

The alternatives: GitHub or GitLab release assets need a public project or a public mirror;
a bucket is a second origin for users to trust. Serving from the product's own domain keeps
one origin in the install command.

**What it costs.** The site needs this project to allow it under Settings → CI/CD → Job token
permissions, or its deploy can't read the registry. Because of the build-time stamp, a local
`make dist` never reproduces the uploaded bytes, so the site pins hashes from the registry
and never from a local build. Replacing a running `clair.exe` on upgrade is the installer's
job (it stops the service and renames the old file first). The `release` job is the gate:
`make dist` fails a tag whose builds report another version.
