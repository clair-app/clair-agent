---
id: "2026-09.zhzc"
slug: the-qr-is-rendered-with-rsc-io-qr-and-drawn-in-half-blocks-by-the-agent
title: "The QR is rendered with rsc.io/qr and drawn in half-blocks by the agent"
date: 2026-09-21
topics: [pairing, dependencies]
---

# ADR 2026-09.zhzc — The QR is rendered with rsc.io/qr and drawn in half-blocks by the agent

Status: Accepted (2026-09-21)

**What was observed.** `clair pair` shows a QR the phone scans (RELAY.md §6.1). The standard
library has no QR encoder; writing one is ~600 lines (GF(256) Reed–Solomon, placement, masking,
format bits) plus a way to prove it right without a decoder. The payload is 65 bytes — `0x01 ‖
pairingId[16] ‖ hostPub[32] ‖ k[16]`, with the relay host appended only when it differs from
the link's origin — carried as `https://<relay>/p#<base64url>`: 117 characters, which encodes at
version 6 (41 modules) at error-correction level L. RELAY.md's "≈85 bytes → version 6" only
holds with the relay field omitted and at level L; at M or with the relay repeated it is
version 7 or 8.

**What changed.** `rsc.io/qr` v0.2.0 is the one dependency outside `golang.org/x`: finished
(2018), dependency-free, BSD-3, one call (`qr.Encode(text, qr.L)`) returning a bitmap. The
agent draws it: two modules per character with `▀ ▄ █` (23 lines for version 6 with a
two-module quiet zone, which fits an 80×24 terminal, over SSH too), `--qr=ascii` for a terminal
without UTF-8, `--qr=none` to print the link only, and `--invert` for a light background. The
default draws light modules as blocks, which is what a dark terminal wants; scanners read both
polarities. On Windows the default is ASCII only when stdout is a pipe or a file outside
Windows Terminal: a console is written in UTF-16 whatever its code page, and `WT_SESSION` alone
missed the console Windows 11 hands to Windows Terminal as the default terminal. The
alternative — `github.com/skip2/go-qrcode` — is equally fine and more used; `rsc.io/qr` was
chosen for its size and pedigree. The in-house encoder was not taken because a QR that fails to
scan is diagnosed by a phone, not a test.

**What it costs.** A `go.sum` row for an unmaintained-because-finished package, refused by the
no-vendor rule from being forked. The trap: a self-hosted relay with a long hostname pushes the
link over version 6 and the code past 24 lines — it still scans, it just scrolls. What keeps
this true: the `depguard` allow-list row for `rsc.io/qr` in `.golangci.yml`, the golden
renderings in `internal/pairing/testdata/qr-*.txt`, and `TestRenderQRFitsATerminal`, which
fails if the default link stops encoding at 41 modules.
