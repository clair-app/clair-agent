---
id: "2026-09.6uv6"
slug: windows-releases-are-authenticode-signed-through-azure-artifact-signing-and
title: "Windows releases are Authenticode-signed through Azure Artifact Signing and timestamped"
date: 2026-09-25
topics: [release, windows, security]
---

# ADR 2026-09.6uv6 — Windows releases are Authenticode-signed through Azure Artifact Signing and timestamped

Status: Accepted (2026-09-25)

**What was observed.** On a Windows 11 machine running Avast, `clair version` in PowerShell
flashed several windows. It looked like the agent spawning something, but it wasn't.

- The agent starts no process for `version`. On `win11`, without Avast, a trace of every
  process start showed `clair.exe` alone, both over SSH and from the signed-in desktop.
- On the Avast machine, the same trace showed two `clair.exe` processes with PowerShell as
  their parent, a `conhost.exe` whose parent was the second `clair.exe`, and `AvastUI.exe`.
- A console program started from PowerShell shares its console and never gets its own
  `conhost`. That one got a new console, which is the window that flashed.
- The builds were unsigned, and antivirus holds back unknown unsigned programs.
- The maintainer already signs the a desktop app through Azure Artifact Signing. That
  is subscription `…`, account `the signing account` (Basic, East US), and Public Trust
  profile `the certificate profile`, as an individual:
  `CN=Jeffrey Mixon, O=Jeffrey Mixon`.

**What changed.** A release tag runs four jobs (`.gitlab-ci.yml`):

1. **`dist`**: `make dist`, as before.
2. **`sign`**: jsign 7.5 (a pinned jar, SHA-256 checked, in `eclipse-temurin:21-jre`) signs
   copies of the two Windows builds.
   - It calls Artifact Signing's API directly, so it needs no Windows machine and no signtool.
   - It is handed an access token, which the job gets from Entra ID with the client secret.
     jsign 7.5 takes only a token for `TRUSTEDSIGNING`. The `<tenant>|<client>|<secret>` form
     in its online docs is from master, and on 7.5 it fails with a 401.
   - It signs with SHA-256 and always adds an RFC 3161 timestamp from
     `timestamp.acs.microsoft.com`. The certificates live three days, so a signature without a
     timestamp is valid at release and invalid by the weekend.
   - The job hands on only `signed/`.
3. **`signature:windows`**: on the `windows` runner, `Get-AuthenticodeSignature` must say
   `Valid`, name Jeffrey Mixon and find a timestamp. The build for the runner must still report
   the tag.
4. **`release`**: `make dist-signed SIGNED=signed`, then the upload.
   - `tools/authenticode check -unsigned dist` refuses a signed copy unless its Authenticode
     digest is `dist`'s own build and its signature and timestamp verify. Signing changes only
     the checksum, the certificate table's directory entry and the table, so a signed file that
     passes is exactly this pipeline's build plus a signature, whatever the `sign` job ran.
   - `SHA256SUMS.txt` is then written over the signed bytes. clair-web pins those, and signs
     them for the self-update, unchanged.

**The credentials.** `sign` uses the signing app registration, not another app's, so either
can be revoked alone.

- It holds *Artifact Signing Certificate Profile Signer* on `the certificate profile` only.
- Its client secret sits in `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`,
  which are protected variables scoped to the `windows-signing` environment. The secret is also
  masked.
- `v*` tags are protected (Maintainers create them). Only a protected tag's pipeline, and in it
  only `sign`, can read the variables. Without them, `sign` fails and nothing is uploaded.

To renew the secret before it expires, as a user who owns the app:

```sh
APP=$(az ad app list --display-name the signing app --query '[0].appId' -o tsv)
az ad app credential reset --id "$APP" --append --display-name gitlab-ci --years 1 --query password -o tsv |
  glab variable update AZURE_CLIENT_SECRET --scope windows-signing -R clair/clair-agent
```

Then delete the old secret with `az ad app credential delete`.

**The alternatives.**

- *The usual desktop-app route*, electron-builder or signtool with Microsoft's TrustedSigning PowerShell
  module on the Windows runner. It works, but the module downloads its own signtool at run
  time, and every release would depend on the one hand-provisioned machine for the signing as
  well as the check.
- *A certificate profile of clair's own.* The Basic plan holds one Public Trust profile, so it
  would need Premium, and the subject would still be the same verified individual.
- *A signer in Go.* Artifact Signing signs a digest, so the agent's own tooling could build the
  PKCS#7. That is hundreds of lines of ASN.1 to write and trust. jsign is maintained and
  independent, and `tools/authenticode` checks what it produced.
- *Reporting a false positive to Avast* would have to be repeated for every release and every
  vendor.

**What it costs.**

- **Reproduction is by digest, not by hash.** `make dist` on the tag still reproduces every
  non-Windows build byte for byte (ADR 2026-09.zvs8). For the two Windows builds,
  `go run ./tools/authenticode digest` on the released file and on the local build must agree.
- **Re-running `sign` changes the bytes**, because the timestamp differs. A re-run after an
  upload puts new files beside the old ones, and clair-web's pin catches the change.
- **A release now depends on more services:** Azure, the Microsoft timestamp server, GitHub
  (for the jar) and the `windows` runner.
- **It is an individual's identity.** SmartScreen and antivirus build reputation per
  certificate subject over time. Signing makes a hold like Avast's less likely, not impossible.
- **The trust anchor is unchanged.** The self-update trusts the Ed25519 release signature
  (ADR 2026-09.qk6v) and never reads Authenticode. Authenticode is for Windows and antivirus.
- **What keeps it true:** `tools/authenticode`'s tests run against jsign-signed fixtures,
  including ones with no timestamp and with a timestamp outside the certificate's validity. The
  `release` job cannot upload without `make dist-signed`.
