# Testing rules

The decision — standard library, no assertion framework — and its reasons are
ADR 2026-09.vnj9. These are the rules that follow from it.

- `make test` is the only invocation: `go test -race -shuffle=on -count=1`. A test that
  passes only without `-race`, only without `-shuffle`, or only on the second run is a bug
  in the test or the code, never a flake to retry.
- Table tests with `t.Run` subtests; `t.Parallel()` on every test and subtest that does not
  touch process-wide state (`tparallel` keeps a package consistent). Name cases for what
  they prove, not what they do.
- Failures print `got X, want Y` with enough context to fix the test without a debugger;
  byte comparisons use `%x`. No assertion library.
- **Golden vectors are files, not literals.** The relay vectors come from `:shared/relay`
  in the `clair` repository (`RelayVectorsTest`); copy the file into
  `internal/<pkg>/testdata/` unchanged and record, in a comment beside the loader, the
  clair commit it was taken from. Compare with `bytes.Equal`. A vector that "needs a small
  fix" is a bug in one of the two implementations — find out which before touching it.
- Inject the clock and the entropy source as parameters (`mintID(now, entropy)` in
  `tools/adr` is the pattern); never monkey-patch a global.
- The filesystem is `t.TempDir()`; the environment is `t.Setenv`; a test never writes
  outside either. Network is `net/http/httptest` or a loopback listener on port `0` —
  no test reaches a real relay, and none needs one.
- Test `run(args, stdout, stderr)` rather than `main`; test behaviour through the package's
  exported-to-the-package surface, not by reaching into a struct.
- A change to what the agent puts on the wire — a record field, the AAD, a header — gets
  a vector test, not only a unit test against a mock.
