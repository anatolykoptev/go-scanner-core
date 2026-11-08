# Contributing to go-scanner-core

go-scanner-core is a small security-boundary library: SSRF hard-blocking, scope authorization
and tamper-evident audit logging. Changes that widen what is allowed, or that weaken a fail-closed
path, need an issue first so the threat model can be discussed before code is written. Report
vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Development

You need Go 1.26 (the version in `go.mod`) and, for the full gate,
[gostall](https://github.com/erfanmomeniii/gostall) v1.0.0 and golangci-lint v2.

```sh
go install github.com/erfanmomeniii/gostall/cmd/gostall@v1.0.0
make preflight   # gostall, gofmt check, go vet, go build, go test -race -count=1
make lint        # golangci-lint run ./...
make cover       # race tests plus a coverage summary
```

CI runs `make preflight` and golangci-lint on every pull request to `main` (workflow
`preflight`). If they pass locally they pass there. A pull request that changes only documents
skips that job.

## Tests

Security behaviour is tested at the boundary: add a table-driven case in `authz/*_test.go` or
`target/*_test.go` for every new accepted or rejected input, and a seed to the fuzz corpus when
a parser changes. A fix for a bypass must come with a test that fails without it.

## Commits

Conventional Commits: `feat:`, `fix:`, `perf:`, `refactor:`, `docs:`, `deps:`, `revert:`, and
`chore:`, `ci:`, `test:`, `build:`, `style:` (these last five are hidden from the changelog).
release-please reads them: `feat:` makes a minor release, `fix:` a patch, and `feat!:` or a
`BREAKING CHANGE:` footer a breaking one (before 1.0 it raises the minor version). A commit that
does not parse is left out of the release notes, so keep the subject clean. Never tag or edit
`CHANGELOG.md` by hand.

## Pull requests

Describe what changed, why, and how it was tested. Keep a pull request to one concern, update
[docs/INDEX.md](docs/INDEX.md) when you add or rename a document, and never commit secrets or
personal data. By contributing you agree your work is licensed under Apache-2.0, see
[LICENSE](LICENSE).
