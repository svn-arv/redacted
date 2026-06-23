# Contributing

Thanks for helping improve `redacted`.

## Development

```bash
git clone https://github.com/svn-arv/redacted.git
cd redacted
go build -o redacted .
go test ./...
```

`go vet ./...` and `gofmt -l .` should come back clean.

## Detection rules

Detection patterns and the heuristic live in `internal/patterns/engine.yml`. Add
or tune rules there, not in Go. A new pattern needs:

- a synthetic generator in `internal/testutil/fake.go` (never commit a real key),
- a recall case in `internal/patterns/corpus_test.go`, and
- no regression in `TestCorpus_Precision` (the clean corpus stays clean).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the engine fits together.

## Pull requests

- Branch off `main` (`feat/...`, `fix/...`, `chore/...`).
- Use [Conventional Commits](https://www.conventionalcommits.org/).
- CI (build, vet, test) must pass.
- A maintainer reviews and merges; external PRs need a maintainer approval.
