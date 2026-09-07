# Contributing

Thanks for taking the time to contribute!

## Getting started

1. Fork and clone the repo.
1. Install git hooks and dev tooling: `make setup`.
1. Create a branch: `git checkout -b feat/short-description`.

## Making changes

- Keep changes focused; one logical change per PR.
- Update `docs/` when behavior changes.
- Ensure CI (`code-quality` + `security`) passes.

Don't edit `CHANGELOG.md` by hand — it's generated from commit messages by
release-please (see [Releases](#releases)).

## Changing the security model

The bind lists at the top of `main.go` (`rwPaths`, `roPaths`, `roFreeze`,
`maskPaths`, `envKeep`) *are* the security model. A PR that adds an entry is a
PR that widens the jail, so:

- Say in the PR description what the new entry exposes when a tool inside the
  jail is hostile, not only what it fixes.
- Paste the relevant `azkaban --dry-run` diff.
- Prefer the per-user config (`~/.config/azkaban/config`) over a new default —
  one person's requirement is not everyone's default.

New escape vectors that are accepted rather than closed belong in the
`KNOWN ESCAPE VECTORS` block at the bottom of `main.go`; an undocumented one is
worse than a documented one.

## Tests

`make test`. The suite drives a real jail against a fake `$HOME` with a
tripwire — see [docs/testing.md](docs/testing.md). Never point a test at your
real home directory; that mistake is the reason this project's overlay default
exists.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat:`,
`fix:`, `docs:`, `chore:`, etc. This keeps history readable and drives the
version bump: `fix:` → patch, `feat:` → minor, `feat!:` or a
`BREAKING CHANGE:` footer → major.

## Releases

Releases are automated by [release-please](.github/workflows/release.yml);
you don't tag or edit the changelog manually.

1. Merge `feat:`/`fix:` PRs into `main` as normal — **no tag is created**.
1. release-please keeps an open **release PR** ("chore: release X.Y.Z"),
   recalculating the next version and changelog on every merge.
1. When you're ready to ship, **merge the release PR** — that (and only that)
   creates the `vX.Y.Z` tag and the GitHub Release.

So `main` is not released per-commit: changes accumulate into the release PR,
and merging it is the deliberate release step.

## Pull requests

Fill out the PR template, link related issues, and request review. Be kind.
