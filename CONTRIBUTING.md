# Contributing

1. Keep live `analyzer.env` files out of git.
2. Put analyzer and viewer code in `src/`, config examples in `config/`, and install helpers in `contrib/`.
3. Use TDD: add or adjust a test in `tests/` for the behaviour you want, run `make test` and see it fail, then change `src/` until the suite is green.
4. Run `make test` before opening a pull request. GitHub Actions runs the same suite. Use `make test` rather than a bare `pytest` if your shell’s Python has extra pytest plugins installed.
5. Prefer a short pull request that states why the change exists, and how you tried it (tests, viewer report, `docker run … --dry-run`, or both).
