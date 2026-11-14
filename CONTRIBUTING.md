# Contributing

1. Keep live `analyzer.env` files out of git.
2. Put analyzer and viewer code in `src/`, config examples in `config/`, and install helpers in `contrib/`.
3. Run `make check` before opening a pull request. GitHub Actions also compiles the sources and builds the pipe image.
4. Prefer a short pull request that states why the change exists, and how you tried it (viewer report, `docker run … --dry-run`, or both).
