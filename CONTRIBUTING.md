# Filing Bugs

Use github issues, as usual. It's likely that any problems come from versions of `strace` we haven't tested against, so be sure to provide that version. It's unexpected that this works anywhere but on Linux.

# Pull Requests

New features are of course welcome. Tests, linting, doc builds, and coverage diffs will automatically be run on new PRs, so just go ahead and create one if you think you have something good to add.

# Development Environment

`flametrace` doesn't depend on much, you should be able to clone it, run `pip install -e .` into a virtualenv, and start editing and testing by running `flametrace`.

The easiest way to get a development environment is to clone it in a VS Code devcontainer. There is a good default environment set up in the repository, which you can get by cloning straight into a devcontainer.

## Testing

You can run the tests with `unittest`, or with `tox -e py39` (or your favorite modern Python 3). You can run tests with coverage with `tox -e coverage` (the default devcontainer setup will show coverage in the gutter).

## Linting

We use `flake8` with `tox -e flake8`.

## Building Docs

You can build the docs with `tox -e docs`. In the devcontainer, `Ctrl-Shift-B` will build the docs and run an HTTP server so you can view them.
