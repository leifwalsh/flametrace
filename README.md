# flametrace

[![codecov](https://codecov.io/gh/leifwalsh/flametrace/branch/main/graph/badge.svg?token=TDFS4CVZCQ)](https://codecov.io/gh/leifwalsh/flametrace)
[![Documentation Status](https://readthedocs.org/projects/flametrace/badge/?version=latest)](https://flametrace.readthedocs.io/en/latest/?badge=latest)
[![PyPI Package](https://img.shields.io/pypi/v/flametrace)](https://pypi.org/project/flametrace/)

Build flamegraph charts for process trees, based on strace.

If you’ve ever wanted to know why a command is slow, flametrace can help! Run
your command under flametrace and get a chart showing what else it ran inside
itself.

## Installing

```
pip install flametrace
```

## Usage

```
flametrace COMMAND
```

## License

[BSD 3-clause](./LICENSE)
