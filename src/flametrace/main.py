# Copyright (c) 2021, Leif Walsh
# All Rights Reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# * Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
# * Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
# * Neither the name of the <organization> nor the names of its contributors
# may be used to endorse or promote products derived from this software
# without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#         SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

"""Render a flamegraph based on stracing a process tree."""

from datetime import datetime
import functools
import os
import os.path
import pkg_resources
import shlex
import subprocess
import sys
import tempfile
import time

import click

from . import core


FLAMEGRAPH = pkg_resources.resource_filename(
    "flametrace", "perl/flamegraph.pl"
)
STRACE = "strace"


@functools.lru_cache()
def _strace_version():
    output = subprocess.check_output([STRACE, "-V"], text=True)
    line = next(iter(output.splitlines()))
    return pkg_resources.parse_version(line.split()[-1])


def _run_strace(mode, argv, output):
    version = _strace_version()
    modes = {
        "process": "trace=%process",
        "io": "trace=%process,%network,%file,read,write",
    }

    strace_args = []
    if version >= pkg_resources.parse_version("5.3"):
        strace_args.append("--seccomp-bpf")
    strace_args.extend(
        [
            "-tttyfT",
            "-e",
            modes[mode],
            "-s",
            "128",
            "-o",
            output,
        ]
    )
    return subprocess.call([STRACE, *strace_args, "--", *argv])


def _collapse_stacks(strace_output, folded_output):
    parser = core.StraceParser()
    collapser = core.Collapser()
    with open(strace_output, "r") as f:
        for call in parser.parse(f):
            collapser.handle_call(call)
    with open(folded_output, "w") as f:
        collapser.render(f)


@click.command(context_settings=dict(ignore_unknown_options=True))
@click.option(
    "--output-base",
    "output",
    help="output basename (OUTPUT.strace, OUTPUT.folded, OUTPUT.svg)",
)
@click.option(
    "--flamegraph-options",
    help="additional flamegraph options (e.g. --inverted)",
)
@click.option(
    "--mode",
    type=click.Choice(["process", "io"]),
    default="process",
    help="what operations to trace (io is slower but more detailed)",
)
@click.argument("command", nargs=-1)
def cli(output, flamegraph_options, mode, command):
    """Run a command and render a flamegraph based on its process tree."""
    if not output:
        now = datetime.now()
        argv0 = os.path.basename(command[0])
        basename = f"{argv0}-{now:%Y%m%d_%H%M%S_%f}"
        dest_dir = tempfile.gettempdir()
        output = os.path.join(dest_dir, basename)

    strace_output = f"{output}.strace"
    folded_output = f"{output}.folded"
    svg_output = f"{output}.svg"

    t0 = time.perf_counter()
    retcode = _run_strace(mode, command, strace_output)
    t1 = time.perf_counter()

    cmd = " ".join(command)
    click.echo(f'Ran "{cmd}" in {t1 - t0:.2f}s')

    _collapse_stacks(strace_output, folded_output)
    flamegraph_cmd = [
        FLAMEGRAPH,
        "--flamechart",
        "--countname",
        "us",
        "--nametype",
        "Frame:",
        "--colors",
        "aqua",
        "--width",
        "1600",
    ]
    if flamegraph_options:
        flamegraph_cmd.extend(shlex.split(flamegraph_options))
    flamegraph_cmd.append(folded_output)
    subprocess.check_call(flamegraph_cmd, stdout=open(svg_output, "w"))

    click.echo(f"strace: {strace_output}")
    click.echo(f"folded: {folded_output}")
    click.echo(f"chart:  {svg_output}")
    sys.exit(retcode)
