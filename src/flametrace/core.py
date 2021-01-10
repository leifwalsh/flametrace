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

"""Process strace output for flamegraph."""

from collections import defaultdict, namedtuple
import copy
from datetime import datetime, timedelta
import sys


Call = namedtuple("Call", "pid ts func args retcode status elapsed")


class StraceParser(object):
    """Parse strace output into Call objects."""

    def __init__(self):  # noqa: D107
        self.pending = {}

    def parse_call(self, call):
        """Parse a single line of strace output."""
        if call.startswith("+++ exited with "):
            retcode = int(call[len("+++ exited with ") :].split()[0])
            return "atexit", None, retcode, None, None
        elif call.startswith("--- "):
            rest = call[len("--- ") :]
            signal, rest = rest.split(" ", 1)
            assert rest.endswith(" ---")
            return "interrupt", signal, rest[:-4], None, None
        else:
            call, rest = call.rsplit(" = ", 1)
            rest = rest.split(" ", 1)
            try:
                retcode = int(rest[0])
            except ValueError:
                retcode = rest[0]
            if len(rest) > 1:
                rest = rest[1].rsplit(" ", 1)
                if len(rest) > 1:
                    status, elapsed = rest
                else:
                    status = None
                    elapsed = rest[0]
                assert elapsed.startswith("<")
                assert elapsed.endswith(">")
                elapsed = timedelta(seconds=float(elapsed[1:-1]))
            else:
                status = None
                elapsed = timedelta(0)
            func = call.split("(")[0]
            args = call[len(func) + 1 :].rsplit(")", 1)[0]
            return func, args, retcode, status, elapsed

    def parse_line(self, line):
        """Parse a line of strace output, collapsing "unfinished" traces."""
        s = line.split(None, 2)
        pid = int(s[0])
        ts = datetime.utcfromtimestamp(float(s[1]))
        if s[2].endswith(" <unfinished ...>"):
            assert pid not in self.pending
            self.pending[pid] = s[2][: -len(" <unfinished ...>")]
        elif s[2].startswith("<... "):
            to_parse = self.pending.pop(pid)
            rest = s[2][len("<... ") :]
            expect_func, rest = rest.split(" ", 1)
            assert rest.startswith("resumed>")
            rest = rest[len("resumed>") :]
            rest = rest.lstrip()
            to_parse += rest
            func, args, retcode, status, elapsed = self.parse_call(to_parse)
            assert func == expect_func
            return Call(
                pid=pid,
                ts=ts,
                func=func,
                args=args,
                retcode=retcode,
                status=status,
                elapsed=elapsed,
            )
        else:
            func, args, retcode, status, elapsed = self.parse_call(s[2])
            return Call(
                pid=pid,
                ts=ts,
                func=func,
                args=args,
                retcode=retcode,
                status=status,
                elapsed=elapsed,
            )

    def parse(self, f):
        """Parse a file containing strace output."""
        for line in f:
            result = self.parse_line(line.strip())
            if result is not None:
                yield result


class SyscallCounter(object):
    """Measure the time spent during a counted number of syscalls."""

    def __init__(self):  # noqa: D107
        self.calls = 0
        self.elapsed = timedelta(0)

    def __add__(self, other):  # noqa: D105
        self.calls += 1
        self.elapsed += other


class Process(object):
    """Representation of a process.

    This class is tightly coupled with Collapser, which manipulates it
    and adds new fields as it processes.

    """

    def __init__(self, pid, parent, begin):  # noqa: D107
        self.args = None
        self.pid = pid
        self.parent = parent
        self.begin = begin
        self.end = None
        self.child_samples = timedelta(0)
        if parent is not None:
            # Attribute any of a child's syscalls to its parent.
            self.syscalls = parent.syscalls
        else:
            self.syscalls = defaultdict(SyscallCounter)

    def execve(self, args, ts):
        """When a process execs, detach it from the parent.

        Consider this a new process on its own, with its own syscall
        tracking.

        Returns the Process entry for the process that led up to this
        exec, for tracking.

        """
        oldproc = copy.copy(self)
        oldproc.end = ts
        self.begin = ts
        self.end = None
        self.args = args
        self.child_samples = timedelta(0)
        self.syscalls = defaultdict(SyscallCounter)
        return oldproc

    @property
    def elapsed(self):  # noqa: D102
        end = self.end if self.end is not None else datetime.now()
        sumcalls = sum(
            (counter.elapsed for counter in self.syscalls.values()),
            timedelta(0),
        )
        return (end - self.begin) - self.child_samples - sumcalls

    def __str__(self):  # noqa: D105
        if self.parent is not None:
            s = str(self.parent)
        else:
            s = ""
        # Many processes (like /bin/bash) aren't interesting just by process
        # name, so we include some information about its args in its frame.
        if self.args is not None:
            arg0, argv = self.args.split(",", 1)
            arg0 = eval(arg0)
            argv = argv.lstrip()
            if argv.startswith("["):
                # argv is a list, let's try to process it like one.
                argv = argv[: argv.rindex("]") + 1]
                if argv[-4:] == "...]":
                    # Last argument truncated, let's make this eval-able.
                    argv = argv[:-4] + ', "..."]'
                try:
                    argv = eval(argv)
                except Exception:
                    # Couldn't eval, just take some content to identify it.
                    argv = argv[:32]
            # Must replace semicolons with something (since they're
            # flamegraph's separator), may as well choose 'z'.
            me = f"{arg0}({self.pid}) {argv}".replace(";", "z")
            if s:
                return s + ";" + me
            else:
                return me
        else:
            return s


class Collapser(object):
    """Collapse strace output calls into a flamegraph input.

    Our strace handling records process begin and end times, but
    flamegraph understands "samples", as if we had sampled the stack
    and had a number of observations. We approximate the sampling input
    by recording an output row for each unique stack we saw, and
    pretend we saw one sample per millisecond while it was executing.

    This explains why we remove the "self time" a child process records
    from its parent's total time recorded.

    """

    SYSCALLS = (
        "open",
        "openat",
        "link",
        "unlink",
        "unlinkat",
        "getcwd",
        "chdir",
        "mkdir",
        "access",
        "faccessat",
        "lstat",
        "stat",
        "newfstatat",
        "statfs",
        "readlink",
        "mount",
        "read",
        "write",
        "connect",
        "socket",
        "bind",
        "setsockopt",
        "getsockopt",
        "getsockname",
        "getpeername",
        "sendmmsg",
        "recvmsg",
        "recvfrom",
        "sendto",
    )

    def __init__(self):  # noqa: D107
        self.pmap = {}
        self.finished = []

    def process(self, pid):
        """Get a Process if we know about it."""
        return self.pmap.get(pid)

    def record_finished(self, proc):
        """Account for a process which is done."""
        if proc.args is None:
            # Processes without their own args are still threads in their
            # parent thread group, we can skip counting them, since their
            # syscalls are attributed to their parent and their elapsed time
            # is too.
            return
        selftime = proc.elapsed
        current = proc.parent
        while current is not None:
            current.child_samples += selftime
            current = current.parent
        self.finished.append(proc)

    def handle_call(self, call):
        """Consume strace calls into the process map."""
        if call.func == "clone":
            # We've seen a process get created, and assume we'll see it
            # exec something later (in execve).
            self.pmap[call.retcode] = Process(
                call.retcode, self.process(call.pid), call.ts
            )
        elif call.func == "execve":
            if call.retcode != 0:
                # Ignore failed execs
                return
            proc = self.process(call.pid)
            if proc is None:
                # The first process in the tree won't have been cloned
                # from anything, so create one to hold its information.
                proc = self.pmap[call.pid] = Process(call.pid, None, call.ts)
                proc.args = call.args
            else:
                oldproc = proc.execve(call.args, call.ts)
                self.record_finished(oldproc)
        elif call.func == "atexit":
            # When a process exits, record the time it consumed, and
            # subtract that self time from its parent processes to avoid
            # double-counting samples.
            proc = self.pmap.pop(call.pid)
            proc.retcode = call.retcode
            proc.end = call.ts
            self.record_finished(proc)
        elif call.func in self.SYSCALLS:
            if call.func == "read" and call.args[1:7] == "<pipe:":
                # Don't record the read time for pipes between processes
                return
            parent = self.process(call.pid)
            if parent is not None:
                counter = parent.syscalls[call.func]
                counter += call.elapsed

    def render(self, f=sys.stdout):
        """Render flamegraph input based on our process map."""
        for proc in self.finished:
            us = max(1, int(proc.elapsed.total_seconds() * 1000000))
            print(proc, us, file=f)
            for func, counter in proc.syscalls.items():
                us = int(counter.elapsed.total_seconds() * 1000000)
                print(f"{proc};{func}({counter.calls} calls)", us, file=f)
