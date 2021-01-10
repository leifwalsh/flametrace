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

from pathlib import Path
import sys
import tempfile
from unittest import TestCase, skipUnless

from click.testing import CliRunner

from flametrace.main import cli


class FlametraceTestBase(TestCase):

    command = ...

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.out_base = Path(self.tmpdir.name, "trace")
        runner = CliRunner(mix_stderr=False)
        result = runner.invoke(
            cli, ["--output-base", self.out_base, *self.command]
        )
        self.returncode = result.exit_code
        self.stdout = result.stdout
        self.stderr = result.stderr

    def tearDown(self):
        self.tmpdir.cleanup()


class FlametraceTests(FlametraceTestBase):

    command = ["ls"]

    def test_flametrace(self):
        self.assertEqual("", self.stderr)
        self.assertIn(f"strace: {self.out_base}.strace", self.stdout)
        self.assertIn(f"folded: {self.out_base}.folded", self.stdout)
        self.assertIn(f"chart:  {self.out_base}.svg", self.stdout)
        self.assertEqual(0, self.returncode)


@skipUnless(
    sys.version_info.major == 3 and sys.version_info.minor == 9,
    "only run on python 3.9",
)
class Flake8FlametraceTests(FlametraceTests):

    command = ["--mode", "io", "tox", "-e", "flake8"]
