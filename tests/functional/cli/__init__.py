# Copyright (C) 2016-2020 OpenIO SAS
# Copyright (C) 2021-2024 OVH SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import os
import shlex
import subprocess
from tests.utils import BaseTestCase


class CommandFailed(Exception):
    def __init__(self, returncode, cmd, output, stderr):
        super(CommandFailed, self).__init__()
        self.returncode = returncode
        self.cmd = cmd
        self.stdout = output
        self.stderr = stderr

    def __str__(self):
        return (
            "Command '%s' returned non-zero exit status %d.\nstdout:\n%s\nstderr:\n%s"
            % (self.cmd, self.returncode, self.stdout, self.stderr)
        )


def execute(cmd, stdin=None, env=None, expected_returncode=0):
    """Executes command."""
    if isinstance(expected_returncode, int):
        expected_returncode = (expected_returncode,)
    cmdlist = shlex.split(cmd)
    result = ""
    result_err = ""
    stdout = subprocess.PIPE
    stderr = subprocess.PIPE
    in_ = subprocess.PIPE if stdin else None
    _env = os.environ.copy()
    if env:
        _env.update(env)
    proc = subprocess.Popen(cmdlist, stdin=in_, stdout=stdout, stderr=stderr, env=_env)
    if isinstance(stdin, str):
        stdin = stdin.encode("utf-8")
    result, result_err = proc.communicate(stdin)
    result = result.decode("utf-8")
    if proc.returncode not in expected_returncode:
        raise CommandFailed(proc.returncode, cmd, result, result_err)
    return result, result_err.decode("utf-8")


class CliTestCase(BaseTestCase):
    @classmethod
    def account_from_env(cls):
        """Get the name of the account set in the process' environment."""
        return os.getenv("OIO_ACCOUNT", "myaccount")

    @classmethod
    def openio(cls, cmd, coverage="--coverage ", **kwargs):
        """Executes openio CLI command."""
        return execute("openio " + coverage + cmd, **kwargs)[0]

    @classmethod
    def openio_batch(cls, commands, coverage="--coverage", **kwargs):
        """Execute several commands in the same openio CLI process."""
        script = "\n".join(commands)
        try:
            return execute("openio " + coverage, stdin=script, **kwargs)[0]
        except CommandFailed:
            print("Stdin was:\n\n%s" % (script,))
            raise

    @classmethod
    def openio_admin(cls, cmd, coverage="--coverage ", **kwargs):
        """Executes openio-admin CLI command."""
        return execute("openio-admin " + coverage + cmd, **kwargs)[0]

    @classmethod
    def openio_admin_with_stderr(cls, cmd, coverage="--coverage ", **kwargs):
        """Executes openio-admin CLI command."""
        return execute("openio-admin " + coverage + cmd, **kwargs)

    @classmethod
    def openio_admin_batch(cls, commands, coverage="--coverage", **kwargs):
        """Execute several commands in the same openio-admin CLI process."""
        return execute("openio-admin " + coverage, stdin="\n".join(commands), **kwargs)[
            0
        ]

    # FIXME(FVE): deprecate this
    @classmethod
    def get_opts(cls, fields, format="value"):
        return cls.get_format_opts(format_=format, fields=fields)

    @classmethod
    def get_format_opts(cls, format_="value", fields=None):
        """
        Get formatting options for OpenIO CLIs,
        to make them output the specified fields in the specified format.
        """
        if fields is None:
            fields = []
        return " -f {0} {1}".format(format_, " ".join(["-c " + it for it in fields]))

    @classmethod
    def assertOutput(cls, expected, actual):
        """
        Compare command outputs, raise an exception if they are different.
        """
        if expected != actual:
            raise Exception("'" + expected + "' != '" + actual + "'")

    def setUp(self):
        super(CliTestCase, self).setUp()
        # Our CLI heavy on CPU usage, making scores go down. To prevent tests
        # from failing because of low scores, it seems a good idea to check
        # them before each test.
        self.wait_for_score(("rawx", "meta2"), score_threshold=2, timeout=5.0)

    def assert_list_output(self, expected_list, actual_output):
        self.assertListEqual(
            sorted(expected_list), sorted(actual_output.rstrip("\n").split("\n"))
        )

    def assert_show_fields(self, items, fields):
        for item in items:
            self.assertIn(item, fields)

    def assert_list_fields(self, items, fields):
        for item in items:
            for field in fields:
                self.assertIn(field, item)
