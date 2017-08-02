# Copyright (C) 2016-2017 OpenIO SAS

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
        return ("Command '%s' returned non-zero exit status %d.\n"
                "stdout:\n%s\n"
                "stderr:\n%s" % (self.cmd,
                                 self.returncode,
                                 self.stdout,
                                 self.stderr))


def execute(cmd):
    """Executes command."""
    cmdlist = shlex.split(cmd)
    result = ''
    result_err = ''
    stdout = subprocess.PIPE
    stderr = subprocess.PIPE
    proc = subprocess.Popen(cmdlist, stdout=stdout, stderr=stderr)
    result, result_err = proc.communicate()
    result = result.decode('utf-8')
    if proc.returncode != 0:
        raise CommandFailed(proc.returncode, cmd, result, result_err)
    return result


class CliTestCase(BaseTestCase):
    @classmethod
    def openio(cls, cmd):
        """Executes openio CLI command."""
        return execute('openio ' + cmd)

    @classmethod
    def get_opts(cls, fields, format='value'):
        return ' -f {0} {1}'.format(
            format, ' '.join(['-c ' + it for it in fields]))

    @classmethod
    def assertOutput(cls, expected, actual):
        if expected != actual:
            raise Exception(expected + ' != ' + actual)

    def assert_show_fields(self, items, fields):
        for item in items:
            self.assertIn(item, fields)

    def assert_list_fields(self, items, fields):
        for item in items:
            for field in fields:
                self.assertIn(field, item)
