# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
# Copyright (C) 2024 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

import uuid
from tempfile import NamedTemporaryFile
from tests.functional.cli import CliTestCase


class LifecycleCliTest(CliTestCase):
    """Functional tests for container lifecycle CLI."""

    NAME = uuid.uuid4().hex

    CONF = """
    {"Rules": [{"ID": "id1", "Status": "Enabled",
        "Filter": {"And": {"ObjectSizeGreaterThan": 101, "Prefix": "test"}},
        "Expiration": {"Days": 11}}]
    }"""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        opts = cls.get_opts(["Name"])
        output = cls.openio("container create " + cls.NAME + opts)
        cls.assertOutput(cls.NAME + "\n", output)

    @classmethod
    def tearDownClass(cls):
        output = cls.openio("container delete " + cls.NAME)
        cls.assertOutput("", output)
        super().tearDownClass()

    def test_lifecycle_set(self):
        self.openio("lifecycle set %s '%s'" % (self.NAME, self.CONF))

    def test_lifecycle_set_file(self):
        with NamedTemporaryFile() as file_:
            file_.write(self.CONF.encode("utf-8"))
            file_.flush()
            self.openio("lifecycle set %s --from-file %s" % (self.NAME, file_.name))

    def test_lifecycle_get(self):
        self.openio("lifecycle set %s '%s'" % (self.NAME, self.CONF))
        output = self.openio("lifecycle get " + self.NAME)
        self.assertEqual(
            self.CONF.replace(" ", "").replace("\n", ""),
            output.replace(" ", "").replace("\n", ""),
        )
