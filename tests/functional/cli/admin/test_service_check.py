# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022 OVH SAS
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

from oio.common.utils import request_id
from oio.event.evob import EventTypes

from tests.utils import random_str
from tests.functional.cli import CliTestCase


class ServiceCheckTest(CliTestCase):
    def test_rawx_check(self):
        """
        Perform basic tests of the 'openio-admin rawx check' command.
        """
        container = "rawx-check-" + random_str(6)
        obj = container + "obj-" + random_str(6)
        # Upload an object (replicated or not).
        reqid = request_id()
        self.storage.object_create(
            self.account, container, data="test data", obj_name=obj, reqid=reqid
        )
        output = self.storage.object_locate(self.account, container, obj)
        for _ in range(1 + len(output[1])):
            self.wait_for_event(
                "oio-preserved",
                reqid=reqid,
                types=(EventTypes.CONTAINER_STATE, EventTypes.CHUNK_NEW),
            )
        opts = self.get_format_opts(fields=["Chunk"])
        # Iterate over all rawx services hosting one of the chunks,
        # expect to find the chunks.
        rawx_list = [(x["url"][7:-65], x["url"]) for x in output[1]]
        for rawx in rawx_list:
            # Return code may be 1 if chunks uploaded by previous tests
            # show issues.
            output = self.openio_admin(
                "rawx check %s %s" % (rawx[0], opts), expected_returncode=(0, 1)
            )
            self.assertIn(rawx[1], output.split("\n"))

        # Delete the object.
        reqid = request_id()
        self.storage.object_delete(self.account, container, obj, reqid=reqid)
        for _ in range(1 + len(output[1])):
            self.wait_for_event(
                "oio-preserved",
                reqid=reqid,
                types=(EventTypes.CONTAINER_STATE, EventTypes.CHUNK_DELETED),
            )
        # Iterate over all rawx services hosting one of the chunks,
        # expect NOT to find the chunks.
        for rawx in rawx_list:
            output = self.openio_admin(
                "rawx check %s %s" % (rawx, opts), expected_returncode=(0, 1)
            )
            self.assertNotIn(rawx[1], output.split("\n"))
