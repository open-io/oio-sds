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

import time
from random import choice

from oio.common.json import json
from oio.rdir.client import RdirDispatcher
from tests.functional.cli import CliTestCase


class ServiceDecommissionTest(CliTestCase):

    def test_rdir_decommission(self):
        """
        Test the 'openio-admin xcute rdir decommission' command actually
        decommissions an rdir service.
        """
        if len(self.conf['services']['rdir']) < 5:
            self.skip('This test requires at least 5 rdir services')

        dispatcher = RdirDispatcher(self.conf, logger=self.logger)
        rawx_per_rdir = dispatcher.get_aggregated_assignments('rawx')
        not_empty = {k: v for k, v in rawx_per_rdir.items()
                     if len(v) > 0}
        candidate = choice(list(not_empty.keys()))

        opts = self.get_format_opts(fields=['job.id'])
        job_id = self.openio_admin('xcute rdir decommission %s %s' % (
            candidate, opts))
        attempts = 5
        status = None
        opts = self.get_format_opts('json')
        for _ in range(attempts):
            res = self.openio_admin('xcute job show %s %s' % (job_id, opts))
            decoded = json.loads(res)
            status = decoded['job.status']
            if status == "FINISHED":
                break
            time.sleep(1)
        else:
            self.fail("xcute job %s did not finish within %ds" % (
                job_id, attempts))

        # We did not specify any type when decommissionning,
        # expect everything to be empty.
        rawx_per_rdir = dispatcher.get_aggregated_assignments('rawx')
        m2_per_rdir = dispatcher.get_aggregated_assignments('meta2')
        self.assertEqual(0, len(rawx_per_rdir[candidate]))
        self.assertEqual(0, len(m2_per_rdir[candidate]))
