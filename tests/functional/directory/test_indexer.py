# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from random import randint

from oio.rdir.client import RdirClient
from oio.directory.client import DirectoryClient
from oio.directory.indexer import Meta2IndexingWorker
from oio.container.client import ContainerClient
from oio.common.utils import cid_from_name
from tests.utils import BaseTestCase, random_str


class TestMeta2Indexing(BaseTestCase):

    def setUp(self):
        super(TestMeta2Indexing, self).setUp()
        self.rdir_client = RdirClient(self.conf)
        self.directory_client = DirectoryClient(self.conf)
        self.container_client = ContainerClient(self.conf)
        self.containers = [random_str(14) for _ in range(0, randint(1, 10))]
        self.containers_svcs = {}
        self.event_agent_name = 'event-agent-1'

    def tearDown(self):
        super(TestMeta2Indexing, self).tearDown()
        self._containers_cleanup()
        self._service(self.event_agent_name, 'start', wait=3)

    def _containers_cleanup(self):
        for container in self.containers:
            self.container_client.container_delete(self.account, container)
            for svc in self.containers_svcs[container]:
                self.rdir_client.meta2_index_delete(
                    volume_id=svc['host'],
                    container_path="{0}/{1}/{2}".format(
                        self.ns, self.account, container
                    ),
                    container_id=cid_from_name(self.account, container)
                )

    def _filter_by_managing_svc(self, all_containers,
                                svc_of_interest):
        """
        Filters through the containers returning only those that have
        svc_of_interest in their list of managing services.
        """
        containers_list = []
        for key in all_containers.keys():
            if svc_of_interest in [x['host'] for x in all_containers[key]]:
                containers_list.append(key)

        return sorted(containers_list)

    def test_volume_indexing_worker(self):
        """
        Test steps:
        - Generate a list of container names and create them
        - Collect their respective meta2 servers
        - For each meta2 server:
            - Run a meta2 indexing worker
            - List all rdir index records and match then with the
              services we're expecting.
        :return:
        """
        self._service(self.event_agent_name, "stop", wait=3)

        for container in self.containers:
            self.container_client.container_create(account=self.account,
                                                   reference=container)

        for container in self.containers:
            self.containers_svcs[container] = [x for x in
                                               self.directory_client.list(
                                                   account=self.account,
                                                   reference=container)['srv']
                                               if x['type'] == 'meta2']

        meta2_data_paths = {}
        for svc in self.conf['services']['meta2']:
            svc_host = svc.get('service_id', svc['addr'])
            meta2_data_paths[svc_host] = svc['path']

        distinct_meta2_servers = set()
        for svc_list in self.containers_svcs.values():
            for svc in svc_list:
                distinct_meta2_servers.add(svc['host'])

        for svc in distinct_meta2_servers:
            expected_containers = self._filter_by_managing_svc(
                self.containers_svcs, svc
            )
            worker = Meta2IndexingWorker(meta2_data_paths[svc], self.conf)
            worker.crawl_volume()
            indexed_containers = sorted(
                [x['container_url'].split('/')[-1] for x in
                 self.rdir_client.meta2_index_fetch_all(volume_id=svc)])

            for cont in expected_containers:
                self.assertIn(cont, indexed_containers)
