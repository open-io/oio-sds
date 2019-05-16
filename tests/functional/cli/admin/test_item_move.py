# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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


import random

from oio.common.utils import cid_from_name
from tests.functional.cli import CliTestCase
from tests.utils import random_str


class ItemMoveTest(CliTestCase):
    """Functionnal tests for item to move."""

    def setUp(self):
        super(ItemMoveTest, self).setUp()
        self.container = "item_move_" + random_str(4)
        self.meta2_services = self.conf['services']['meta2']

    def test_container_move_without_dst(self):
        opts = self.get_opts(['Name'])
        output = self.openio('container create %s %s'
                             % (self.container, opts))
        self.assertOutput('%s\n' % self.container, output)

        opts = self.get_opts(['meta2'])
        output = self.openio('container locate %s %s'
                             % (self.container, opts))
        current_peers = output.rstrip('\n').split(', ')

        if len(current_peers) >= len(self.meta2_services):
            self.skipTest("need at least 1 more meta2")

        src = random.choice(current_peers)
        opts = self.get_opts(['Container', 'Source', 'Status'])
        output = self.openio_admin('container move %s --src %s %s'
                                   % (self.container, src, opts))
        self.assertOutput('%s %s OK\n' % (self.container, src), output)

    def test_container_move_with_dst(self):
        opts = self.get_opts(['Name'])
        output = self.openio('container create %s %s'
                             % (self.container, opts))
        self.assertOutput('%s\n' % self.container, output)

        opts = self.get_opts(['meta2'])
        output = self.openio('container locate %s %s'
                             % (self.container, opts))
        current_peers = output.rstrip('\n').split(', ')

        if len(current_peers) >= len(self.meta2_services):
            self.skipTest("need at least 1 more meta2")

        for service in self.meta2_services:
            service_id = service.get('service_id')
            if service_id is None:
                service_id = service['addr']
            if service_id not in current_peers:
                dst = service_id

        src = random.choice(current_peers)
        opts = self.get_opts(['Container', 'Source', 'Destination', 'Status'])
        output = self.openio_admin('container move %s --src %s --dst %s %s'
                                   % (self.container, src, dst, opts))
        self.assertOutput('%s %s %s OK' % (self.container, src, dst),
                          output.rstrip())

    def test_container_move_with_error(self):
        opts = self.get_opts(['Name'])
        output = self.openio('container create %s %s'
                             % (self.container, opts))
        self.assertOutput('%s\n' % self.container, output)

        opts = self.get_opts(['meta2'])
        output = self.openio('container locate %s %s'
                             % (self.container, opts))
        current_peers = output.rstrip('\n').split(', ')

        if len(current_peers) >= len(self.meta2_services):
            self.skipTest("need at least 1 more meta2")

        src = '127.0.0.1:666'
        opts = self.get_opts(['Container', 'Source', 'Status'])
        output = self.openio_admin(
            'container move %s --src %s %s' % (self.container, src, opts),
            expected_returncode=1)
        self.assertOutput('%s %s error' % (self.container, src),
                          output.rstrip())

    def test_container_move_with_several_containers(self):
        opts = self.get_opts(['Name'])
        output = self.openio('container create %s %s'
                             % (self.container, opts))
        self.assertOutput('%s\n' % self.container, output)

        opts = self.get_opts(['meta2'])
        output = self.openio('container locate %s %s'
                             % (self.container, opts))
        current_peers = output.rstrip('\n').split(', ')

        if len(current_peers) >= len(self.meta2_services):
            self.skipTest("need at least 1 more meta2")

        container_bis = self.container + '_bis'
        opts = self.get_opts(['Name'])
        output = self.openio('container create %s %s'
                             % (container_bis, opts))
        self.assertOutput('%s\n' % container_bis, output)

        opts = self.get_opts(['meta2'])
        output = self.openio('container locate %s %s'
                             % (container_bis, opts))
        current_peers_bis = output.rstrip('\n').split(', ')

        intersection = [value for value in current_peers
                        if value in current_peers_bis]
        if not intersection:
            self.skipTest("No service in common")

        src = random.choice(intersection)
        opts = self.get_opts(['Container', 'Source', 'Status'])
        output = self.openio_admin(
            'container move %s %s --src %s %s'
            % (self.container, container_bis, src, opts))
        self.assertOutput('%s %s OK\n%s %s OK\n'
                          % (self.container, src, container_bis, src), output)

    def test_container_move_with_cid(self):
        account = 'test_container_move_with_cid'

        opts = self.get_opts(['Name'])
        output = self.openio(
            'container --oio-account %s create %s %s'
            % (account, self.container, opts))
        self.assertOutput('%s\n' % self.container, output)

        opts = self.get_opts(['meta2'])
        output = self.openio(
            'container --oio-account %s locate %s %s'
            % (account, self.container, opts))
        current_peers = output.rstrip('\n').split(', ')

        if len(current_peers) >= len(self.meta2_services):
            self.skipTest("need at least 1 more meta2")

        cid = cid_from_name(account, self.container)
        src = random.choice(current_peers)
        opts = self.get_opts(['Container', 'Source', 'Status'])
        output = self.openio_admin('container move %s --cid --src %s %s'
                                   % (cid, src, opts))
        self.assertOutput('%s %s OK\n' % (self.container, src), output)
