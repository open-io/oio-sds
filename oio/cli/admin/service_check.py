# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from cliff import lister

from oio.conscience.client import ConscienceClient


class BaseCheckCommand(lister.Lister):
    """
    Base class for all check commands.
    """

    def __init__(self, *args, **kwargs):
        super(BaseCheckCommand, self).__init__(*args, **kwargs)
        self._zkcnxstr = None
        self.catalog = None
        self.live = None

    def get_parser(self, prog_name):
        parser = super(BaseCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            '--catalog',
            type=str,
            help="Load catalog from file."
        )
        return parser

    def load_catalog(self, parsed_args):
        # Load the live services
        self.live = self.load_live_services()
        self.live = tuple(self.live)
        self.logger.info("Catalog: Loaded %d services", len(self.live))
        for t, i, p, s in self.live:
            self.logger.debug("live> %s %s %d score=%d", t, i, p, s)

        # Load a catalog of expected services
        self.catalog = list()
        if parsed_args.catalog:
            self.catalog = self.load_catalog_from_file(parsed_args.catalog)
        else:
            for t, i, p, s in self.live:
                self.catalog.append((t, i, p, s))
        self.catalog = tuple(self.catalog)
        self.logger.info("Catalog: Loaded %d services", len(self.catalog))
        for t, i, p, s in self.catalog:
            self.logger.debug("catalog> %s %s %d", t, i, p)

    @staticmethod
    def filter_services(srv, srvtype):
        for t, i, p, s in srv:
            if t == srvtype:
                yield t, i, p, s

    def load_live_services(self):
        client = ConscienceClient({"namespace": self.app.options.ns})
        for srvtype in client.service_types():
            for srv in client.all_services(srvtype):
                ip, port = srv['addr'].split(':')
                yield str(srvtype), str(ip), int(port), int(srv['score'])

    def load_catalog_from_file(self, path):
        with open(path, "r") as fin:
            for line in fin:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    t, i, p = line.split()
                    yield str(t), str(i), int(p), 0
                except Exception as ex:
                    self.logger.exception("Failed to loadthe NS services: %s",
                                          ex)

    @property
    def logger(self):
        return self.app.client_manager.logger

    def zookeeper(self):
        if self._zkcnxstr:
            return self._zkcnxstr

        print(self.app.client_manager.sds_conf['zookeeper'])
        conf = self.app.client_manager.sds_conf
        self._zkcnxstr = conf.get('zookeeper.%s' % self.SRV,
                                  conf.get('zookeeper'))
        return self._zkcnxstr


class Meta0Check(BaseCheckCommand):
    SRV = 'meta0'

    def take_action(self, parsed_args):
        super(Meta0Check, self).take_action(parsed_args)
        self.load_catalog(parsed_args)
        import zookeeper
        from oio.zk.client import get_meta0_paths, get_connected_handles
        self.logger.debug("Checking the META0 services")

        # TODO: tcp touch to the meta0 services

        # check they are registered in the ZK
        for zh in get_connected_handles(self.zookeeper()):
            for p in get_meta0_paths(zh, self.app.options.ns):
                try:
                    registered = set()
                    for n in zookeeper.get_children(zh.get(), p):
                        v, m = zookeeper.get(zh.get(), p + '/' + n)
                        registered.add(v)
                    known = set()
                    for t, i, p, s in self.filter_services(self.catalog,
                                                           'meta0'):
                        known.add('%s:%d' % (i, p))
                    self.logger.info("meta0 known=%d zk_registered=%d",
                                     len(known), len(registered))
                    assert registered == known
                except Exception as ex:
                    self.logger.exception(
                            "Failed to list the M0 from the ZK: %s", ex)
                finally:
                    zh.close()

        return ('Status',), [('Ok', )]


class Meta1Check(BaseCheckCommand):
    SRV = 'meta1'

    def take_action(self, parsed_args):
        super(Meta1Check, self).take_action(parsed_args)
        self.load_catalog(parsed_args)

        # All the services must have been declared
        c0 = list(self.filter_services(self.catalog, self.SRV))
        l0 = list(self.filter_services(self.live, self.SRV))
        assert len(c0) == len(l0)
        self.logger.info("All the META1 are alive")

        # They also need a positive score
        for _, _, _, m1_score in l0:
            assert m1_score > 0
        self.logger.info("All the META1 have a positive score")
        return ('Status',), [('Ok', )]


class DirCheck(BaseCheckCommand):
    def take_action(self, parsed_args):
        super(DirCheck, self).take_action(parsed_args)
        self.load_catalog(parsed_args)
        import subprocess
        from oio.directory.meta0 import Meta0Client
        from oio.common.json import json

        self.logger.debug("Checking the directory bootstrap")

        # Get an official dump from the proxy, check its size
        m0 = Meta0Client({"namespace": self.app.options.ns})
        prefixes = m0.list()
        assert len(prefixes) == 65536
        self.logger.info("The proxy serves a full META0 dump")

        # contact each M0 to perform a check: any "get" command will
        # fail if the meta0 is not complete. Unfortunately we just have
        # oio-meta0-client to target a specific service.
        for t, i, p, s in self.filter_services(self.catalog, 'meta0'):
            url = '%s:%d' % (i, p)
            subprocess.check_call(['oio-meta0-client', url, 'get', '0000'])
        self.logger.info("All the META0 are complete")

        # contact each meta0 to check that all the dumps are identical
        dump0 = None
        for t, i, p, s in self.filter_services(self.catalog, 'meta0'):
            url = '%s:%d' % (i, p)
            dump = subprocess.check_output(['oio-meta0-client', url, 'list'])
            if dump0 is None:
                dump0 = dump
            else:
                assert dump0 == dump
        self.logger.info("All the META0 are the same")

        # Check all the meta1 are concerned
        reverse_dump = set()
        for _, v in json.loads(dump0).iteritems():
            for url in v:
                reverse_dump.add(url)
        m1 = list(self.filter_services(self.catalog, 'meta1'))
        assert len(m1) == len(reverse_dump)
        self.logger.info("All the META1 have been assigned")
        return ('Status', ), [('Ok', )]


class RdirCheck(BaseCheckCommand):
    def take_action(self, parsed_args):
        super(RdirCheck, self).take_action(parsed_args)
        self.load_catalog(parsed_args)
        from oio.rdir.client import RdirDispatcher

        self.logger.debug("Checking the RDIR services")

        # Load the assigned rdir services
        client = RdirDispatcher({"namespace": self.app.options.ns})
        all_rawx, all_rdir = client.get_assignments('rawx')
        assert not any(r['rdir'] is None for r in all_rawx)
        self.logger.info("All the RAWX have a RDIR assigned")

        # Compare with the number of expected services
        l0 = list(self.filter_services(self.live, 'rdir'))
        c0 = list(self.filter_services(self.catalog, 'rdir'))
        assert len(l0) == len(c0)
        assert len(l0) == len(all_rdir)
        self.logger.info("All the RDIR are alive")
        return ('Status', ), [('Ok', )]

        # TODO(mbo) Check all the meta2 have a RDIR assigned
