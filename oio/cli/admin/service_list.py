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
from oio.common.exceptions import ClientException


class ServiceListCommand(lister.Lister):
    """
    A command to display items of a specific service
    """

    reqid_prefix = 'ACLI-LST-'

    def __init__(self, *args, **kwargs):
        super(ServiceListCommand, self).__init__(*args, **kwargs)
        self._cids_cache = {}

    # Cliff ###########################################################

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction
        parser = super(ServiceListCommand, self).get_parser(prog_name)
        parser.add_argument(
            'service_id',
            metavar='<service_id>',
            help='ID of the service to query.'
        )
        parser.add_argument(
            '--no-paging',
            dest='no_paging',
            default=False,
            help=("List all elements without paging "
                  "(and set output format to 'value')"),
            action=ValueFormatStoreTrueAction,
        )
        return parser

    # Accessors #######################################################

    @property
    def rdir(self):
        """Get an instance of RdirClient."""
        return self.app.client_manager.rdir

    @property
    def dir(self):
        """Get an instance of DirectoryClient."""
        return self.storage.directory

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def storage(self):
        """Get an instance of ObjectStorageApi."""
        return self.app.client_manager.storage

    # Utility #########################################################

    def translate_cid(self, cid):
        """Resolve a CID into account/container names."""
        reqid = self.app.request_id(self.reqid_prefix)
        try:
            if cid not in self._cids_cache:
                md = self.dir.show(cid=cid, reqid=reqid)
                self._cids_cache[cid] = '/'.join([md.get('account'),
                                                  md.get('name')])
            return self._cids_cache[cid]
        except ClientException:
            pass
        return cid


class RawxListContainers(ServiceListCommand):
    """
    List containers having chunks stored on the specified rawx service.
    """
    reqid_prefix = 'ACLI-RLC-'

    def _list_containers(self, rawx, translate=False):
        reqid = self.app.request_id(self.reqid_prefix)
        status = self.rdir.status(rawx, reqid=reqid)
        containers = status.get('container')
        trans = self.translate_cid if translate else lambda x: x
        for cid, info in containers.iteritems():
            yield trans(cid), info['total']
        yield 'Total', status['chunk']['total']

    def get_parser(self, prog_name):
        parser = super(RawxListContainers, self).get_parser(prog_name)
        parser.add_argument(
            '--no-translation',
            action='store_true',
            help=("Do not translate container ID to "
                  "account and container names")
        )
        return parser

    def take_action(self, parsed_args):
        super(RawxListContainers, self).take_action(parsed_args)
        return (('Name', 'Chunks'),
                self._list_containers(
                    parsed_args.service_id,
                    translate=not parsed_args.no_translation))


class Meta2ListContainers(ServiceListCommand):
    """
    List containers hosted by the specified meta2 service.
    """
    reqid_prefix = 'ACLI-M2LC-'

    def get_parser(self, prog_name):
        parser = super(Meta2ListContainers, self).get_parser(prog_name)
        parser.add_argument(
            '--limit',
            metavar='<limit>',
            type=int,
            default=1000,
            help='Limit the number of results (1000 by default)'
        )
        parser.add_argument(
            '--marker',
            metavar='<marker>',
            help='Marker for paging.'
        )
        parser.add_argument(
            '--prefix',
            metavar='<prefix>',
            help='Filter the output list using <prefix>.'
        )
        return parser

    def _list_all_containers(self, meta2, prefix=None):
        reqid = self.app.request_id(self.reqid_prefix)
        for item in self.rdir.meta2_index_fetch_all(
                meta2, prefix=prefix, reqid=reqid):
            yield item['container_url']

    def _list_containers(self, meta2, **kwargs):
        reqid = self.app.request_id(self.reqid_prefix)
        resp = self.rdir.meta2_index_fetch(meta2, reqid=reqid, **kwargs)
        for item in resp.get('records'):
            yield item['container_url']

    def take_action(self, parsed_args):
        super(Meta2ListContainers, self).take_action(parsed_args)
        kwargs = {}
        if parsed_args.marker:
            kwargs['marker'] = parsed_args.marker
        if parsed_args.prefix:
            kwargs['prefix'] = parsed_args.prefix
        if parsed_args.limit:
            kwargs['limit'] = parsed_args.limit

        if parsed_args.no_paging:
            containers = self._list_all_containers(parsed_args.service_id,
                                                   prefix=parsed_args.prefix)
        else:
            containers = self._list_containers(parsed_args.service_id,
                                               **kwargs)
        return ('Name',), ((v,) for v in containers)
