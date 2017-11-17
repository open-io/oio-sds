# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

"""Container-related commands"""

from six import iteritems
from logging import getLogger
from cliff import command, show, lister
from time import time
from oio.common.timestamp import Timestamp
from oio.common.constants import OIO_DB_STATUS_NAME


class SetPropertyCommandMixin(object):
    """Command setting quota, storage policy or generic property"""

    def patch_parser(self, parser):
        from oio.cli.common.utils import KeyValueAction

        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add/update for the container(s)'
        )
        parser.add_argument(
            '--quota',
            metavar='<bytes>',
            type=int,
            help='Set the quota on the container'
        )
        parser.add_argument(
            '--storage-policy', '--stgpol',
            metavar='<storage_policy>',
            help='Set the storage policy of the container'
        )
        parser.add_argument(
            '--max-versions', '--versioning',
            metavar='<n>',
            type=int,
            help="""Set the versioning policy of the container.
 n<0 is unlimited number of versions.
 n=0 is disabled (cannot overwrite existing object).
 n=1 is suspended (can overwrite existing object).
 n>1 is maximum n versions.
"""
        )


class CreateContainer(SetPropertyCommandMixin, lister.Lister):
    """Create an object container."""

    log = getLogger(__name__ + '.CreateContainer')

    def get_parser(self, prog_name):
        parser = super(CreateContainer, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'containers',
            metavar='<container-name>',
            nargs='+',
            help='New container name(s)'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        properties = parsed_args.property
        system = dict()
        if parsed_args.quota is not None:
            system['sys.m2.quota'] = str(parsed_args.quota)
        if parsed_args.storage_policy is not None:
            system['sys.m2.policy.storage'] = parsed_args.storage_policy
        if parsed_args.max_versions is not None:
            system['sys.m2.policy.version'] = str(parsed_args.max_versions)

        results = []
        account = self.app.client_manager.account
        if len(parsed_args.containers) > 1:
            results = self.app.client_manager.storage.container_create_many(
                account,
                parsed_args.containers,
                properties=properties,
                system=system)

        else:
            for container in parsed_args.containers:
                success = self.app.client_manager.storage.container_create(
                    account,
                    container,
                    properties=properties,
                    system=system)
                results.append((container, success))

        return ('Name', 'Created'), (r for r in results)


class SetContainer(SetPropertyCommandMixin, command.Command):
    """Set container properties, quota, storage policy or versioning."""

    log = getLogger(__name__ + '.SetContainer')

    def get_parser(self, prog_name):
        parser = super(SetContainer, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to modify'
        )
        parser.add_argument(
            '--clear',
            dest='clear',
            default=False,
            help='Clear previous properties',
            action="store_true"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        properties = parsed_args.property
        system = dict()
        if parsed_args.quota is not None:
            system['sys.m2.quota'] = str(parsed_args.quota)
        if parsed_args.storage_policy is not None:
            system['sys.m2.policy.storage'] = parsed_args.storage_policy
        if parsed_args.max_versions is not None:
            system['sys.m2.policy.version'] = str(parsed_args.max_versions)

        self.app.client_manager.storage.container_set_properties(
            self.app.client_manager.account,
            parsed_args.container,
            properties,
            clear=parsed_args.clear,
            system=system
        )


class TouchContainer(command.Command):
    """Touch an object container, triggers asynchronous treatments on it."""

    log = getLogger(__name__ + '.TouchContainer')

    def get_parser(self, prog_name):
        parser = super(TouchContainer, self).get_parser(prog_name)
        parser.add_argument(
            'containers',
            metavar='<container>',
            nargs='+',
            help='Container(s) to delete'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        for container in parsed_args.containers:
            self.app.client_manager.storage.container_touch(
                self.app.client_manager.account,
                container
            )


class DeleteContainer(command.Command):
    """Delete an object container."""

    log = getLogger(__name__ + '.DeleteContainer')

    def get_parser(self, prog_name):
        parser = super(DeleteContainer, self).get_parser(prog_name)
        parser.add_argument(
            'containers',
            metavar='<container>',
            nargs='+',
            help='Container(s) to delete'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        for container in parsed_args.containers:
            self.app.client_manager.storage.container_delete(
                self.app.client_manager.account,
                container
            )


class ShowContainer(show.ShowOne):
    """Display information about an object container."""

    log = getLogger(__name__ + '.ShowContainer')

    def get_parser(self, prog_name):
        parser = super(ShowContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Name of the container to display information about'
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account

        # The command is named 'show' but we must call
        # container_get_properties() because container_show() does
        # not return system properties (and we need them).
        data = self.app.client_manager.storage.container_get_properties(
            account,
            parsed_args.container
        )

        sys = data['system']
        ctime = float(sys['sys.m2.ctime']) / 1000000.
        bytes_usage = sys.get('sys.m2.usage', 0)
        objects = sys.get('sys.m2.objects', 0)
        if parsed_args.formatter == 'table':
            from oio.common.easy_value import convert_size

            ctime = int(ctime)
            bytes_usage = convert_size(int(bytes_usage), unit="B")
            objects = convert_size(int(objects))
        info = {
            'account': sys['sys.account'],
            'base_name': sys['sys.name'],
            'container': sys['sys.user.name'],
            'ctime': ctime,
            'bytes_usage': bytes_usage,
            'quota': sys.get('sys.m2.quota', "Namespace default"),
            'objects': objects,
            'storage_policy': sys.get('sys.m2.policy.storage',
                                      "Namespace default"),
            'max_versions': sys.get('sys.m2.policy.version',
                                    "Namespace default"),
            'status': OIO_DB_STATUS_NAME.get(sys.get('sys.status'), "Unknown"),
        }
        for k, v in iteritems(data['properties']):
            info['meta.' + k] = v
        return list(zip(*sorted(info.items())))


class ListContainer(lister.Lister):
    """List containers."""

    log = getLogger(__name__ + '.ListContainer')

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListContainer, self).get_parser(prog_name)
        parser.add_argument(
            '--prefix',
            metavar='<prefix>',
            help='Filter list using <prefix>'
        )
        parser.add_argument(
            '--delimiter',
            metavar='<delimiter>',
            help='Delimiter'
        )
        parser.add_argument(
            '--marker',
            metavar='<marker>',
            help='Marker for paging'
        )
        parser.add_argument(
            '--end-marker',
            metavar='<end-marker>',
            help='End marker for paging'
        )
        parser.add_argument(
            '--limit',
            metavar='<limit>',
            help='Limit the number of containers returned'
        )
        parser.add_argument(
            '--no-paging', '--full',
            dest='full_listing',
            default=False,
            help=("List all containers without paging "
                  "(and set output format to 'value')"),
            action=ValueFormatStoreTrueAction
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        kwargs = {}
        if parsed_args.prefix:
            kwargs['prefix'] = parsed_args.prefix
        if parsed_args.marker:
            kwargs['marker'] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs['end_marker'] = parsed_args.end_marker
        if parsed_args.delimiter:
            kwargs['delimiter'] = parsed_args.delimiter
        if parsed_args.limit:
            kwargs['limit'] = parsed_args.limit

        account = self.app.client_manager.account

        if parsed_args.full_listing:
            def full_list():
                listing = self.app.client_manager.storage.container_list(
                    account, **kwargs)
                for element in listing:
                    yield element

                while listing:
                    kwargs['marker'] = listing[-1][0]
                    listing = self.app.client_manager.storage.container_list(
                        account, **kwargs)
                    if listing:
                        for element in listing:
                            yield element

            listing = full_list()
        else:
            listing = self.app.client_manager.storage.container_list(
                account, **kwargs)

        columns = ('Name', 'Bytes', 'Count')
        return columns, ((v[0], v[2], v[1]) for v in listing)


class UnsetContainer(command.Command):
    """Unset container properties."""

    log = getLogger(__name__ + '.UnsetContainer')

    def get_parser(self, prog_name):
        parser = super(UnsetContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to modify'
        )
        parser.add_argument(
            '--property',
            metavar='<key>',
            action='append',
            default=[],
            help='Property to remove from container',
        )
        parser.add_argument(
            '--storage-policy', '--stgpol',
            action='store_true',
            help='Reset the storage policy of the container '
                 'to the namespace default'
        )
        parser.add_argument(
            '--max-versions', '--versioning',
            action='store_true',
            help='Reset the versioning policy of the container '
                 'to the namespace default'
        )
        parser.add_argument(
            '--quota',
            action='store_true',
            help='Reset the quota of the container '
                 'to the namespace default'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        properties = parsed_args.property
        system = dict()
        if parsed_args.storage_policy:
            system['sys.m2.policy.storage'] = ''
        if parsed_args.max_versions:
            system['sys.m2.policy.version'] = ''
        if parsed_args.quota:
            system['sys.m2.quota'] = ''

        if properties:
            self.app.client_manager.storage.container_del_properties(
                self.app.client_manager.account,
                parsed_args.container,
                properties)
        if system:
            self.app.client_manager.storage.container_set_properties(
                self.app.client_manager.account,
                parsed_args.container,
                system=system)


class SaveContainer(command.Command):
    """Save all objects of a container locally."""

    log = getLogger(__name__ + '.SaveContainer')

    def get_parser(self, prog_name):
        parser = super(SaveContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to save')
        return parser

    def take_action(self, parsed_args):
        import os

        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container
        objs = self.app.client_manager.storage.object_list(
            account, container)

        for obj in objs['objects']:
            obj_name = obj['name']
            _, stream = self.app.client_manager.storage.object_fetch(
                account, container, obj_name)

            if not os.path.exists(os.path.dirname(obj_name)):
                if len(os.path.dirname(obj_name)) > 0:
                    os.makedirs(os.path.dirname(obj_name))
            with open(obj_name, 'wb') as f:
                for chunk in stream:
                    f.write(chunk)


class LocateContainer(show.ShowOne):
    """Locate the services in charge of a container."""

    log = getLogger(__name__ + '.LocateContainer')

    def get_parser(self, prog_name):
        parser = super(LocateContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to show'
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container

        data = self.app.client_manager.storage.container_get_properties(
            account, container)

        data_dir = self.app.client_manager.storage.directory.list(
            account, container)

        info = {
            'account': data['system']['sys.account'],
            'base_name': data['system']['sys.name'],
            'name': data['system']['sys.user.name'],
            'meta0': list(),
            'meta1': list(),
            'meta2': list(),
            'status': OIO_DB_STATUS_NAME.get(data['system'].get('sys.status'),
                                             "Unknown"),
        }

        for d in data_dir['srv']:
            if d['type'] == 'meta2':
                info['meta2'].append(d['host'])

        for d in data_dir['dir']:
            if d['type'] == 'meta0':
                info['meta0'].append(d['host'])
            if d['type'] == 'meta1':
                info['meta1'].append(d['host'])

        for stype in ["meta0", "meta1", "meta2"]:
            info[stype] = ', '.join(info[stype])
        return list(zip(*sorted(info.items())))


class PurgeContainer(command.Command):
    """Purge exceeding object versions."""

    log = getLogger(__name__ + '.PurgeContainer')

    def get_parser(self, prog_name):
        parser = super(PurgeContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to purge',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account
        self.app.client_manager.storage.container.container_purge(
            account, parsed_args.container
        )


class RefreshContainer(command.Command):
    """ Refresh counters of an account (triggers asynchronous treatments) """

    log = getLogger(__name__ + '.RefreshContainer')

    def get_parser(self, prog_name):
        parser = super(RefreshContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to refresh',
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account
        self.app.client_manager.storage.container_refresh(
            account=account,
            container=parsed_args.container
        )


class SnapshotContainer(lister.Lister):
    """
    Take a snapshot of a container.

    Create a separate database containing all information about the contents
    from the original database, but with copies of the chunks at the time
    of the snapshot. This new database is not replicated.
    """

    log = getLogger(__name__ + '.SnapshotContainer')

    def get_parser(self, prog_name):
        parser = super(SnapshotContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to snapshot'
        )
        parser.add_argument(
            '--dst-account',
            metavar='<account>',
            help=('The account where the snapshot should be created. '
                  'By default the same account as the snapshotted container.')
        )
        parser.add_argument(
            '--dst-container',
            metavar='<container>',
            help=('The name of the container hosting the snapshot. '
                  'By default the name of the snapshotted container '
                  'suffixed by a timestamp.')
        )
        parser.add_argument(
            '--chunk-batch-size',
            metavar='<size>',
            default=100,
            help=('The number of chunks updated at the same time.')
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container
        dst_account = parsed_args.dst_account or account
        dst_container = (parsed_args.dst_container or
                         (container + "-" + Timestamp(time()).normal))
        batch = parsed_args.chunk_batch_size

        self.app.client_manager.storage.container_snapshot(
            account, container, dst_account, dst_container, batch=batch)
        lines = [(dst_account, dst_container, "OK")]
        return ('Account', 'Container', 'Status'), lines
