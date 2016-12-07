import os
import logging
from cliff import show
from cliff import command
from cliff import lister

from oio.cli.utils import KeyValueAction


class SetPropertyCommandMixin(object):
    """Command setting quota, storage policy or generic property"""

    def patch_parser(self, parser):
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
            help='Set the storage policy of the container'
        )


class CreateContainer(SetPropertyCommandMixin, lister.Lister):
    """Create an object container"""

    log = logging.getLogger(__name__ + '.CreateContainer')

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

        results = []
        account = self.app.client_manager.get_account()
        for container in parsed_args.containers:
            success = self.app.client_manager.storage.container_create(
                account,
                container,
                properties=properties,
                system=system)
            results.append((container, success))

        columns = ('Name', 'Created')
        res_gen = (r for r in results)
        return columns, res_gen


class SetContainer(SetPropertyCommandMixin, command.Command):
    """Set container properties, quota or storage policy"""

    log = logging.getLogger(__name__ + '.SetContainer')

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

        self.app.client_manager.storage.container_set_properties(
            self.app.client_manager.get_account(),
            parsed_args.container,
            properties,
            clear=parsed_args.clear,
            system=system
        )


class DeleteContainer(command.Command):
    """Delete an object container"""

    log = logging.getLogger(__name__ + '.DeleteContainer')

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
                self.app.client_manager.get_account(),
                container
            )


class ShowContainer(show.ShowOne):
    """Display information about an object container"""

    log = logging.getLogger(__name__ + '.ShowContainer')

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

        account = self.app.client_manager.get_account()

        data = self.app.client_manager.storage.container_show(
            account,
            parsed_args.container
        )

        sys = data['system']
        info = {'account': sys['sys.account'],
                'base_name': sys['sys.name'],
                'container': sys['sys.user.name'],
                'ctime': sys['sys.m2.ctime'],
                'bytes_usage': sys.get('sys.m2.usage', 0),
                'quota': sys.get('sys.m2.quota', "Namespace default"),
                'objects': sys.get('sys.m2.objects', 0),
                'storage_policy': sys.get('sys.m2.policy.storage',
                                          "Namespace default"),
                }
        for k, v in data['properties'].iteritems():
            info['meta.' + k] = v
        return zip(*sorted(info.iteritems()))


class ListContainer(lister.Lister):
    """List containers"""

    log = logging.getLogger(__name__ + '.ListContainer')

    def get_parser(self, prog_name):
        parser = super(ListContainer, self).get_parser(prog_name)
        parser.add_argument(
            '--full',
            dest='full_listing',
            default=False,
            help='Full listing',
            action="store_true"
        )
        parser.add_argument(
            '--prefix',
            metavar='<prefix>',
            help='Filter list using <prefix>'
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
            '--delimiter',
            metavar='<delimiter>',
            help='Delimiter'
        )
        parser.add_argument(
            '--limit',
            metavar='<limit>',
            help='Limit of results to return'
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

        account = self.app.client_manager.get_account()

        columns = ('Name', 'Bytes', 'Count')

        if parsed_args.full_listing:
            def full_list():
                l, meta = self.app.client_manager.storage.container_list(
                    account, **kwargs)
                listing = l
                for e in l:
                    yield e

                while listing:
                    kwargs['marker'] = listing[-1][0]
                    listing, meta = \
                        self.app.client_manager.storage.container_list(
                            account, **kwargs)
                    if listing:
                        for e in listing:
                            yield e

            l = full_list()
        else:
            l, meta = self.app.client_manager.storage.container_list(
                account, **kwargs)

        results = ((v[0], v[2], v[1]) for v in l)
        return columns, results


class UnsetContainer(command.Command):
    """Unset container properties"""

    log = logging.getLogger(__name__ + '.UnsetContainer')

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
            required=True
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        properties = parsed_args.property

        self.app.client_manager.storage.container_del_properties(
            self.app.client_manager.get_account(),
            parsed_args.container,
            properties)


class SaveContainer(command.Command):
    """Save all objects of a container locally"""

    log = logging.getLogger(__name__ + '.SaveContainer')

    def get_parser(self, prog_name):
        parser = super(SaveContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to save')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container
        objs = self.app.client_manager.storage.object_list(
            account, container)

        for obj in objs['objects']:
            obj_name = obj['name']
            meta, stream = self.app.client_manager.storage.object_fetch(
                account, container, obj_name)

            if not os.path.exists(os.path.dirname(obj_name)):
                if len(os.path.dirname(obj_name)) > 0:
                    os.makedirs(os.path.dirname(obj_name))
            with open(obj_name, 'wb') as f:
                for chunk in stream:
                    f.write(chunk)


class AnalyzeContainer(show.ShowOne):
    """Locate the services in charge of a container"""

    log = logging.getLogger(__name__ + '.AnalyzeContainer')

    def get_parser(self, prog_name):
        parser = super(AnalyzeContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to show'
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container

        data = self.app.client_manager.storage.container_show(
            account, container)

        data_dir = self.app.client_manager.directory.get(
            account, container)

        info = {'account': data['system']['sys.account'],
                'base_name': data['system']['sys.name'],
                'name': data['system']['sys.user.name'],
                'meta0': list(),
                'meta1': list(),
                'meta2': list()}

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
        return zip(*sorted(info.iteritems()))
