import os
import logging
from cliff import show
from cliff import command
from cliff import lister

from oio.cli.utils import KeyValueAction


class CreateContainer(lister.Lister):
    """Create container"""

    log = logging.getLogger(__name__ + '.CreateContainer')

    def get_parser(self, prog_name):
        parser = super(CreateContainer, self).get_parser(prog_name)
        parser.add_argument(
            'containers',
            metavar='<container-name>',
            nargs='+',
            help='New container name(s)'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        results = []
        account = self.app.client_manager.get_account()
        for container in parsed_args.containers:
            success = self.app.client_manager.storage.container_create(
                account,
                container)
            results.append((container, success))

        columns = ('Name', 'Created')
        l = (r for r in results)
        return columns, l


class SetContainer(command.Command):
    """Set container properties"""

    log = logging.getLogger(__name__ + '.SetContainer')

    def get_parser(self, prog_name):
        parser = super(SetContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to modify'
        )
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add/update for this container'
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

        properties = {}
        for k, v in parsed_args.property.iteritems():
            properties['user.%s' % k] = v

        self.app.client_manager.storage.container_set_properties(
            self.app.client_manager.get_account(),
            parsed_args.container,
            properties,
            clear=parsed_args.clear
        )


class DeleteContainer(command.Command):
    """Delete container"""

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
    """Show container"""

    log = logging.getLogger(__name__ + '.ShowContainer')

    def get_parser(self, prog_name):
        parser = super(ShowContainer, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to show'
        )

        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.get_account()

        data = self.app.client_manager.storage.container_show(
            account,
            parsed_args.container
        )

        info = {'account': data['sys.account'],
                'base_name': data['sys.name'],
                'container': data['sys.user.name'],
                'ctime': data['sys.m2.ctime'],
                'bytes_usage': data.get('sys.m2.usage', 0)}
        for k, v in data.iteritems():
            if k.startswith('user.'):
                info['meta.' + k[len('meta.'):]] = v
        return zip(*sorted(info.iteritems()))


class ListContainer(lister.Lister):
    """List container"""

    log = logging.getLogger(__name__ + '.ListContainer')

    def get_parser(self, prog_name):
        parser = super(ListContainer, self).get_parser(prog_name)

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

        l, meta = self.app.client_manager.storage.container_list(
            self.app.client_manager.get_account(),
            **kwargs
        )

        columns = ('Name', 'Bytes', 'Count')

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

        properties = []
        for p in parsed_args.property:
            properties.append('user.%s' % p)

        self.app.client_manager.storage.container_del_properties(
            self.app.client_manager.get_account(),
            parsed_args.container,
            properties)


class SaveContainer(command.Command):
    """Save container locally"""

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
    """Analyze container"""

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

        info = {'account': data['sys.account'],
                'base_name': data['sys.name'],
                'name': data['sys.user.name'],
                'meta2': []}
        for d in data_dir['srv']:
            if d['type'] == 'meta2':
                info['meta2'].append(d['host'])

        info['meta2'] = ', '.join(s for s in info['meta2'])
        return zip(*sorted(info.iteritems()))
