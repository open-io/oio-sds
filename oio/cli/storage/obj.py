import io
import logging
import os

from cliff import command
from cliff import lister
from cliff import show

from oio.cli.utils import KeyValueAction


class CreateObject(lister.Lister):
    """Upload object"""

    log = logging.getLogger(__name__ + '.CreateObject')

    def get_parser(self, prog_name):
        parser = super(CreateObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container for new object'
        )
        parser.add_argument(
            'objects',
            metavar='<filename>',
            nargs='+',
            help='Local filename(s) to upload'
        )
        parser.add_argument(
            '--name',
            metavar='<key>',
            default=[],
            action='append',
            help='Object name to create'
        )
        parser.add_argument(
            '--policy',
            metavar='<policy>',
            help='Storage Policy'
        )
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add/update to the object(s)'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='File containing application keys'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        container = parsed_args.container
        policy = parsed_args.policy
        objs = parsed_args.objects
        names = parsed_args.name
        key_file = parsed_args.key_file
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file

        def get_file_size(f):
            currpos = f.tell()
            f.seek(0, 2)
            total_size = f.tell()
            f.seek(currpos)
            return total_size

        properties = parsed_args.property
        results = []
        for obj in objs:
            with io.open(obj, 'rb') as f:
                name = names.pop(0) if names else os.path.basename(f.name)
                data = self.app.client_manager.storage.object_create(
                    self.app.client_manager.get_account(),
                    container,
                    file_or_path=f,
                    obj_name=name,
                    content_length=get_file_size(f),
                    policy=policy,
                    metadata=properties,
                    key_file=key_file)

                results.append((name, data[1], data[2].upper()))

        l = (obj for obj in results)
        columns = ('Name', 'Size', 'Hash')
        return columns, l


class DeleteObject(command.Command):
    """Delete object from container"""

    log = logging.getLogger(__name__ + '.DeleteObject')

    def get_parser(self, prog_name):
        parser = super(DeleteObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Delete object(s) from <container>'
        )
        parser.add_argument(
            'objects',
            metavar='<object>',
            nargs='+',
            help='Object(s) to delete'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        container = parsed_args.container

        for obj in parsed_args.objects:
            self.app.client_manager.storage.object_delete(
                self.app.client_manager.get_account(),
                container,
                obj
            )


class ShowObject(show.ShowOne):
    """Show object"""

    log = logging.getLogger(__name__ + '.ShowObject')

    def get_parser(self, prog_name):
        parser = super(ShowObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container'
        )
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Object'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container
        obj = parsed_args.object

        data = self.app.client_manager.storage.object_show(
            account,
            container,
            obj)
        info = {'account': account,
                'container': container,
                'object': obj,
                'id': data['id'],
                'version': data['version'],
                'mime-type': data['mime-type'],
                'size': data['length'],
                'hash': data['hash'],
                'ctime': data['ctime'],
                'policy': data['policy']}
        for k, v in data['properties'].iteritems():
            info['meta.' + k] = v
        return zip(*sorted(info.iteritems()))


class SetObject(command.Command):
    """Set object properties"""

    log = logging.getLogger(__name__ + '.SetObject')

    def get_parser(self, prog_name):
        parser = super(SetObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container'
        )
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Object')
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add to this object'
        )
        parser.add_argument(
            '--clear',
            default=False,
            help='Clear previous properties',
            action='store_true')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        container = parsed_args.container
        obj = parsed_args.object
        properties = parsed_args.property
        self.app.client_manager.storage.object_set_properties(
            self.app.client_manager.get_account(),
            container,
            obj,
            properties,
            parsed_args.clear)


class SaveObject(command.Command):
    """Save object locally"""

    log = logging.getLogger(__name__ + '.SaveObject')

    def get_parser(self, prog_name):
        parser = super(SaveObject, self).get_parser(prog_name)
        parser.add_argument(
            '--file',
            metavar='<filename>',
            help='Destination filename (defaults to object name)'
        )
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Download <object> from <container>'
        )
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Object to save'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='file containing the keys'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        container = parsed_args.container
        obj = parsed_args.object
        key_file = parsed_args.key_file
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file
        filename = parsed_args.file
        if not filename:
            filename = obj

        meta, stream = self.app.client_manager.storage.object_fetch(
            self.app.client_manager.get_account(),
            container,
            obj,
            key_file=key_file
        )
        if not os.path.exists(os.path.dirname(filename)):
            if len(os.path.dirname(filename)) > 0:
                os.makedirs(os.path.dirname(filename))
        with open(filename, 'wb') as ofile:
            for chunk in stream:
                ofile.write(chunk)


class ListObject(lister.Lister):
    """List objects in container"""

    log = logging.getLogger(__name__ + '.ListObject')

    def get_parser(self, prog_name):
        parser = super(ListObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container to list'
        )
        parser.add_argument(
            '--prefix',
            metavar='<prefix>',
            help='Filter list using <prefix>'
        )
        parser.add_argument(
            '--delimiter',
            metavar='<delimiter>',
            help='Filter list using <delimiter>'
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
            help='Limit the number of objects returned'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        container = parsed_args.container

        resp = self.app.client_manager.storage.object_list(
            self.app.client_manager.get_account(),
            container,
            limit=parsed_args.limit,
            marker=parsed_args.marker,
            end_marker=parsed_args.end_marker,
            prefix=parsed_args.prefix,
            delimiter=parsed_args.delimiter
        )
        l = resp['objects']
        results = ((obj['name'], obj['size'], obj['hash']) for obj in l)
        columns = ('Name', 'Size', 'Hash')
        return (columns, results)


class UnsetObject(command.Command):
    """Unset object properties"""

    log = logging.getLogger(__name__ + '.UnsetObject')

    def get_parser(self, prog_name):
        parser = super(UnsetObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container'
        )
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Object to modify')
        parser.add_argument(
            '--property',
            metavar='<key>',
            default=[],
            action='append',
            help='Property to remove from object',
            required=True
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        container = parsed_args.container
        obj = parsed_args.object
        properties = parsed_args.property
        self.app.client_manager.storage.object_del_properties(
            self.app.client_manager.get_account(),
            container,
            obj,
            properties)


class AnalyzeObject(lister.Lister):
    """Analyze object"""

    log = logging.getLogger(__name__ + '.AnalyzeObject')

    def get_parser(self, prog_name):
        parser = super(AnalyzeObject, self).get_parser(prog_name)
        parser.add_argument(
            'container',
            metavar='<container>',
            help='Container'
        )
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Object'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container
        obj = parsed_args.object

        data = self.app.client_manager.storage.object_analyze(
            account,
            container,
            obj)

        def sort_chunk_pos(c1, c2):
            c1_tokens = c1[0].split('.')
            c2_tokens = c2[0].split('.')
            c1_pos = int(c1_tokens[0])
            c2_pos = int(c2_tokens[0])
            if len(c1_tokens) == 1 or c1_pos != c2_pos:
                return c1_pos - c2_pos
            return cmp(c1[0], c2[0])

        chunks = ((c['pos'], c['url'], c['size'], c['hash']) for c in data[1])
        columns = ('Pos', 'Id', 'Size', 'Hash')
        return columns, sorted(chunks, cmp=sort_chunk_pos)
