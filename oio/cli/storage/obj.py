import logging
import os
from oio.common.http import requests
from cliff import command, lister, show
from oio.cli.utils import KeyValueAction, ValueFormatStoreTrueAction


class ContainerCommandMixin(object):
    """Command taking a container name as parameter"""

    @property
    def flatns_manager(self):
        return self.app.client_manager.get_flatns_manager()

    def patch_parser(self, parser):
        parser.add_argument(
            'container',
            metavar='<container>',
            nargs='?',
            help=("Name of the container to interact with.\n" +
                  "Optional if --auto is specified.")
        )
        parser.add_argument(
            '--auto',
            help=("Auto-generate the container name according to the " +
                  "'flat_*' namespace parameters (<container> is ignored)."),
            action="store_true",
            default=False
        )

    def take_action(self, parsed_args):
        if not parsed_args.container and not parsed_args.auto:
            from argparse import ArgumentError
            raise ArgumentError(parsed_args.container,
                                "Missing value for container or --auto")


class ObjectCommandMixin(ContainerCommandMixin):
    """Command taking an object name as parameter"""

    def patch_parser(self, parser):
        super(ObjectCommandMixin, self).patch_parser(parser)
        parser.add_argument(
            'object',
            metavar='<object>',
            help='Name of the object to manipulate.')
        parser.add_argument(
            '--object-version',
            type=int,
            default=None,
            metavar='version',
            help='Version of the object to manipulate.')


class CreateObject(ContainerCommandMixin, lister.Lister):
    """Upload object"""

    log = logging.getLogger(__name__ + '.CreateObject')

    def get_parser(self, prog_name):
        parser = super(CreateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'objects',
            metavar='<filename>',
            nargs='+',
            help='Local filename(s) to upload.'
        )
        parser.add_argument(
            '--name',
            metavar='<key>',
            default=[],
            action='append',
            help=("Name of the object to create. " +
                  "If not specified, use the basename of the uploaded file.")
        )
        parser.add_argument(
            '--policy',
            metavar='<policy>',
            help='Storage policy'
        )
        parser.add_argument(
            '--property',
            metavar='<key=value>',
            action=KeyValueAction,
            help='Property to add to the object(s)'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='File containing application keys'
        )
        parser.add_argument(
            '--mime-type',
            metavar='<type>',
            help='Object MIME type',
            default=None
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(CreateObject, self).take_action(parsed_args)

        container = parsed_args.container
        policy = parsed_args.policy
        objs = parsed_args.objects
        names = parsed_args.name
        key_file = parsed_args.key_file
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file

        import io
        any_error = False
        properties = parsed_args.property
        results = []
        for obj in objs:
            try:
                with io.open(obj, 'rb') as f:
                    name = names.pop(0) if names else os.path.basename(f.name)
                    if parsed_args.auto:
                        container = self.flatns_manager(name)
                    data = self.app.client_manager.storage.object_create(
                        self.app.client_manager.get_account(),
                        container,
                        file_or_path=f,
                        obj_name=name,
                        policy=policy,
                        metadata=properties,
                        key_file=key_file,
                        mime_type=parsed_args.mime_type)

                    results.append((name, data[1], data[2].upper(), 'Ok'))
            except KeyboardInterrupt:
                results.append((name, 0, None, 'Interrupted'))
                any_error = True
                break
            except Exception:
                self.log.exception("Failed to upload %s in %s", obj, container)
                any_error = True
                results.append((name, 0, None, 'Failed'))

        l = (obj for obj in results)
        columns = ('Name', 'Size', 'Hash', 'Status')
        if any_error:
            self.produce_output(parsed_args, columns, l)
            raise Exception("Too many errors occured")
        return columns, l


class TouchObject(ContainerCommandMixin, command.Command):
    """Touch an object in a container, re-triggers asynchronous treatments"""

    log = logging.getLogger(__name__ + '.TouchObject')

    def get_parser(self, prog_name):
        parser = super(TouchObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'objects',
            metavar='<object>',
            nargs='+',
            help='Object(s) to delete'
        )
        parser.add_argument(
            '--object-version',
            type=int,
            default=None,
            metavar='version',
            help='Version of the object to manipulate.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(TouchObject, self).take_action(parsed_args)
        container = parsed_args.container

        if len(parsed_args.objects) > 1 and parsed_args.object_version:
            raise Exception("Cannot specify a version for several objects")

        for obj in parsed_args.objects:
            if parsed_args.auto:
                container = self.flatns_manager(obj)
            self.app.client_manager.storage.object_touch(
                self.app.client_manager.get_account(),
                container,
                obj,
                version=parsed_args.object_version)


class DeleteObject(ContainerCommandMixin, lister.Lister):
    """Delete object from container"""

    log = logging.getLogger(__name__ + '.DeleteObject')

    def get_parser(self, prog_name):
        parser = super(DeleteObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'objects',
            metavar='<object>',
            nargs='+',
            help='Object(s) to delete'
        )
        parser.add_argument(
            '--object-version',
            type=int,
            default=None,
            metavar='version',
            help='Version of the object to manipulate.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(DeleteObject, self).take_action(parsed_args)
        container = ''
        results = []
        account = self.app.client_manager.get_account()

        if len(parsed_args.objects) <= 1:
            if parsed_args.auto:
                container = self.flatns_manager(parsed_args.objects[0])
            else:
                container = parsed_args.container

            deleted = self.app.client_manager.storage.object_delete(
                account,
                container,
                parsed_args.objects[0],
                version=parsed_args.object_version)
            results.append((parsed_args.objects[0], deleted))
        else:
            if parsed_args.object_version:
                raise Exception("Cannot specify a version for several objects")
            if parsed_args.auto:
                objs = {}
                for obj in parsed_args.objects:
                    container = self.flatns_manager(obj)
                    if container not in objs:
                        objs[container] = []
                    objs[container].append(obj)

                for key, value in objs:
                    tmp = self.app.client_manager.storage.object_delete_many(
                        account,
                        key,
                        value)
                    results += tmp
            else:
                container = parsed_args.container
                results = self.app.client_manager.storage.object_delete_many(
                    account,
                    container,
                    parsed_args.objects)

        columns = ('Name', 'Deleted')
        res_gen = (r for r in results)
        return columns, res_gen


class ShowObject(ObjectCommandMixin, show.ShowOne):
    """Show information about an object"""

    log = logging.getLogger(__name__ + '.ShowObject')

    def get_parser(self, prog_name):
        parser = super(ShowObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(ShowObject, self).take_action(parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container
        obj = parsed_args.object

        if parsed_args.auto:
            container = self.flatns_manager(obj)
        data = self.app.client_manager.storage.object_show(
            account,
            container,
            obj,
            version=parsed_args.object_version)
        info = {'account': account,
                'container': container,
                'object': obj,
                'id': data['id'],
                'version': data['version'],
                'mime-type': data['mime_type'],
                'size': data['length'],
                'hash': data['hash'],
                'ctime': data['ctime'],
                'policy': data['policy']}
        for k, v in data['properties'].iteritems():
            info['meta.' + k] = v
        return zip(*sorted(info.iteritems()))


class SetObject(ObjectCommandMixin, command.Command):
    """Set object properties"""

    log = logging.getLogger(__name__ + '.SetObject')

    def get_parser(self, prog_name):
        parser = super(SetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
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
        super(SetObject, self).take_action(parsed_args)
        container = parsed_args.container
        obj = parsed_args.object
        if parsed_args.auto:
            container = self.flatns_manager(obj)
        properties = parsed_args.property
        self.app.client_manager.storage.object_set_properties(
            self.app.client_manager.get_account(),
            container,
            obj,
            properties,
            version=parsed_args.object_version,
            clear=parsed_args.clear)


class SaveObject(ObjectCommandMixin, command.Command):
    """Save object locally"""

    log = logging.getLogger(__name__ + '.SaveObject')

    def get_parser(self, prog_name):
        parser = super(SaveObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--file',
            metavar='<filename>',
            help='Destination filename (defaults to object name)'
        )
        parser.add_argument(
            '--key-file',
            metavar='<key_file>',
            help='File containing application keys'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(SaveObject, self).take_action(parsed_args)

        container = parsed_args.container
        obj = parsed_args.object
        key_file = parsed_args.key_file
        if key_file and key_file[0] != '/':
            key_file = os.getcwd() + '/' + key_file
        filename = parsed_args.file
        if not filename:
            filename = obj
        if parsed_args.auto:
            container = self.flatns_manager(obj)

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


class ListObject(ContainerCommandMixin, lister.Lister):
    """List objects in container"""

    log = logging.getLogger(__name__ + '.ListObject')

    def get_parser(self, prog_name):
        parser = super(ListObject, self).get_parser(prog_name)
        self.patch_parser(parser)
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
            type=int,
            default=1000,
            help='Limit the number of objects returned (1000 by default)'
        )
        parser.add_argument(
            '--no-paging', '--full',
            dest='full_listing',
            default=False,
            help=("List all objects without paging "
                  "(and set output format to 'value')"),
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            '--properties', '--long',
            dest='long_listing',
            default=False,
            help='List properties with objects',
            action="store_true"
        )
        parser.add_argument(
            '--versions', '--all-versions',
            dest='versions',
            default=False,
            help='List all objects versions (not only the last one)',
            action="store_true"
        )
        return parser

    def _list_loop(self, account, container, **kwargs):
        resp = self.app.client_manager.storage.object_list(
            account, container, **kwargs)
        listing = resp['objects']
        for element in listing:
            yield element

        while listing:
            if not kwargs.get('delimiter'):
                marker = listing[-1]['name']
            else:
                marker = listing[-1].get('name')
            kwargs['marker'] = marker
            listing = self.app.client_manager.storage.object_list(
                account, container, **kwargs)['objects']
            if listing:
                for element in listing:
                    yield element

    # TODO: make a decorator with this loop pattern
    def _container_provider(self, account, **kwargs):
        listing = self.app.client_manager.storage.container_list(
                account, **kwargs)
        for element in listing:
            yield element[0]

        while listing:
            kwargs['marker'] = listing[-1][0]
            listing = self.app.client_manager.storage.container_list(
                account, **kwargs)
            if listing:
                for element in listing:
                    yield element[0]

    def _autocontainer_loop(self, account, marker=None, limit=None, **kwargs):
        autocontainer = self.app.client_manager.get_flatns_manager()
        container_marker = autocontainer(marker) if marker else None
        count = 0
        # Start to list contents at 'marker' inside the last visited container
        if container_marker:
            for element in self._list_loop(account, container_marker,
                                           marker=marker, **kwargs):
                count += 1
                yield element
                if limit and count >= limit:
                    return
        # Start to list contents from the beginning of the next container
        for container in self._container_provider(account,
                                                  marker=container_marker):
            if not autocontainer.verify(container):
                self.log.debug("Container %s is not an autocontainer",
                               container)
                continue
            self.log.debug("Listing autocontainer %s", container)
            for element in self._list_loop(account, container, **kwargs):
                count += 1
                yield element
                if limit and count >= limit:
                    return

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(ListObject, self).take_action(parsed_args)

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
        if parsed_args.long_listing:
            kwargs['properties'] = True
        if parsed_args.versions:
            kwargs['versions'] = True

        account = self.app.client_manager.get_account()
        if parsed_args.auto:
            obj_gen = self._autocontainer_loop(account, **kwargs)
        else:
            container = parsed_args.container
            if parsed_args.full_listing:
                obj_gen = self._list_loop(account, container, **kwargs)
            else:
                resp = self.app.client_manager.storage.object_list(
                    account, container, **kwargs)
                obj_gen = resp['objects']

        if parsed_args.long_listing:
            from oio.common.utils import Timestamp

            def _format_props(props):
                prop_list = ["%s=%s" % (k, v) for k, v
                             in props.iteritems()]
                if parsed_args.formatter == 'table':
                    prop_string = "\n".join(prop_list)
                elif parsed_args.formatter in ('value', 'csv'):
                    prop_string = " ".join(prop_list)
                else:
                    prop_string = props
                return prop_string

            def _gen_results(objects):
                for obj in objects:
                    result = (obj['name'], obj['size'],
                              obj['hash'], obj['version'],
                              obj['deleted'], obj['mime_type'],
                              Timestamp(obj['ctime']).isoformat,
                              obj['policy'],
                              _format_props(obj.get('properties', {})))
                    yield result
            results = _gen_results(obj_gen)
            columns = ('Name', 'Size', 'Hash', 'Version', 'Deleted',
                       'Content-Type', 'Last-Modified', 'Policy', 'Properties')
        else:
            results = ((obj['name'],
                        obj['size'] if not obj['deleted'] else 'deleted',
                        obj['hash'],
                        obj['version'])
                       for obj in obj_gen)
            columns = ('Name', 'Size', 'Hash', 'Version')
        return (columns, results)


class UnsetObject(ObjectCommandMixin, command.Command):
    """Unset object properties"""

    log = logging.getLogger(__name__ + '.UnsetObject')

    def get_parser(self, prog_name):
        parser = super(UnsetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
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
        super(UnsetObject, self).take_action(parsed_args)
        container = parsed_args.container
        obj = parsed_args.object
        properties = parsed_args.property
        if parsed_args.auto:
            container = self.flatns_manager(obj)
        self.app.client_manager.storage.object_del_properties(
            self.app.client_manager.get_account(),
            container,
            obj,
            properties,
            version=parsed_args.object_version)


class DrainObject(ContainerCommandMixin, command.Command):
    """ Drain the chunks """

    log = logging.getLogger(__name__ + '.DrainObject')

    def get_parser(self, prog_name):
        parser = super(DrainObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            'objects',
            metavar='<filename>',
            nargs='+',
            help='Local filename(s) to upload.'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(DrainObject, self).take_action(parsed_args)
        account = self.app.client_manager.get_account()
        container = parsed_args.container

        for obj in parsed_args.objects:
            self.app.client_manager.storage.object_drain(
                account,
                container,
                obj)


class LocateObject(ObjectCommandMixin, lister.Lister):
    """Locate the parts of an object"""

    log = logging.getLogger(__name__ + '.LocateObject')

    def get_parser(self, prog_name):
        parser = super(LocateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            '--chunk-info',
            action='store_true',
            default=False,
            help='Display chunk size and hash as they are on persistent \
            storage. It sends request per chunk so it is likely to be slow.'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        super(LocateObject, self).take_action(parsed_args)

        account = self.app.client_manager.get_account()
        container = parsed_args.container
        obj = parsed_args.object
        if parsed_args.auto:
            container = self.flatns_manager(obj)

        data = self.app.client_manager.storage.object_analyze(
            account,
            container,
            obj,
            version=parsed_args.object_version)

        def sort_chunk_pos(c1, c2):
            c1_tokens = c1[0].split('.')
            c2_tokens = c2[0].split('.')
            c1_pos = int(c1_tokens[0])
            c2_pos = int(c2_tokens[0])
            if len(c1_tokens) == 1 or c1_pos != c2_pos:
                return c1_pos - c2_pos
            return cmp(c1[0], c2[0])

        def get_chunks_info(chunks):
            session = requests.Session()
            chunk_hash = ""
            chunk_size = ""
            for c in chunks:
                resp = session.request('HEAD', c['url'])
                if resp.status_code != 200:
                    chunk_size = "%d %s" % (
                        resp.status_code, resp.reason)
                    chunk_hash = "%d %s" % (
                        resp.status_code, resp.reason)
                else:
                    chunk_size = resp.headers.get(
                        'X-oio-chunk-meta-chunk-size',
                        'Missing chunk size header')
                    chunk_hash = resp.headers.get(
                        'X-oio-chunk-meta-chunk-hash',
                        'Missing chunk hash header')
                yield (c['pos'], c['url'], c['size'], c['hash'], chunk_size,
                       chunk_hash)
        columns = ()
        chunks = []
        if parsed_args.chunk_info:
            columns = ('Pos', 'Id', 'Metachunk size', 'Metachunk hash',
                       'Chunk size', 'Chunk hash')
            chunks = get_chunks_info(data[1])
        else:
            columns = ('Pos', 'Id', 'Metachunk size', 'Metachunk hash')
            chunks = ((c['pos'], c['url'], c['size'],
                       c['hash']) for c in data[1])

        return columns, sorted(chunks, cmp=sort_chunk_pos)
