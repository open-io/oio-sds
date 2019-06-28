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


from oio.common.utils import cid_from_name


class CommandMixin(object):

    def patch_parser(self, parser):
        raise NotImplementedError()

    def check_and_load_parsed_args(self, app, parsed_args):
        raise NotImplementedError()


class AccountCommandMixin(CommandMixin):
    """
    Add account-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'accounts',
            nargs='*',
            metavar='<account_name>',
            help='Name of the account to work on.'
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        if not parsed_args.accounts:
            parsed_args.accounts = [app.options.account]


class ContainerCommandMixin(CommandMixin):
    """
    Add container-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'containers',
            nargs='+',
            metavar='<container_name>',
            help='Name of the container to work on.'
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass

    def resolve_containers(self, app, parsed_args, no_name=False, no_id=False):
        containers = list()
        if parsed_args.is_cid:
            for container_id in parsed_args.containers:
                account = None
                container_name = None
                if not no_name:
                    account, container_name = \
                        app.client_manager.storage.resolve_cid(container_id)
                if no_id:
                    container_id = None
                containers.append((account, container_name, container_id))
        else:
            for container_name in parsed_args.containers:
                account = app.options.account
                container_id = None
                if not no_id:
                    container_id = cid_from_name(account, container_name)
                if no_name:
                    account = None
                    container_name = None
                containers.append((account, container_name, container_id))
        return containers


class ObjectCommandMixin(CommandMixin):
    """
    Add object-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'container',
            metavar='<container_name>',
            nargs='?',
            help=("Name or cid of the container to interact with.\n" +
                  "Optional if --auto is specified.")
        )
        parser.add_argument(
            'objects',
            metavar='<object_name>',
            nargs='*',
            help='Name of the object to work on.'
        )
        parser.add_argument(
            '--object-version',
            metavar='<version>',
            help=("Version of the object to work on. Can be used when only "
                  "one object is specified on command line.")
        )
        parser.add_argument(
            '--auto',
            action="store_true",
            help=("Auto-generate the container name according to the " +
                  "'flat_*' namespace parameters (<container> is ignored)."),
        )
        parser.add_argument(
            '--flat-bits',
            type=int,
            help="Number of bits for flat-NS computation",
        )
        parser.add_argument(
            '--cid',
            action='store_true',
            dest='is_cid',
            help="Interpret <container_name> as a container ID",
        )

    # TODO(FVE): merge with oio.cli.object.object.ContainerCommandMixin
    def check_and_load_parsed_args(self, app, parsed_args):
        if not parsed_args.container and not parsed_args.auto:
            from argparse import ArgumentError
            raise ArgumentError(parsed_args.container,
                                "Missing value for container_name or --auto")
        # If we are generating the container name automatically,
        # the first object name is in the container variable.
        if parsed_args.auto:
            parsed_args.objects.append(parsed_args.container)
            parsed_args.container = None
        if not parsed_args.objects:
            from argparse import ArgumentError
            raise ArgumentError(None, 'Missing value for object_name')
        if parsed_args.flat_bits:
            app.client_manager.flatns_set_bits(parsed_args.flat_bits)

    def resolve_objects(self, app, parsed_args):
        containers = set()
        objects = list()
        if parsed_args.auto:
            account = app.options.account
            autocontainer = app.client_manager.flatns_manager
            for obj in parsed_args.objects:
                ct = autocontainer(obj)
                containers.add(ct)
                objects.append((ct, obj, parsed_args.object_version))
        else:
            if parsed_args.is_cid:
                account, container = \
                    app.client_manager.storage.resolve_cid(
                        parsed_args.container)
            else:
                account = app.options.account
                container = parsed_args.container
            containers.add(container)
            for obj in parsed_args.objects:
                objects.append(
                    (container, obj, parsed_args.object_version))
        return account, containers, objects


class ChunkCommandMixin(CommandMixin):
    """
    Add chunk-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'chunks',
            metavar='<chunk_url>',
            nargs='+',
            help='URL of the chunk to work on.'
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class SingleServiceCommandMixin(CommandMixin):
    """
    Add service-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'service',
            metavar='<service_id>',
            help=("ID of the service to work on."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class MultipleServicesCommandMixin(CommandMixin):
    """
    Add service-related arguments to a cliff command.
    """

    service_type = None

    def patch_parser(self, parser):
        parser.add_argument(
            'services',
            nargs='*',
            metavar='<service_id>',
            help=("ID of the service to work on. "
                  "If no service is specified, work on all."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        """
        Load IDs of services.
        """
        if not parsed_args.services:
            parsed_args.services = [
                s['id'] for s in app.client_manager.conscience.all_services(
                    self.service_type)]


class ProxyCommandMixin(CommandMixin):
    """
    Add proxy-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument(
            'service',
            metavar='<service_id>',
            nargs='?',
            help=("ID of the proxy to work on. "
                  "If not specified, use the local one."),
        )

    def check_and_load_parsed_args(self, app, parsed_args):
        pass


class ToolCommandMixin(CommandMixin):
    """
    Add tool-related arguments to a cliff command.
    """

    tool_conf = dict()
    tool_class = None
    distributed = False

    def patch_parser(self, parser):
        parser.add_argument(
            '--report-interval', type=int,
            help='Report interval in seconds. '
                 '(default=%d)'
                 % self.tool_class.DEFAULT_REPORT_INTERVAL)
        parser.add_argument(
            '--items-per-second', type=int,
            help='Max items per second. '
                 '(default=%d)'
                 % self.tool_class.DEFAULT_ITEM_PER_SECOND)
        if self.distributed:  # distributed
            distributed_tube_help = """
The beanstalkd tube to use to send the items to rebuild. (default=%s)
""" % self.tool_class.DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE
            parser.add_argument(
                '--distributed-tube',
                help=distributed_tube_help)
        else:  # local
            parser.add_argument(
                '--concurrency', type=int,
                help='Number of coroutines to spawn. '
                     '(default=%d)' % self.tool_class.DEFAULT_CONCURRENCY)

    def check_and_load_parsed_args(self, app, parsed_args):
        self.tool_conf.update(app.client_manager.client_conf)
        self.tool_conf['report_interval'] = parsed_args.report_interval
        self.tool_conf['items_per_second'] = parsed_args.items_per_second
        if self.distributed:  # distributed
            self.tool_conf['distributed_beanstalkd_worker_tube'] = \
                parsed_args.distributed_tube
        else:  # local
            self.tool_conf['concurrency'] = parsed_args.concurrency
