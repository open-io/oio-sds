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
from logging import getLogger

from oio.account.rebuilder import AccountRebuilder
from oio.blob.rebuilder import BlobRebuilder
from oio.rebuilder.meta1_rebuilder import Meta1Rebuilder
from oio.rebuilder.meta2_rebuilder import Meta2Rebuilder


class ServiceRebuildCommand(lister.Lister):
    """
    Various parameters that apply to all rebuild commands.
    """

    log = None
    columns = None
    rebuilder_class = None
    rebuilder = None
    conf = dict()
    distributed = False

    @property
    def formatter_default(self):
        return 'value'

    def get_parser(self, prog_name):
        parser = super(ServiceRebuildCommand, self).get_parser(prog_name)
        # common
        parser.add_argument(
            '--report-interval', type=int,
            help='Report interval in seconds. '
                 '(default=%d)' % self.rebuilder_class.DEFAULT_REPORT_INTERVAL)
        if self.distributed:  # distributed
            distributed_tube_help = """
The beanstalkd tube to use to send the items to rebuild. (default=%s)
""" % self.rebuilder_class.DEFAULT_DISTRIBUTED_BEANSTALKD_WORKER_TUBE
            parser.add_argument(
                '--distributed-tube',
                help=distributed_tube_help)
        else:  # local
            parser.add_argument(
                '--workers', type=int,
                help='Number of workers. '
                     '(default=%d)' % self.rebuilder_class.DEFAULT_WORKERS
            )
            parser.add_argument(
                '--items-per-second', type=int,
                help='Max items per second. '
                     '(default=%d)'
                % self.rebuilder_class.DEFAULT_ITEM_PER_SECOND
            )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        self.conf.update(self.app.client_manager.client_conf)
        self.conf['namespace'] = self.app.options.ns
        self.conf['report_interval'] = parsed_args.report_interval
        if self.distributed:  # distributed
            self.conf['distributed_beanstalkd_worker_tube'] = \
                parsed_args.distributed_tube
        else:  # local
            self.conf['workers'] = parsed_args.workers
            self.conf['items_per_second'] = parsed_args.items_per_second

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ServiceRebuildCommand, self).run(parsed_args)
        if self.rebuilder is not None and not self.rebuilder.is_success():
            return 1


class Meta1Rebuild(ServiceRebuildCommand):
    """
    Rebuild meta1 databases by setting 'last_rebuild' property in admin table,
    thus triggering a replication. And print the failed container IDs.
    """

    log = getLogger(__name__ + '.Meta1Rebuild')
    columns = ('Prefix', 'Status')
    rebuilder_class = Meta1Rebuilder
    success = False

    def _take_action(self, parsed_args):
        meta1_rebuilder = Meta1Rebuilder(self.conf, self.log)
        self.success = meta1_rebuilder.rebuilder_pass()
        return
        yield  # pylint: disable=unreachable

    def run(self, parsed_args):
        super(Meta1Rebuild, self).run(parsed_args)
        if not self.success:
            return 1


class Meta2Rebuild(ServiceRebuildCommand):
    """
    Rebuild meta2 databases by setting 'last_rebuild'
    property in admin table, thus triggering a replication.
    And print the failed container IDs.
    """

    log = getLogger(__name__ + '.Meta2Rebuild')
    columns = ('Reference', 'Status')
    rebuilder_class = Meta2Rebuilder
    success = False

    def _take_action(self, parsed_args):
        meta2_rebuilder = Meta2Rebuilder(self.conf, self.log)
        self.success = meta2_rebuilder.rebuilder_pass()
        return
        yield  # pylint: disable=unreachable

    def run(self, parsed_args):
        super(Meta2Rebuild, self).run(parsed_args)
        if not self.success:
            return 1


class RawxRebuildCommand(ServiceRebuildCommand):

    rebuilder_class = BlobRebuilder

    def get_parser(self, prog_name):
        parser = super(RawxRebuildCommand, self).get_parser(prog_name)

        # input
        parser.add_argument(
            'service_id',
            metavar='<service_id>',
            help='ID of the service to rebuild')
        # common
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum of entries returned in each rdir response. '
                 '(default=%d)' % BlobRebuilder.DEFAULT_RDIR_FETCH_LIMIT)
        if not self.distributed:  # local
            parser.add_argument(
                '--dry-run', action='store_true',
                help='Display actions but do nothing. '
                     '(default=%s)' % self.rebuilder_class.DEFAULT_DRY_RUN)
            parser.add_argument(
                '--delete-faulty-chunks', action='store_true',
                help='Try to delete faulty chunks after they have been '
                     'rebuilt elsewhere. This option is useful if the chunks '
                     'you are rebuilding are not actually missing but are '
                     'corrupted. '
                     '(default=%s)' % BlobRebuilder.DEFAULT_TRY_CHUNK_DELETE)

        return parser

    def _take_action(self, parsed_args):
        # common
        self.conf['rdir_fetch_limit'] = parsed_args.rdir_fetch_limit
        if not self.distributed:  # local
            self.conf['dry_run'] = parsed_args.dry_run
            self.conf['try_chunk_delete'] = parsed_args.delete_faulty_chunks

        self.rebuilder = BlobRebuilder(
            self.conf, rawx_id=parsed_args.service_id, logger=self.log)
        if self.distributed:
            self.rebuilder.prepare_distributed_dispatcher()
        else:
            self.rebuilder.prepare_local_dispatcher()

        for item, _, error in self.rebuilder.run():
            if error is None:
                status = 'OK'
            else:
                status = error
            yield (self.rebuilder.string_from_item(item), status)


class RawxRebuild(RawxRebuildCommand):
    """
    Rebuild chunks that were on the specified volume. It is necessary to
    declare an incident (with 'openio volume admin incident') before running
    this command.
    """

    log = getLogger(__name__ + '.RawxRebuild')


class RawxDistributedRebuild(RawxRebuildCommand):
    """
    Rebuild chunks that were on the specified volume across the platform.
    It is necessary to declare an incident (with 'openio volume admin
    incident') before running this command.
    """

    log = getLogger(__name__ + '.RawxDistributedRebuild')
    distributed = True


class AccountServiceRebuild(ServiceRebuildCommand):
    """
    Rebuild account services.

    The steps of the rebuilding:
    recompute the counter of all accounts ;
    refresh the counter of all containers.
    """

    log = getLogger(__name__ + '.AccountServiceRebuild')
    columns = ('Entry', 'Status')
    rebuilder_class = AccountRebuilder

    def _take_action(self, parsed_args):
        self.rebuilder = AccountRebuilder(self.conf, logger=self.log)
        self.rebuilder.prepare_local_dispatcher()

        for item, _, error in self.rebuilder.run():
            if error is None:
                status = 'OK'
            else:
                status = error
            yield (self.rebuilder.string_from_item(item), status)
