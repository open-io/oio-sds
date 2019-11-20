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

from oio.account.rebuilder import AccountRebuilder
from oio.cli import Lister
from oio.cli.admin.common import MultipleServicesCommandMixin, \
    ToolCommandMixin, SingleServiceCommandMixin
from oio.directory.meta2_rebuilder import Meta2Rebuilder
from oio.rebuilder.meta1_rebuilder import Meta1Rebuilder
from oio.xcute.jobs.blob_rebuilder import RawxRebuildJob


class ServiceRebuildCommand(ToolCommandMixin, lister.Lister):
    """
    Various parameters that apply to all rebuild commands.
    """

    columns = None
    rebuilder = None

    @property
    def formatter_default(self):
        return 'value'

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ServiceRebuildCommand, self).get_parser(prog_name)
        ToolCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        ToolCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        self.logger.debug('take_action(%s)', parsed_args)

        return self.columns, self._take_action(parsed_args)

    def run(self, parsed_args):
        super(ServiceRebuildCommand, self).run(parsed_args)
        if self.rebuilder is not None and not self.rebuilder.is_success():
            return 1


class Meta1Rebuild(ServiceRebuildCommand):
    """
    Rebuild meta1 databases.
    To rebuild, the 'last_rebuild' property is set in admin table,
    thus triggering a replication. And print the failed container IDs.
    """

    tool_class = Meta1Rebuilder
    columns = ('Prefix', 'Status', 'Errors')
    success = False

    def _take_action(self, parsed_args):
        meta1_rebuilder = Meta1Rebuilder(self.tool_conf, self.logger)
        self.success = meta1_rebuilder.rebuilder_pass()
        return
        yield  # pylint: disable=unreachable

    def run(self, parsed_args):
        super(Meta1Rebuild, self).run(parsed_args)
        if not self.success:
            return 1


class Meta2Rebuild(SingleServiceCommandMixin, ServiceRebuildCommand):
    """
    Rebuild meta2 databases that were on the specified volume.
    The steps of the rebuilding:
    rebuild all missing, lost bases ;
    synchronize the bases.
    """

    tool_class = Meta2Rebuilder
    columns = ('Reference', 'Status', 'Errors')
    rebuilder = None

    def get_parser(self, prog_name):
        parser = super(Meta2Rebuild, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)

        # common
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
            % self.tool_class.DEFAULT_RDIR_FETCH_LIMIT)
        return parser

    def _take_action(self, parsed_args):
        self.tool_conf['rdir_fetch_limit'] = parsed_args.rdir_fetch_limit

        self.rebuilder = Meta2Rebuilder(
            self.tool_conf, service_id=parsed_args.service,
            logger=self.logger)
        self.rebuilder.prepare_local_dispatcher()

        for item, _, error in self.rebuilder.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.rebuilder.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return super(Meta2Rebuild, self).take_action(parsed_args)


class RawxRebuildCommand(MultipleServicesCommandMixin, Lister):

    columns = ('Service ID', 'Job ID')

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def xcute(self):
        return self.app.client_manager.xcute_client

    def get_parser(self, prog_name):
        parser = super(RawxRebuildCommand, self).get_parser(prog_name)
        MultipleServicesCommandMixin.patch_parser(self, parser)

        parser.add_argument(
            '--chunks-per-second', type=int,
            help='Max chunks per second. '
                 '(default=%d)'
                 % RawxRebuildJob.DEFAULT_TASKS_PER_SECOND)
        parser.add_argument(
            '--rdir-fetch-limit', type=int,
            help='Maximum number of entries returned in each rdir response. '
                 '(default=%d)'
            % RawxRebuildJob.DEFAULT_RDIR_FETCH_LIMIT)
        parser.add_argument(
            '--rdir-timeout', type=float,
            help='Timeout for rdir operations, in seconds. (default=%f)'
                 % RawxRebuildJob.DEFAULT_RDIR_TIMEOUT)
        parser.add_argument(
            '--rawx-timeout', type=float,
            help='Timeout for rawx operations, in seconds. (default=%f)'
                 % RawxRebuildJob.DEFAULT_RAWX_TIMEOUT)
        parser.add_argument(
            '--dry-run', action='store_true',
            help='Display actions but do nothing.')
        parser.add_argument(
            '--delete-faulty-chunks', action='store_true',
            help='Try to delete faulty chunks after they have been '
                 'rebuilt elsewhere. This option is useful if the chunks '
                 'you are rebuilding are not actually missing but are '
                 'corrupted.')
        parser.add_argument(
            '--allow-frozen-container', action='store_true',
            help='Allow rebuilding a chunk in a frozen container.')

        return parser

    def _take_action(self, parsed_args):
        job_params = {
            'rdir_fetch_limit': parsed_args.rdir_fetch_limit,
            'rdir_timeout': parsed_args.rdir_timeout,
            'rawx_timeout': parsed_args.rawx_timeout,
            'dry_run': parsed_args.dry_run,
            'try_chunk_delete': parsed_args.delete_faulty_chunks,
            'allow_frozen_container': parsed_args.allow_frozen_container
        }
        job_config = {
            'tasks_per_second': parsed_args.chunks_per_second,
            'params': job_params
        }

        for service_id in parsed_args.services:
            job_params['service_id'] = service_id
            try:
                job_info = self.xcute.job_create(
                    RawxRebuildJob.JOB_TYPE, job_config=job_config)
                res = job_info['id']
            except Exception as exc:
                self.success = False
                res = str(exc)
            yield (service_id, res)

    def take_action(self, parsed_args):
        MultipleServicesCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args)
        return (self.columns, self._take_action(parsed_args))


class RawxRebuild(RawxRebuildCommand):
    """
    Rebuild chunks that were on the specified volume.
    It is necessary to declare an incident (with 'openio volume admin
    incident') before running this command.
    """


class RawxDistributedRebuild(RawxRebuildCommand):
    """
    Rebuild chunks that were on the specified volume across the platform.
    It is necessary to declare an incident (with 'openio volume admin
    incident') before running this command.
    """

    distributed = True


class AccountServiceRebuild(ServiceRebuildCommand):
    """
    Rebuild account services.
    The steps of the rebuilding:
    recompute the counter of all accounts ;
    refresh the counter of all containers.
    """

    tool_class = AccountRebuilder
    columns = ('Entry', 'Status', 'Errors')

    def _take_action(self, parsed_args):
        self.rebuilder = AccountRebuilder(
            self.tool_conf, logger=self.logger)
        self.rebuilder.prepare_local_dispatcher()

        for item, _, error in self.rebuilder.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.rebuilder.string_from_item(item), status, error)
