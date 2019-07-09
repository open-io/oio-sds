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

from oio.blob.rebuilder import BlobRebuilder
from oio.cli.admin.common import ToolCommandMixin


class ItemRebuildCommand(ToolCommandMixin, lister.Lister):
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
        parser = super(ItemRebuildCommand, self).get_parser(prog_name)
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
        super(ItemRebuildCommand, self).run(parsed_args)
        if self.rebuilder is not None and not self.rebuilder.is_success():
            return 1


class ChunkRebuildCommand(ItemRebuildCommand):

    tool_class = BlobRebuilder
    columns = ('Chunk', 'Status', 'Errors')

    def get_parser(self, prog_name):
        parser = super(ChunkRebuildCommand, self).get_parser(prog_name)

        parser.add_argument(
            '--input-file',
            help='Read chunks from this file. '
                 'Each line should be formatted like '
                 '"container_id|content_id|short_chunk_id_or_position".')

        if not self.distributed:  # local
            parser.add_argument(
                '--dry-run', action='store_true',
                help='Display actions but do nothing. '
                     '(default=%s)' % self.tool_class.DEFAULT_DRY_RUN)
            parser.add_argument(
                '--delete-faulty-chunks', action='store_true',
                help='Try to delete faulty chunks after they have been '
                     'rebuilt elsewhere. This option is useful if the chunks '
                     'you are rebuilding are not actually missing but are '
                     'corrupted. '
                     '(default=%s)'
                % self.tool_class.DEFAULT_TRY_CHUNK_DELETE)

        return parser

    def _take_action(self, parsed_args):
        if not self.distributed:  # local
            self.tool_conf['dry_run'] = parsed_args.dry_run
            self.tool_conf['try_chunk_delete'] = \
                parsed_args.delete_faulty_chunks

        self.rebuilder = BlobRebuilder(
            self.tool_conf, input_file=parsed_args.input_file,
            logger=self.logger)
        if self.distributed:
            self.rebuilder.prepare_distributed_dispatcher()
        else:
            self.rebuilder.prepare_local_dispatcher()

        for item, _, error in self.rebuilder.run():
            if error is None:
                status = 'OK'
            else:
                status = 'error'
            yield (self.rebuilder.string_from_item(item), status, error)

    def take_action(self, parsed_args):
        if not parsed_args.input_file:
            raise ValueError('Missing input file')
        return super(ChunkRebuildCommand, self).take_action(parsed_args)


class ChunkRebuild(ChunkRebuildCommand):
    """
    Rebuild the specified chunks.
    """


class ChunkDistributedRebuild(ChunkRebuildCommand):
    """
    Rebuild the specified chunks,
    using several workers across the platform.
    """

    distributed = True
