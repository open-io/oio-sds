# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2024 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from cliff import lister

from oio.common.exceptions import ClientException
from oio.cli.admin.common import SingleServiceCommandMixin


class ServiceListCommand(SingleServiceCommandMixin, lister.Lister):
    """
    A command to display items of a specific service
    """

    columns = None
    reqid_prefix = "ACLI-LST-"

    def __init__(self, *args, **kwargs):
        super(ServiceListCommand, self).__init__(*args, **kwargs)
        self._cids_cache = {}

    # Cliff ###########################################################

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ServiceListCommand, self).get_parser(prog_name)
        SingleServiceCommandMixin.patch_parser(self, parser)
        parser.add_argument(
            "--no-paging",
            dest="no_paging",
            default=False,
            help="List all elements without paging (and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        SingleServiceCommandMixin.check_and_load_parsed_args(
            self, self.app, parsed_args
        )
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)

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
                md = self.dir.list(cid=cid, reqid=reqid)
                self._cids_cache[cid] = "/".join([md.get("account"), md.get("name")])
            return self._cids_cache[cid]
        except ClientException:
            pass
        return cid


class RawxListContainers(ServiceListCommand):
    """
    List containers having chunks stored on the specified rawx service.
    """

    columns = ("Name", "Chunks")
    reqid_prefix = "ACLI-RLC-"

    def _list_containers(self, rawx, translate=False):
        reqid = self.app.request_id(self.reqid_prefix)
        status = self.rdir.status(rawx, reqid=reqid)
        containers = status.get("container")
        trans = self.translate_cid if translate else lambda x: x
        for cid, info in containers.items():
            yield trans(cid), info["total"]
        yield "Total", status["chunk"]["total"]

    def get_parser(self, prog_name):
        parser = super(RawxListContainers, self).get_parser(prog_name)
        parser.add_argument(
            "--no-translation",
            action="store_true",
            help="Do not translate container ID to account and container names",
        )
        return parser

    def _take_action(self, parsed_args):
        return self._list_containers(
            parsed_args.service, translate=not parsed_args.no_translation
        )


class RawxListObjects(ServiceListCommand):
    """
    List objects having chunks stored on the specified rawx service.

    This will be slow if the queried volume contains a lot of chunks.
    """

    columns = ("Name", "Chunk", "Object", "Version", "Mtime", "Content ID")
    reqid_prefix = "ACLI-RLO-"

    def _list_objects(
        self, rawx, cid=None, chunk_id=None, translate=False, before_incident=False
    ):
        reqid = self.app.request_id(self.reqid_prefix)
        trans = self.translate_cid if translate else lambda x: x
        for container, chunk, obj in self.rdir.chunk_fetch(
            rawx, container_id=cid, rebuild=before_incident, reqid=reqid
        ):
            if chunk_id and chunk != chunk_id:
                continue
            yield (
                trans(container),
                chunk,
                obj.get("path"),
                obj.get("version"),
                obj.get("mtime"),
                obj.get("content_id"),
            )

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--before-incident",
            help="List objects which existed before the last incident",
            action="store_true",
        )
        parser.add_argument(
            "--cid",
            help="Filter results on this container ID",
        )
        parser.add_argument(
            "--chunk-id",
            help=(
                "Filter results on this chunk ID only. "
                + "Filtering is done client-side."
            ),
        )
        parser.add_argument(
            "--no-translation",
            action="store_true",
            help="Do not translate container ID to account and container names",
        )
        return parser

    def _take_action(self, parsed_args):
        return self._list_objects(
            parsed_args.service,
            cid=parsed_args.cid,
            chunk_id=parsed_args.chunk_id,
            translate=not parsed_args.no_translation,
            before_incident=parsed_args.before_incident,
        )


class Meta2ListContainers(ServiceListCommand):
    """
    List containers hosted by the specified meta2 service.
    """

    columns = ("Name",)
    reqid_prefix = "ACLI-M2LC-"

    def get_parser(self, prog_name):
        parser = super(Meta2ListContainers, self).get_parser(prog_name)
        parser.add_argument(
            "--limit",
            metavar="<limit>",
            type=int,
            default=1000,
            help="Limit the number of results (1000 by default)",
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging.")
        parser.add_argument(
            "--prefix",
            metavar="<prefix>",
            help=(
                "Filter the output list using <prefix>. Notice that records "
                "are in the form <NAMESPACE>/<ACCOUNT>/<CONTAINER>. If you "
                "look for containers of a specific account, you must include "
                "the namespace name before the account name."
            ),
        )
        return parser

    def _list_all_containers(self, meta2, prefix=None):
        reqid = self.app.request_id(self.reqid_prefix)
        for item in self.rdir.meta2_index_fetch_all(meta2, prefix=prefix, reqid=reqid):
            yield item["container_url"]

    def _list_containers(self, meta2, **kwargs):
        reqid = self.app.request_id(self.reqid_prefix)
        resp = self.rdir.meta2_index_fetch(meta2, reqid=reqid, **kwargs)
        for item in resp.get("records"):
            # Get rid of the namespace name
            res = item["container_url"].split("/", 1)[1]
            yield res

    def _take_action(self, parsed_args):
        kwargs = {}
        if parsed_args.marker:
            kwargs["marker"] = parsed_args.marker
        if parsed_args.prefix:
            kwargs["prefix"] = parsed_args.prefix
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit

        if parsed_args.no_paging:
            containers = self._list_all_containers(
                parsed_args.service, prefix=parsed_args.prefix
            )
        else:
            containers = self._list_containers(parsed_args.service, **kwargs)
        return ((v,) for v in containers)
