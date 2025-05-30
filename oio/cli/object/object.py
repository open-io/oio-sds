# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

import os
from logging import getLogger
from sys import stdin

from oio.cli import Command, Lister, ShowOne
from oio.common import exceptions
from oio.common.constants import HTTP_CONTENT_TYPE_DELETED
from oio.common.easy_value import boolean_value
from oio.common.exceptions import CommandError
from oio.common.green import GreenPool
from oio.common.http_urllib3 import get_pool_manager
from oio.common.json import json
from oio.common.utils import depaginate

# flatns_manager field is not seen as callable.
# pylint: disable=not-callable


class ContainerCommandMixin(object):
    """Command taking a container name as parameter"""

    @property
    def flatns_manager(self):
        return self.app.client_manager.flatns_manager

    def patch_parser(self, parser):
        parser.add_argument(
            "container",
            metavar="<container>",
            nargs="?",
            help=(
                "Name or cid of the container to interact with.\n"
                "Optional if --auto is specified."
            ),
        )
        parser.add_argument(
            "--auto",
            help=(
                "Auto-generate the container name according to the "
                "'flat_*' namespace parameters (<container> is ignored)."
            ),
            action="store_true",
        )
        parser.add_argument(
            "--flat-bits",
            type=int,
            help="Number of bits for flat-NS computation",
        )
        parser.add_argument(
            "--cid",
            dest="is_cid",
            default=False,
            help="Interpret <container> as a CID",
            action="store_true",
        )

    def take_action(self, parsed_args):
        if not parsed_args.container and not parsed_args.auto:
            from argparse import ArgumentError

            raise ArgumentError(
                parsed_args.container, "Missing value for container or --auto"
            )
        parsed_args.cid = None
        if parsed_args.is_cid:
            parsed_args.cid = parsed_args.container
            parsed_args.container = None

        if parsed_args.flat_bits:
            self.app.client_manager.flatns_set_bits(parsed_args.flat_bits)


class ObjectCommandMixin(ContainerCommandMixin):
    """Command taking an object name as parameter"""

    def patch_parser(self, parser):
        super(ObjectCommandMixin, self).patch_parser(parser)
        parser.add_argument(
            "object", metavar="<object>", help="Name of the object to manipulate."
        )
        parser.add_argument(
            "--object-version",
            type=int,
            default=None,
            metavar="version",
            help="Version of the object to manipulate.",
        )


class CreateObject(ContainerCommandMixin, Lister):
    """Upload object"""

    log = getLogger(__name__ + ".CreateObject")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(CreateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        # TODO(mb): manage --opt and --no-opt
        parser.add_argument(
            "--no-autocreate",
            help="Forbid autocreation of container if nonexistent",
            action="store_false",
            dest="autocreate",
            default=True,
        )
        parser.add_argument(
            "objects",
            metavar="<filename>",
            nargs="+",
            help="Local filename(s) to upload.\nUse '-' to read from stdin.",
        )
        parser.add_argument(
            "--name",
            metavar="<key>",
            default=[],
            action="append",
            help=(
                "Name of the object to create. "
                "If not specified, use the basename of the uploaded file."
            ),
        )
        parser.add_argument("--policy", metavar="<policy>", help="Storage policy")
        parser.add_argument(
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add to the object(s)",
        )
        parser.add_argument(
            "--key-file", metavar="<key_file>", help="File containing application keys"
        )
        parser.add_argument(
            "--mime-type", metavar="<type>", help="Object MIME type", default=None
        )
        parser.add_argument(
            "--tls",
            action="store_true",
            help="Upgrade RAWX connection to TLS",
            default=False,
        )
        parser.add_argument(
            "--perfdata-column",
            action="store_true",
            help="Add a column to display performance data",
            default=False,
        )
        parser.add_argument(
            "--restore-drained",
            action="store_true",
            help="Restore a drained object (keeping its metadata)",
            default=False,
        )
        parser.add_argument(
            "--checksum-algo",
            metavar="<checksum_algo>",
            help="Object Checksum Algorithm",
            default=None,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(CreateObject, self).take_action(parsed_args)

        container = parsed_args.container
        cid = parsed_args.cid
        policy = parsed_args.policy
        objs = parsed_args.objects
        names = parsed_args.name
        key_file = parsed_args.key_file
        autocreate = parsed_args.autocreate
        if cid is not None:
            reqid = self.app.request_id("CLI-object-create-")
            data = self.app.client_manager.storage.container_get_properties(
                self.app.client_manager.account, None, cid=cid, reqid=reqid
            )
            container = data["system"]["sys.user.name"]
        if key_file and key_file[0] != "/":
            key_file = os.getcwd() + "/" + key_file

        any_error = False
        properties = parsed_args.property
        results = []
        perfdata = self.app.client_manager.storage.perfdata
        if names and len(objs) != len(names):
            raise CommandError("Mismatch between number of objects and names")
        for obj in objs:
            reqid = self.app.request_id("CLI-object-create-")
            use_stdin = False if obj != "-" else True
            name = None
            if names:
                name = names.pop(0)
            elif not use_stdin:
                name = os.path.basename(obj)
            else:
                raise CommandError("Missing value for names")
            try:
                with open(obj, "rb") if not use_stdin else stdin as f:
                    if parsed_args.auto:
                        container = self.flatns_manager(name)
                    kwargs = {
                        "account": self.app.client_manager.account,
                        "autocreate": autocreate,
                        "container": container,
                        "key_file": key_file,
                        "mime_type": parsed_args.mime_type,
                        "obj_name": name,
                        "object_checksum_algo": parsed_args.checksum_algo,
                        "policy": policy,
                        "properties": properties,
                        "restore_drained": parsed_args.restore_drained,
                        "tls": parsed_args.tls,
                        "reqid": reqid,
                    }
                    kwargs["file_or_path"] = f if not use_stdin else f.buffer
                    # Send all arguments from kwargs that are not None.
                    # For example, object_checksum_algo is not supposed to be
                    # propagated if it is None.
                    data = self.app.client_manager.storage.object_create_ext(
                        **{k: v for k, v in kwargs.items() if v is not None}
                    )

                    res = (name, data[1], data[2].upper(), data[3]["status"])
                    if parsed_args.perfdata_column:
                        res += (json.dumps(perfdata, sort_keys=True, indent=4),)

                    results.append(res)
            except KeyboardInterrupt:
                results.append((name, 0, None, "Interrupted"))
                any_error = True
                break
            except Exception as exc:
                self.log.error("Failed to upload %s in %s: %s", obj, container, exc)
                any_error = True
                results.append((name, 0, None, "Failed"))

        listing = (obj for obj in results)
        columns = ("Name", "Size", "Hash", "Status")
        if parsed_args.perfdata_column:
            columns += ("Perfdata",)
        if any_error:
            self.produce_output(parsed_args, columns, listing)
            raise Exception("Too many errors occurred")
        return columns, listing


class TouchObject(ContainerCommandMixin, Command):
    """Touch an object in a container, re-triggers asynchronous treatments"""

    log = getLogger(__name__ + ".TouchObject")

    def get_parser(self, prog_name):
        parser = super(TouchObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "objects", metavar="<object>", nargs="+", help="Object(s) to touch"
        )
        parser.add_argument(
            "--object-version",
            type=int,
            default=None,
            metavar="version",
            help="Version of the object to manipulate.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(TouchObject, self).take_action(parsed_args)

        container = parsed_args.container
        cid = parsed_args.cid
        if len(parsed_args.objects) > 1 and parsed_args.object_version:
            raise Exception("Cannot specify a version for several objects")
        if cid is not None:
            reqid = self.app.request_id("CLI-object-touch-")
            data = self.app.client_manager.storage.container_get_properties(
                self.app.client_manager.account, None, cid=cid, reqid=reqid
            )
            container = data["system"]["sys.user.name"]
        for obj in parsed_args.objects:
            reqid = self.app.request_id("CLI-object-touch-")
            if parsed_args.auto:
                container = self.flatns_manager(obj)
            self.app.client_manager.storage.object_touch(
                self.app.client_manager.account,
                container,
                obj,
                version=parsed_args.object_version,
                cid=cid,
                reqid=reqid,
            )


class DeleteObject(ContainerCommandMixin, Lister):
    """Delete one or several objects from a container."""

    log = getLogger(__name__ + ".DeleteObject")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "objects", metavar="<object>", nargs="+", help="Object(s) to delete"
        )
        parser.add_argument(
            "--object-version",
            type=int,
            default=None,
            metavar="version",
            help="Version of the object to manipulate.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(DeleteObject, self).take_action(parsed_args)
        container = ""
        results = []
        account = self.app.client_manager.account
        reqid = self.app.request_id("CLI-object--delete-")

        if len(parsed_args.objects) <= 1:
            if parsed_args.auto:
                container = self.flatns_manager(parsed_args.objects[0])
            else:
                container = parsed_args.container

            try:
                (
                    delete_marker,
                    _version_id,
                ) = self.app.client_manager.storage.object_delete(
                    account,
                    container,
                    parsed_args.objects[0],
                    version=parsed_args.object_version,
                    cid=parsed_args.cid,
                    reqid=reqid,
                )
                # If we specify a version, something is deleted each time (supposedly).
                # If we don't specify a version, something is deleted only if no
                # delete marker is created.
                # FIXME(FVE): should we say "False" when a delete marker is created?
                deleted = bool(parsed_args.object_version) or not delete_marker
            except exceptions.OioException as exc:
                self.log.error("%s", exc)
                self.success = False
                deleted = False
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
                    reqid = self.app.request_id("CLI-object--delete-")
                    tmp = self.app.client_manager.storage.object_delete_many(
                        account, key, value, reqid=reqid
                    )
                    results += tmp
            else:
                container = parsed_args.container
                cid = parsed_args.cid
                if cid is not None:
                    data = self.app.client_manager.storage.container_get_properties(
                        self.app.client_manager.account, None, cid=cid, reqid=reqid
                    )
                    container = data["system"]["sys.user.name"]
                results = self.app.client_manager.storage.object_delete_many(
                    account, container, parsed_args.objects, reqid=reqid
                )

        columns = ("Name", "Deleted")
        res_gen = (r for r in results)
        return columns, res_gen


class ShowObject(ObjectCommandMixin, ShowOne):
    """Show information about an object"""

    log = getLogger(__name__ + ".ShowObject")

    def get_parser(self, prog_name):
        parser = super(ShowObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        from oio.common.easy_value import convert_timestamp

        self.log.debug("take_action(%s)", parsed_args)
        super(ShowObject, self).take_action(parsed_args)

        account = self.app.client_manager.account
        obj = parsed_args.object

        container = parsed_args.container
        cid = parsed_args.cid
        if parsed_args.auto:
            container = self.flatns_manager(obj)
        data = self.app.client_manager.storage.object_get_properties(
            account,
            container,
            obj,
            version=parsed_args.object_version,
            cid=cid,
            reqid=self.app.request_id("CLI-object-show-"),
        )
        info = {"account": account, "container": container, "object": obj}
        conv = {
            "id": "id",
            "version": "version",
            "mime-type": "mime_type",
            "size": "length",
            "hash": "hash",
            "ctime": "ctime",
            "mtime": "mtime",
            "policy": "policy",
            "target_policy": "target_policy",
            "chunk_method": "chunk_method",
            "shard_hexid": "shard_hexid",
        }
        for key0, key1 in conv.items():
            info[key0] = data.get(key1, "n/a")
        if boolean_value(data.get("deleted"), False):
            info["mime-type"] = HTTP_CONTENT_TYPE_DELETED
            info["size"] = "deleted"
        for k, v in data["properties"].items():
            info["meta." + k] = v
        if parsed_args.formatter == "table":
            if info.get("ctime"):
                info["ctime"] = convert_timestamp(info.get("ctime"))
            if info.get("mtime"):
                info["mtime"] = convert_timestamp(info.get("mtime"))
        return list(zip(*sorted(info.items())))


class SetObject(ObjectCommandMixin, Command):
    """Set object properties"""

    log = getLogger(__name__ + ".SetObject")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(SetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add to this object",
        )
        parser.add_argument(
            "--tagging", metavar="<JSON object>", help="Replaces S3 tags on this object"
        )
        parser.add_argument(
            "--clear",
            default=False,
            help="Clear previous properties",
            action="store_true",
        )
        parser.add_argument(
            "--new-hash",
            metavar="<new hash>",
            help="New hash to use for the object",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(SetObject, self).take_action(parsed_args)
        container = parsed_args.container
        cid = parsed_args.cid
        obj = parsed_args.object
        if parsed_args.auto:
            container = self.flatns_manager(obj)
        properties = parsed_args.property
        new_hash = parsed_args.new_hash

        if parsed_args.tagging:
            try:
                tags = json.loads(parsed_args.tagging)
                if not isinstance(tags, dict):
                    raise ValueError()
            except ValueError:
                raise CommandError("--tags: Not a JSON object")
            tags_xml = "<Tagging><TagSet>"
            for k, v in tags.items():
                tags_xml += "<Tag><Key>%s</Key><Value>%s</Value></Tag>" % (k, v)
            tags_xml += "</TagSet></Tagging>"
            properties = properties or dict()
            from oio.container.lifecycle import TAGGING_KEY

            properties[TAGGING_KEY] = tags_xml

        if not properties and not new_hash:
            raise Command("Nothing to do")

        if properties:
            self.app.client_manager.storage.object_set_properties(
                self.app.client_manager.account,
                container,
                obj,
                properties,
                version=parsed_args.object_version,
                clear=parsed_args.clear,
                cid=cid,
                reqid=self.app.request_id("CLI-object-set-"),
            )

        if new_hash:
            self.app.client_manager.storage.object_update_hash(
                self.app.client_manager.account,
                container,
                obj,
                new_hash,
                version=parsed_args.object_version,
                cid=cid,
                reqid=self.app.request_id("CLI-object-set-"),
            )


class SaveObject(ObjectCommandMixin, Command):
    """Save object locally"""

    log = getLogger(__name__ + ".SaveObject")

    def get_parser(self, prog_name):
        parser = super(SaveObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--file",
            metavar="<filename>",
            help="Destination filename (defaults to object name)",
        )
        parser.add_argument(
            "--key-file", metavar="<key_file>", help="File containing application keys"
        )
        parser.add_argument(
            "--tls",
            action="store_true",
            help="Upgrade RAWX connection to TLS",
            default=False,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(SaveObject, self).take_action(parsed_args)

        container = parsed_args.container
        cid = parsed_args.cid
        obj = parsed_args.object
        key_file = parsed_args.key_file
        if key_file and key_file[0] != "/":
            key_file = os.getcwd() + "/" + key_file
        filename = parsed_args.file
        if not filename:
            filename = obj
        if parsed_args.auto:
            container = self.flatns_manager(obj)

        _meta, stream = self.app.client_manager.storage.object_fetch(
            self.app.client_manager.account,
            container,
            obj,
            version=parsed_args.object_version,
            key_file=key_file,
            properties=False,
            cid=cid,
            tls=parsed_args.tls,
            reqid=self.app.request_id("CLI-object-save-"),
        )
        if not os.path.exists(os.path.dirname(filename)):
            if len(os.path.dirname(filename)) > 0:
                os.makedirs(os.path.dirname(filename))
        with open(filename, "wb") as ofile:
            for chunk in stream:
                ofile.write(chunk)


class ListObject(ContainerCommandMixin, Lister):
    """List objects in a container."""

    log = getLogger(__name__ + ".ListObject")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--prefix", metavar="<prefix>", help="Filter list using <prefix>"
        )
        parser.add_argument(
            "--delimiter", metavar="<delimiter>", help="Filter list using <delimiter>"
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging")
        parser.add_argument(
            "--end-marker", metavar="<end-marker>", help="End marker for paging"
        )
        parser.add_argument(
            "--concurrency",
            metavar="<concurrency>",
            type=int,
            default=100,
            help=(
                "The number of concurrent requests to the container. "
                "(Only used when the --auto argument is specified. "
                "Default: 100)"
            ),
        )
        parser.add_argument(
            "--attempts",
            dest="attempts",
            type=int,
            default=0,
            help="Number of attempts for listing requests",
        )
        parser.add_argument(
            "--page-size",
            "--limit",
            metavar="<size>",
            dest="limit",
            type=int,
            default=1000,
            help="Limit the number of objects returned per page (1000 by default)",
        )
        parser.add_argument(
            "--no-paging",
            "--full",
            dest="full_listing",
            default=False,
            help="List all objects without paging (and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            "--properties",
            "--long",
            dest="long_listing",
            default=False,
            help="List properties with objects",
            action="store_true",
        )
        parser.add_argument(
            "--versions",
            "--all-versions",
            dest="versions",
            default=False,
            help="List all objects versions (not only the last one)",
            action="store_true",
        )
        parser.add_argument(
            "--local",
            dest="local",
            default=False,
            action="store_true",
            help="Ask the meta2 to open a local database",
        )
        parser.add_argument(
            "--chunks",
            dest="chunks",
            default=False,
            help="List chunks with objects (only readable with json format)",
            action="store_true",
        )
        return parser

    def _autocontainer_loop(
        self, account, marker=None, limit=None, concurrency=1, **kwargs
    ):
        from functools import partial

        container_marker = self.flatns_manager(marker) if marker else None
        count = 0
        kwargs["pool_manager"] = get_pool_manager(pool_maxsize=concurrency * 2)
        # Start to list contents at 'marker' inside the last visited container
        if container_marker:
            for element in depaginate(
                self.app.client_manager.storage.object_list,
                listing_key=lambda x: x["objects"],
                marker_key=lambda x: x.get("next_marker"),
                version_marker_key=lambda x: x.get("next_version_marker"),
                truncated_key=lambda x: x["truncated"],
                account=account,
                container=container_marker,
                marker=marker,
                **kwargs,
            ):
                count += 1
                yield element
                if limit and count >= limit:
                    return

        pool = GreenPool(concurrency)
        for object_list in pool.imap(
            partial(self._list_autocontainer_objects, account=account, **kwargs),
            depaginate(
                self.app.client_manager.storage.container_list,
                item_key=lambda x: x[0],
                marker_key=lambda x: x[-1][0],
                account=account,
                marker=container_marker,
            ),
        ):
            for element in object_list:
                count += 1
                yield element
                if limit and count >= limit:
                    return

    def _list_autocontainer_objects(self, container, account, **kwargs):
        object_list = []
        if not self.flatns_manager.verify(container):
            self.log.debug("Container %s is not an autocontainer", container)
            return object_list
        self.log.debug("Listing autocontainer %s", container)
        try:
            for i in depaginate(
                self.app.client_manager.storage.object_list,
                listing_key=lambda x: x["objects"],
                marker_key=lambda x: x.get("next_marker"),
                version_marker_key=lambda x: x.get("next_version_marker"),
                truncated_key=lambda x: x["truncated"],
                account=account,
                container=container,
                **kwargs,
            ):
                object_list.append(i)
        except exceptions.OioException as err:
            self.success = False
            self.log.warning(
                "Listing may be incomplete: container %s: %s", container, err
            )
        return object_list

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(ListObject, self).take_action(parsed_args)

        kwargs = {}
        if parsed_args.prefix:
            kwargs["prefix"] = parsed_args.prefix
        if parsed_args.marker:
            kwargs["marker"] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs["end_marker"] = parsed_args.end_marker
        if parsed_args.delimiter:
            kwargs["delimiter"] = parsed_args.delimiter
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit
        if parsed_args.long_listing:
            kwargs["properties"] = True
        if parsed_args.versions:
            kwargs["versions"] = True
        if parsed_args.local:
            kwargs["local"] = True
        if parsed_args.concurrency:
            kwargs["concurrency"] = parsed_args.concurrency
        if parsed_args.attempts:
            kwargs["request_attempts"] = parsed_args.attempts
        if parsed_args.chunks:
            kwargs["chunks"] = True

        account = self.app.client_manager.account
        if parsed_args.auto:
            obj_gen = self._autocontainer_loop(account, **kwargs)
        else:
            container = parsed_args.container
            cid = parsed_args.cid
            if parsed_args.full_listing:
                obj_gen = depaginate(
                    self.app.client_manager.storage.object_list,
                    listing_key=lambda x: x["objects"],
                    marker_key=lambda x: x.get("next_marker"),
                    version_marker_key=lambda x: x.get("next_version_marker"),
                    truncated_key=lambda x: x["truncated"],
                    account=account,
                    container=container,
                    cid=cid,
                    reqid=self.app.request_id("CLI-object-list-"),
                    **kwargs,
                )
            else:
                reqid = self.app.request_id("CLI-object-list-")
                resp = self.app.client_manager.storage.object_list(
                    account, container, cid=cid, reqid=reqid, **kwargs
                )
                obj_gen = resp["objects"]
                if resp.get("truncated"):
                    self.log.info(
                        "Object listing has been truncated, next marker: %s",
                        resp.get("next_marker"),
                    )

        def _format_chunks(chunks):
            # only return chunks if format is json (other format are
            # not readable anyway)
            if parsed_args.formatter == "json":
                return chunks
            return "n/a"

        if parsed_args.long_listing:
            from oio.common.easy_value import convert_timestamp

            def _format_props(props):
                prop_list = ["%s=%s" % (k, v) for k, v in props.items()]
                if parsed_args.formatter == "table":
                    prop_string = "\n".join(prop_list)
                elif parsed_args.formatter in ("value", "csv"):
                    prop_string = " ".join(prop_list)
                else:
                    prop_string = props
                return prop_string

            def _gen_results(objects):
                for obj in objects:
                    try:
                        mtime = obj["mtime"]
                        if parsed_args.formatter == "table":
                            mtime = convert_timestamp(mtime)
                        result = (
                            obj["name"],
                            obj["size"],
                            obj["hash"],
                            obj["version"],
                            obj["deleted"],
                            obj["mime_type"],
                            mtime,
                            obj["policy"],
                            obj.get("target-policy", "n/a"),
                            obj["chunk_method"],
                            _format_props(obj.get("properties", {})),
                        )
                        if parsed_args.chunks:
                            result += (_format_chunks(obj.get("chunks", {})),)
                        yield result
                    except KeyError as exc:
                        self.success = False
                        self.log.warning("Bad object entry, missing '%s': %s", exc, obj)

            columns = (
                "Name",
                "Size",
                "Hash",
                "Version",
                "Deleted",
                "Content-Type",
                "Last-Modified",
                "Policy",
                "Target-Policy",
                "Chunk-Method",
                "Properties",
            )
        else:

            def _gen_results(objects):
                for obj in objects:
                    try:
                        result = (
                            obj["name"],
                            obj["size"] if not obj["deleted"] else "deleted",
                            obj["hash"],
                            obj["version"],
                        )
                        if parsed_args.chunks:
                            result += (_format_chunks(obj.get("chunks", {})),)
                        yield result
                    except KeyError as exc:
                        self.success = False
                        self.log.warning("Bad object entry, missing %s: %s", exc, obj)

            columns = ("Name", "Size", "Hash", "Version")

        if parsed_args.chunks:
            columns += ("Chunks",)

        results = _gen_results(obj_gen)
        return (columns, results)


class UnsetObject(ObjectCommandMixin, Command):
    """Unset object properties"""

    log = getLogger(__name__ + ".UnsetObject")

    def get_parser(self, prog_name):
        parser = super(UnsetObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--property",
            metavar="<key>",
            default=[],
            action="append",
            help="Property to remove from object",
        )
        parser.add_argument(
            "--tagging",
            default=False,
            help="Clear previous S3 tags",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(UnsetObject, self).take_action(parsed_args)
        container = parsed_args.container
        cid = parsed_args.cid
        obj = parsed_args.object
        properties = parsed_args.property or list()
        if parsed_args.auto:
            container = self.flatns_manager(obj)
        if parsed_args.tagging:
            from oio.container.lifecycle import TAGGING_KEY

            properties.append(TAGGING_KEY)
        self.app.client_manager.storage.object_del_properties(
            self.app.client_manager.account,
            container,
            obj,
            properties,
            version=parsed_args.object_version,
            cid=cid,
            reqid=self.app.request_id("CLI-object-unset-"),
        )


class DrainObject(ContainerCommandMixin, Command):
    """\
Remove all the chunks of a content but keep the properties.
We can replace the data or the properties of the content
but no action needing the removed chunks are accepted\
"""

    log = getLogger(__name__ + ".DrainObject")

    def get_parser(self, prog_name):
        parser = super(DrainObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "objects", metavar="<object>", nargs="+", help="Object(s) to drain"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(DrainObject, self).take_action(parsed_args)
        account = self.app.client_manager.account
        container = parsed_args.container
        cid = parsed_args.cid
        for obj in parsed_args.objects:
            reqid = self.app.request_id("CLI-object-drain-")
            self.app.client_manager.storage.object_drain(
                account, container, obj, cid=cid, reqid=reqid
            )


class LocateObject(ObjectCommandMixin, Lister):
    """Locate the parts of an object"""

    log = getLogger(__name__ + ".LocateObject")

    def get_parser(self, prog_name):
        parser = super(LocateObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--chunk-info",
            action="store_true",
            default=False,
            help=(
                "Display chunk size and hash as they are on persistent            "
                " storage. It sends request per chunk so it is likely to be slow."
            ),
        )
        parser.add_argument(
            "--resolve",
            action="store_true",
            default=False,
            help="Display resolved services IDs to addresses and ports.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(LocateObject, self).take_action(parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container
        cid = parsed_args.cid

        obj = parsed_args.object
        if parsed_args.auto:
            container = self.flatns_manager(obj)

        obj_md, obj_chunks = self.app.client_manager.storage.object_locate(
            account,
            container,
            obj,
            cid=cid,
            version=parsed_args.object_version,
            chunk_info=parsed_args.chunk_info,
            reqid=self.app.request_id("CLI-object-locate-"),
        )

        if "shard_hexid" in obj_md:
            self.log.info("shard_hexid: %s", obj_md["shard_hexid"])

        # Build columns
        columns = ("Pos", "Id", "Metachunk size", "Metachunk hash")
        if parsed_args.chunk_info:
            columns += ("Chunk size", "Chunk hash")
        if parsed_args.resolve:
            columns += ("Real-Url",)

        # Build chunks with data
        chunks = []
        for c in obj_chunks:
            chunk = (c["pos"], c["url"], c["size"], c["hash"])
            if parsed_args.chunk_info:
                chunk += (c.get("chunk_size", "n/a"), c.get("chunk_hash", "n/a"))
            if parsed_args.resolve:
                chunk += (c["real_url"],)
            chunks.append(chunk)

        return columns, chunks


class PurgeObject(ObjectCommandMixin, Command):
    """Purge exceeding object versions."""

    log = getLogger(__name__ + ".PurgeObject")

    def get_parser(self, prog_name):
        parser = super(PurgeObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--max-versions",
            metavar="<n>",
            type=int,
            help="""The number of versions to keep
 (overrides the container configuration).
 n<0 is unlimited number of versions (purge only deleted aliases).
 n=0 is 1 version.
 n>0 is n versions.
""",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        super(PurgeObject, self).take_action(parsed_args)

        container = parsed_args.container
        cid = parsed_args.cid
        account = self.app.client_manager.account
        self.app.client_manager.storage.container.content_purge(
            account,
            container,
            parsed_args.object,
            maxvers=parsed_args.max_versions,
            cid=cid,
            reqid=self.app.request_id("CLI-object-purge-"),
        )


class LinkObject(ObjectCommandMixin, Command):
    """
    Make a shallow copy of an object (similar to a hardlink).
    """

    log = getLogger(__name__ + ".LinkObject")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import KeyValueAction

        parser = super(LinkObject, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--dest-account",
            "--link-account",
            metavar="<destination account>",
            help="Name of the destination account.",
        )
        parser.add_argument(
            "--dest-container",
            "--link-container",
            metavar="<destination container>",
            help=(
                "Name of the destination container. If not specified, the "
                "name of the destination container is the same as the source"
                " container, unless --auto is also specified in which case "
                "the name will be computed from the destination object."
            ),
        )
        parser.add_argument(
            "dest_object",
            metavar="<destination object>",
            help="Name of the destination object.",
        )
        parser.add_argument("--content-id", metavar="<content ID>", help="Content ID.")
        parser.add_argument(
            "--dest-content-id",
            "--link-content-id",
            metavar="<destination content ID>",
            help="destination content ID.",
        )
        parser.add_argument(
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add to the destination object.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        account = self.app.client_manager.account
        directive = "COPY"
        kwargs = {}

        if parsed_args.auto:
            container = self.flatns_manager(parsed_args.object)
        else:
            container = parsed_args.container
        if parsed_args.property:
            directive = "REPLACE"
            kwargs["properties"] = parsed_args.property
        if not parsed_args.dest_account:
            parsed_args.dest_account = account
        if not parsed_args.dest_container:
            if parsed_args.auto:
                parsed_args.dest_container = self.flatns_manager(
                    parsed_args.dest_object
                )
            else:
                parsed_args.dest_container = container
            parsed_args.cid = None
        cid = None
        if parsed_args.is_cid:
            cid = container
            container = None

        self.app.client_manager.storage.object_link(
            account,
            container,
            parsed_args.object,
            parsed_args.dest_account,
            parsed_args.dest_container,
            parsed_args.dest_object,
            target_version=parsed_args.object_version,
            target_content_id=parsed_args.content_id,
            link_content_id=parsed_args.dest_content_id,
            properties_directive=directive,
            cid=cid,
            reqid=self.app.request_id("CLI-object-link-"),
            **kwargs,
        )
