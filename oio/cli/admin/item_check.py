# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from cliff import lister

from oio.cli import ShowOne, flat_dict_from_dict, get_all_values
from oio.cli.admin.common import (
    AccountCommandMixin,
    ChunkCommandMixin,
    ContainerCommandMixin,
    ObjectCommandMixin,
)
from oio.common.exceptions import NotFound, OioException
from oio.crawler.integrity import DEFAULT_DEPTH, Checker, Target


class ItemCheckCommand(lister.Lister):
    """
    Various parameters that apply to all check commands.
    """

    columns = ("Type", "Item", "Status", "Errors")
    success = True
    checker = None

    @property
    def logger(self):
        return self.app.client_manager.logger

    def get_parser(self, prog_name):
        parser = super(ItemCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            "--attempts",
            type=int,
            default=1,
            help="Number of attempts for listing requests (default: 1).",
        )
        parser.add_argument(
            "--checksum", action="store_true", help="Perform checksum comparisons."
        )

        parser.add_argument(
            "--concurrency",
            "--workers",
            type=int,
            default=30,
            help="Number of concurrent checks (default: 30).",
        )
        parser.add_argument(
            "-o",
            "--output",
            help=(
                "Output file. Will contain elements in error. "
                "Can later be passed to stdin of the legacy "
                "oio-crawler-integrity to re-check only these elements."
            ),
        )
        parser.add_argument(
            "--output-for-chunk-rebuild",
            help=(
                "Write chunk errors in a file with a format "
                "suitable as 'openio-admin chunk rebuild' input."
            ),
        )
        return parser

    def _take_action(self, parsed_args):
        raise NotImplementedError()

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        self.checker = Checker(
            self.app.options.ns,
            concurrency=parsed_args.concurrency,
            error_file=parsed_args.output,
            rebuild_file=parsed_args.output_for_chunk_rebuild,
            request_attempts=parsed_args.attempts,
            verify_chunk_checksum=parsed_args.checksum,
            logger=self.logger,
        )

        return self.columns, self._take_action(parsed_args)

    def _format_results(self):
        for res in self.checker.run():
            if not res.has_errors:
                status = "OK"
                yield (res.type, repr(res), status, str(None))
            else:
                self.success = False
                status = "error"
                yield (
                    res.type,
                    repr(res),
                    status,
                    res.latest_error_result().errors_to_str(),
                )

    def run(self, parsed_args):
        super(ItemCheckCommand, self).run(parsed_args)
        if not self.success:
            return 1


class RecursiveCheckCommand(ItemCheckCommand):
    """ItemCheckCommand with additional parameters to control recursion."""

    def get_parser(self, prog_name):
        parser = super(RecursiveCheckCommand, self).get_parser(prog_name)
        parser.add_argument(
            "--depth",
            "--max-depth",
            type=int,
            default=DEFAULT_DEPTH,
            help=(
                "How deep to recurse. 0 means do not recurse. "
                "N > 0 means recurse N levels below the specified item type "
                "(namespace -> account -> container -> object -> chunk, "
                "default: %d)."
            )
            % DEFAULT_DEPTH,
        )
        parser.add_argument(
            "--limit-listings",
            type=int,
            default=2,
            help=(
                "Avoid listing the whole container (resp. account) to check if an "
                "object (resp. container) exists:\n"
                "0 means no limit (build an exhaustive list "
                "useful when checking many objects from many containers).\n"
                "1 means limit only container listings.\n"
                "2 means limit both container and object listings.\n"
                "Default is 2."
            ),
        )
        return parser


class AccountCheck(AccountCommandMixin, RecursiveCheckCommand):
    """
    Check an account for problems.
    """

    def get_parser(self, prog_name):
        parser = super(AccountCheck, self).get_parser(prog_name)
        AccountCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        for acct in parsed_args.accounts:
            target = Target(acct)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        AccountCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(AccountCheck, self).take_action(parsed_args)


class ContainerCheck(ContainerCommandMixin, RecursiveCheckCommand):
    """
    Check a container for problems.

    Quick checks on the account owning
    the container will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ContainerCheck, self).get_parser(prog_name)
        ContainerCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        containers = self.resolve_containers(self.app, parsed_args, no_id=True)
        self.checker.limit_listings = parsed_args.limit_listings
        for account, container_name, _ in containers:
            target = Target(account, container_name)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        ContainerCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(ContainerCheck, self).take_action(parsed_args)


class ObjectCheck(ObjectCommandMixin, RecursiveCheckCommand):
    """
    Check an object for problems.

    Quick checks on the account and the container
    owning the object will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ObjectCheck, self).get_parser(prog_name)
        ObjectCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        account, _, objects = self.resolve_objects(self.app, parsed_args)
        self.checker.limit_listings = parsed_args.limit_listings
        for container, obj_name, version in objects:
            target = Target(account, container, obj_name, version=version)
            self.checker.check(target, parsed_args.depth)
        return self._format_results()

    def take_action(self, parsed_args):
        ObjectCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(ObjectCheck, self).take_action(parsed_args)


class ChunkCheck(ChunkCommandMixin, ItemCheckCommand):
    """
    Check a chunk for problems.

    Quick checks on the account, the container
    and the object owning the chunk will also be performed.
    """

    def get_parser(self, prog_name):
        parser = super(ChunkCheck, self).get_parser(prog_name)
        ChunkCommandMixin.patch_parser(self, parser)
        return parser

    def _take_action(self, parsed_args):
        for chunk in parsed_args.chunks:
            target = Target(self.app.options.account, chunk=chunk)
            self.checker.check(target)
        return self._format_results()

    def take_action(self, parsed_args):
        ChunkCommandMixin.check_and_load_parsed_args(self, self.app, parsed_args)
        return super(ChunkCheck, self).take_action(parsed_args)


class PeersCheck(ShowOne):
    """
    Check the consistency of all peers of the indicated type
    with what is known by the parent metaX.
    """

    @property
    def logger(self):
        return self.app.client_manager.logger

    @property
    def storage(self):
        return self.app.client_manager.storage

    def get_parser(self, prog_name):
        parser = super(PeersCheck, self).get_parser(prog_name)
        parser.add_argument(
            "service_type", choices=("meta0", "meta1", "meta2"), help="Service type"
        )
        parser.add_argument("reference", metavar="<reference>", help="Reference name")
        parser.add_argument(
            "--cid",
            dest="is_cid",
            default=False,
            help="Interpret <reference> as a CID",
            action="store_true",
        )
        return parser

    def get_params(self, parsed_args):
        service_type = parsed_args.service_type
        if parsed_args.is_cid:
            cid = parsed_args.reference
            account = None
            reference = None
        else:
            account = self.app.options.account
            reference = parsed_args.reference
            cid = None
        return service_type, account, reference, cid

    def get_meta2_links(self, account, reference, cid):
        """
        Return the meta2 links known by the master meta1 database.
        """
        data_dir = self.storage.directory.list(
            account, reference, cid=cid, force_master=True
        )
        meta1_peers = []
        for d in data_dir["dir"]:
            if d["type"] == "meta1":
                meta1_peers.append(d["host"])
        meta2_links = []
        for d in data_dir["srv"]:
            if d["type"] == "meta2":
                meta2_links.append(d["host"])
        meta2_links.sort()

        # Check that all meta1 peers agree
        for sid in meta1_peers:
            data_dir = self.storage.directory.list(
                account, reference, cid=cid, service_id=sid
            )
            _meta2_links = sorted(
                (d["host"] for d in data_dir["srv"] if d["type"] == "meta2")
            )
            if _meta2_links != meta2_links:
                raise OioException(
                    "Unsynchronized meta1 peers: "
                    f"{_meta2_links} ({sid}) != {meta2_links} (master)"
                )

        if not meta2_links:
            raise OioException("No meta2 links in meta1 DB")
        return tuple(meta2_links)

    def get_meta2_peers(self, account, reference, cid, service_id):
        """
        Return the meta2 peers known by the meta2 database.
        """
        try:
            # Don’t trigger an election
            meta = self.storage.container_get_properties(
                account,
                reference,
                cid=cid,
                params={"service_id": service_id, "local": 1},
            )
            system = meta.get("system")
            if not system:
                # Database doesn't exist
                return None
            meta2_peers = system.get("sys.peers")
            if meta2_peers is None:
                # Maybe no metaX replication
                return ()
            return tuple(sorted(meta2_peers.split(",")))
        except NotFound:
            self.logger.info(
                "Reference %s/%s no longer exists (meta2 service)", account, reference
            )
            return None
        except Exception as exc:
            self.success = False
            self.logger.error(
                "Failed to locate reference %s/%s (meta2 service): %s",
                account,
                reference,
                exc,
            )
            return None

    def get_all_metaX_peers(
        self,
        all_metaX_peers,
        get_metaX_peers_func,
        account,
        reference,
        cid,
        service_id,
    ):
        all_metaX_peers = dict(all_metaX_peers)
        if service_id not in all_metaX_peers:
            metaX_peers = get_metaX_peers_func(account, reference, cid, service_id)
            all_metaX_peers[service_id] = metaX_peers
            if metaX_peers is not None:
                for sid in metaX_peers:
                    all_metaX_peers.update(
                        self.get_all_metaX_peers(
                            all_metaX_peers,
                            get_metaX_peers_func,
                            account,
                            reference,
                            cid,
                            sid,
                        )
                    )
        return all_metaX_peers

    def take_action(self, parsed_args):
        service_type, account, reference, cid = self.get_params(parsed_args)

        if service_type == "meta2":
            parent_peers_func = self.get_meta2_links
            get_metaX_peers_func = self.get_meta2_peers
        else:
            raise NotImplementedError(f"Service type {service_type} is not implemented")

        parent_peers = parent_peers_func(account, reference, cid)
        all_metaX_peers = {}
        for sid in parent_peers:
            all_metaX_peers = self.get_all_metaX_peers(
                all_metaX_peers,
                get_metaX_peers_func,
                account,
                reference,
                cid,
                sid,
            )

        nb_repli = len(parent_peers)
        if nb_repli == 1:
            # No metaX replication
            for sid, peers in all_metaX_peers.items():
                if peers == ():
                    # metaX databases don't need to know about their peers
                    # (since there aren't any)
                    all_metaX_peers[sid] = tuple(parent_peers)

        # Select the majority peers
        majority_peers = None
        all_metaX_peers_values = [
            peers for peers in all_metaX_peers.values() if peers is not None
        ]
        if all_metaX_peers_values.count(parent_peers) >= nb_repli:
            # Favor already parent peers
            majority_peers = parent_peers
        else:
            for peers in set(all_metaX_peers_values):
                count = all_metaX_peers_values.count(peers)
                if count < nb_repli:
                    continue
                if majority_peers is not None:
                    raise OioException("Impossible to know the majority peers")
                majority_peers = peers

        # Check the consistency of the information.
        res = {
            "peers": {
                "parent": parent_peers,
                service_type: all_metaX_peers,
                "majority": majority_peers,
            },
            "agree_with_majority": {
                "parent": majority_peers is not None and parent_peers == majority_peers,
                service_type: {
                    sid: majority_peers is not None and metaX_peers == majority_peers
                    for sid, metaX_peers in all_metaX_peers.items()
                },
                "majority": majority_peers is not None
                and all(
                    (all_metaX_peers[sid] == majority_peers for sid in majority_peers)
                ),
            },
        }
        self.success = all(get_all_values(res["agree_with_majority"]))
        if parsed_args.formatter not in ("json", "yaml"):
            res = flat_dict_from_dict(parsed_args, res, separator=",")
        return list(zip(*sorted(res.items())))
