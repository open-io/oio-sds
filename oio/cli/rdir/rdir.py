# Copyright (C) 2018-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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

from argparse import ArgumentError
from logging import getLogger
from six import iteritems
from itertools import combinations

from oio.cli import Lister
from oio.common.exceptions import OioException
from oio.rdir.client import DEFAULT_RDIR_REPLICAS
from oio.cli.common.utils import ValueCheckStoreTrueAction, format_detailed_scores
from oio.content.quality import get_distance


def _format_assignments(all_services, svc_col_title="Rawx", check=False):
    """Prepare the list of results for display"""
    # Possible improvement: if we do not sort by rdir,
    # we can yield results instead of building a list.
    results = list()
    for svc in all_services:
        rdirs = svc.get("rdir", [{"addr": "n/a", "tags": {}}])
        joined_ids = ",".join(
            (r["tags"].get("tag.service_id") or r["addr"]) for r in rdirs
        )
        joined_loc = ",".join(r["tags"].get("tag.loc", "n/a") for r in rdirs)
        res = (
            svc["tags"].get("tag.service_id") or svc["addr"],
            joined_ids,
        )
        if check:
            res += (
                len(svc.get("rdir", [])),
                svc.get("rdir_min_dist", 0),
                svc.get("rdir_status", "n/a"),
            )
        else:
            res += (svc["tags"].get("tag.loc"), joined_loc)
        results.append(res)

    results.sort()
    columns = (svc_col_title, "Rdir")
    if check:
        columns += ("Number of replicas", "Minimum distance", "Check status")
    else:
        columns += ("%s location" % svc_col_title, "Rdir location")
    return columns, results


class RdirBootstrap(Lister):
    """Assign rdir services"""

    log = getLogger(__name__ + ".RdirBootstrap")

    def get_parser(self, prog_name):
        parser = super(RdirBootstrap, self).get_parser(prog_name)
        parser.add_argument(
            "service_type", help="Which service type to assign rdir to."
        )
        parser.add_argument(
            "--max-per-rdir",
            metavar="<N>",
            type=int,
            help="Maximum number of databases per rdir service (total).",
        )
        parser.add_argument(
            "--min-dist",
            metavar="<N>",
            type=int,
            help=(
                "Minimum required distance between any service and "
                "its assigned rdir service."
            ),
        )
        parser.add_argument(
            "--replicas",
            metavar="<N>",
            type=int,
            default=DEFAULT_RDIR_REPLICAS,
            help="Number of rdirs per service.",
        )
        parser.add_argument(
            "--service-id",
            metavar="<service-id>",
            help="Assign an rdir only for this service ID.",
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Display actions but do nothing."
        )
        return parser

    def take_action(self, parsed_args):
        dispatcher = self.app.client_manager.rdir_dispatcher
        try:
            all_services = dispatcher.assign_services(
                parsed_args.service_type,
                max_per_rdir=parsed_args.max_per_rdir,
                min_dist=parsed_args.min_dist,
                replicas=parsed_args.replicas,
                service_id=parsed_args.service_id,
                dry_run=parsed_args.dry_run,
                connection_timeout=30.0,
                read_timeout=90.0,
            )
        except OioException as exc:
            self.success = False
            self.log.warning(
                "Failed to assign all %s services: %s", parsed_args.service_type, exc
            )
            all_services, _ = dispatcher.get_assignments(
                parsed_args.service_type, connection_timeout=30.0, read_timeout=90.0
            )

        return _format_assignments(all_services, parsed_args.service_type.capitalize())


class RdirAssignments(Lister):
    """Display which rdir service is linked to each other service"""

    log = getLogger(__name__ + ".DisplayVolumeAssignation")

    def get_parser(self, prog_name):
        parser = super(RdirAssignments, self).get_parser(prog_name)
        parser.add_argument(
            "service_type", help="Which service type to display rdir assignments"
        )
        parser.add_argument(
            "--aggregated",
            action="store_true",
            help="Display an aggregation of the assignation",
        )
        parser.add_argument(
            "--stats",
            action="store_true",
            help="Display additional rdir stats (requires --aggregated)",
        )
        parser.add_argument(
            "--check",
            action="store_true",
            help="Check rdir assignation is done correctly.",
        )
        parser.add_argument(
            "--min-dist",
            metavar="<N>",
            type=int,
            default=3,
            action=ValueCheckStoreTrueAction,
            help=(
                "(Enables 'check') Minimum required distance between any service "
                "and its assigned rdir service."
            ),
        )
        parser.add_argument(
            "--replicas",
            metavar="<N>",
            type=int,
            default=DEFAULT_RDIR_REPLICAS,
            action=ValueCheckStoreTrueAction,
            help="(Enables 'check') Number of rdirs per service.",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        if parsed_args.aggregated and parsed_args.check:
            raise ValueError("--aggregated and --check are mutually exclusive")

        dispatcher = self.app.client_manager.rdir_dispatcher
        results = []
        if not parsed_args.aggregated:
            all_services, _all_rdir = dispatcher.get_assignments(
                parsed_args.service_type, connection_timeout=30.0, read_timeout=90.0
            )

            if parsed_args.check:
                for service in all_services:
                    min_dist = 0
                    rdir_status = None
                    if "rdir" not in service or service["rdir"] is None:
                        rdir_status = "No rdir found"
                    elif len(service["rdir"]) < parsed_args.replicas:
                        rdir_status = "Not enough replicas"
                    elif len(service["rdir"]) > parsed_args.replicas:
                        rdir_status = "Too many replicas"
                    else:
                        min_dist = None
                        for svc1, svc2 in combinations(service["rdir"] + [service], 2):
                            dist = get_distance(
                                svc1["tags"]["tag.loc"], svc2["tags"]["tag.loc"]
                            )
                            if min_dist is None:
                                min_dist = dist
                            else:
                                min_dist = min(dist, min_dist)
                        if min_dist < parsed_args.min_dist:
                            rdir_status = "Minimum distance requirement failure"
                    if rdir_status:
                        self.success = False
                    else:
                        rdir_status = "OK"
                    service["rdir_min_dist"] = min_dist
                    service["rdir_status"] = rdir_status

            columns, results = _format_assignments(
                all_services,
                parsed_args.service_type.capitalize(),
                check=parsed_args.check,
            )
        else:
            managed_svc = dispatcher.get_aggregated_assignments(
                parsed_args.service_type, connection_timeout=30.0, read_timeout=90.0
            )
            for rdir, managed in iteritems(managed_svc):
                results.append((rdir, len(managed), " ".join(managed)))
            results.sort()
            if parsed_args.stats:
                all_rdir = dispatcher.cs.all_services("rdir", True)
                by_id = {
                    x["tags"].get("tag.service_id", x["addr"]): x for x in all_rdir
                }
                results = [
                    (
                        x[0],
                        by_id.get(x[0], {}).get("score", "0"),
                        format_detailed_scores(by_id.get(x[0], {})),
                        by_id.get(x[0], {}).get("tags", {}).get("stat.opened_db_count"),
                        x[2],
                    )
                    for x in results
                ]
                columns = (
                    "Rdir",
                    "Score",
                    "Scores",
                    f"Number of bases ({parsed_args.service_type})",
                    "Number of bases (total)",
                    "Bases",
                )
            else:
                columns = ("Rdir", "Number of bases", "Bases")
        return columns, results


class RdirReassign(Lister):
    """
    Reassign rdir services.

    This command does not copy the old databases to the new host, neither
    removes them.

    You can either use the dry-run mode, copy the database to the suggested
    host, then force the assignment with 'openio reference force --replace'.
    Or use the standard mode and let the crawlers reindex everything into
    the new host.
    """

    log = getLogger(__name__ + ".RdirReassign")

    def get_parser(self, prog_name):
        parser = super(RdirReassign, self).get_parser(prog_name)
        parser.add_argument(
            "service_type", help="Which service type to assign rdir to."
        )
        parser.add_argument("rdir_id", help="ID of an rdir service to be replaced.")
        parser.add_argument(
            "--max-per-rdir",
            metavar="<N>",
            type=int,
            help="Maximum number of databases per rdir service (total).",
        )
        parser.add_argument(
            "--min-dist",
            metavar="<N>",
            type=int,
            help=(
                "Minimum required distance between any service and "
                "its assigned rdir service."
            ),
        )
        parser.add_argument(
            "--replicas",
            metavar="<N>",
            type=int,
            default=DEFAULT_RDIR_REPLICAS,
            help="Number of rdirs per service.",
        )
        parser.add_argument(
            "--service-id",
            metavar="<service-id>",
            help="Assign an rdir only for this service ID.",
        )
        parser.add_argument(
            "--dry-run", action="store_true", help="Display actions but do nothing."
        )
        parser.add_argument(
            "--allow-down-services",
            type=int,
            default=0,
            help=(
                "Allow to reassign even if some of the old assigned "
                "services are down (score=0). The parameter is the number "
                "of down services we tolerate."
            ),
        )
        return parser

    def take_action(self, parsed_args):
        dispatcher = self.app.client_manager.rdir_dispatcher
        try:
            all_services = dispatcher.assign_services(
                parsed_args.service_type,
                reassign=parsed_args.rdir_id,
                service_id=parsed_args.service_id,
                max_per_rdir=parsed_args.max_per_rdir,
                min_dist=parsed_args.min_dist,
                replicas=parsed_args.replicas,
                dry_run=parsed_args.dry_run,
                allow_down_known_services=parsed_args.allow_down_services,
                connection_timeout=30.0,
                read_timeout=90.0,
            )
        except OioException as exc:
            self.success = False
            self.log.warning(
                "Failed to assign all %s services: %s", parsed_args.service_type, exc
            )
            all_services, _ = dispatcher.get_assignments(
                parsed_args.service_type, connection_timeout=30.0, read_timeout=90.0
            )
        return _format_assignments(all_services, parsed_args.service_type.capitalize())


class RdirCopyBase(Lister):
    """
    Copy one database from an rdir service to another.

    Specify either '--source' or '--dest'. The destination (resp. the source)
    will be searched in the service directory (meta1). You can specify
    both to avoid querying the directory.
    """

    log = getLogger(__name__ + ".RdirBootstrap")

    def get_parser(self, prog_name):
        parser = super(RdirCopyBase, self).get_parser(prog_name)

        # TODO(FVE): autodetect type
        parser.add_argument(
            "service_type",
            choices=("rawx", "meta2"),
            help="The type of service the database belongs to.",
        )
        parser.add_argument(
            "service_id",
            help=(
                "The ID of the service the database belongs to (may be an "
                "IP address and a port)."
            ),
        )

        parser.add_argument(
            "--source", action="append", help="ID of the rdir service to copy from."
        )
        parser.add_argument(
            "--dest",
            "--destination",
            action="append",
            help="ID of the rdir service to copy to.",
        )

        return parser

    def take_action(self, parsed_args):
        if not (parsed_args.source or parsed_args.dest):
            raise ArgumentError(
                parsed_args.source, "Must specify a source or a destination."
            )

        reqid = self.app.request_id("ACLI-")
        copy_func = {
            "meta2": self.app.client_manager.rdir.meta2_copy_vol,
            "rawx": self.app.client_manager.rdir.chunk_copy_vol,
        }
        copy_func[parsed_args.service_type](
            parsed_args.service_id,
            sources=parsed_args.source,
            dests=parsed_args.dest,
            reqid=reqid,
        )
        return ("Status",), [("OK",)]
