# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2024 OVH SAS
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

from logging import getLogger

from oio.cli import Lister, ShowOne
from oio.common.exceptions import OioException


class ShowAdminVolume(ShowOne):
    """
    Show information about a volume, like the last incident date,
    or the presence of a lock on the volume.

    An empty output means there is no lock and incident on the volume.
    """

    log = getLogger(__name__ + ".ShowAdminVolume")

    def get_parser(self, prog_name):
        parser = super(ShowAdminVolume, self).get_parser(prog_name)
        parser.add_argument("volume", metavar="<volume>", help="ID of the rawx service")
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        output = []
        output.append(("volume", parsed_args.volume))
        data = self.app.client_manager.volume.volume_admin_show(
            volume=parsed_args.volume,
            reqid=self.app.request_id(),
        )
        for k, v in sorted(data.items()):
            output.append((k, v))
        return list(zip(*output))


class ClearAdminVolume(Lister):
    """Clear volume incident date."""

    log = getLogger(__name__ + ".ClearAdminVolume")

    def get_parser(self, prog_name):
        parser = super(ClearAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            "volumes",
            metavar="<volumes>",
            nargs="+",
            help="IDs of the rawx services",
        )
        parser.add_argument(
            "--all",
            dest="clear_all",
            default=False,
            help="Clear all chunks entries",
            action="store_true",
        )
        parser.add_argument(
            "--before-incident",
            dest="before_incident",
            default=False,
            help="Clear all chunks entries before incident date",
            action="store_true",
        )
        parser.add_argument(
            "--repair",
            dest="repair",
            default=False,
            help="Repair all chunks entries",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        volumes = parsed_args.volumes

        results = []
        reqid = self.app.request_id()
        for volume in volumes:
            try:
                resp_body = self.app.client_manager.volume.volume_admin_clear(
                    volume,
                    clear_all=parsed_args.clear_all,
                    before_incident=parsed_args.before_incident,
                    repair=parsed_args.repair,
                    reqid=reqid,
                )
                results.append((volume, True, resp_body))
            except OioException as exc:
                self.success = False
                results.append((volume, False, exc))
        columns = ("Volume", "Success", "Message")
        return columns, results


class ShowVolume(ShowOne):
    """
    Show various volume information, like number of indexed chunks,
    and names of containers having chunks on this volume.
    """

    log = getLogger(__name__ + ".ShowVolume")

    def get_parser(self, prog_name):
        parser = super(ShowVolume, self).get_parser(prog_name)
        parser.add_argument(
            "volume",
            metavar="<volume>",
            help="ID of the rawx service",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        data = self.app.client_manager.volume.volume_show(
            volume=parsed_args.volume,
            read_timeout=60.0,
            reqid=self.app.request_id(),
        )
        return list(zip(*sorted(data.items())))


class IncidentAdminVolume(Lister):
    """Declare an incident on the specified volume."""

    log = getLogger(__name__ + ".IncidentAdminVolume")

    def get_parser(self, prog_name):
        parser = super(IncidentAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            "volumes",
            metavar="<volumes>",
            nargs="+",
            help="IDs of the rawx services",
        )
        parser.add_argument(
            "--date",
            metavar="<key>",
            default=[],
            type=int,
            action="append",
            help="Incident date to set (seconds since Epoch)",
        )
        return parser

    def take_action(self, parsed_args):
        from time import time

        self.log.debug("take_action(%s)", parsed_args)

        volumes = parsed_args.volumes
        dates = parsed_args.date

        results = []
        reqid = self.app.request_id()
        for volume in volumes:
            date = dates.pop(0) if dates else int(time())
            self.app.client_manager.volume.volume_admin_incident(
                volume,
                date,
                reqid=reqid,
            )
            results.append((volume, date))
        columns = ("Volume", "Date")
        return columns, results


class LockAdminVolume(Lister):
    """
    Lock the specified volumes.
    Useful to prevent several rebuilders to work on the same volume.
    """

    log = getLogger(__name__ + ".LockAdminVolume")

    def get_parser(self, prog_name):
        parser = super(LockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            "volumes", metavar="<volumes>", nargs="+", help="IDs of the rawx services"
        )
        parser.add_argument(
            "--key",
            metavar="<key>",
            required=True,
            help="Identifier of what is locking the volume",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        volumes = parsed_args.volumes
        key = parsed_args.key

        results = []
        reqid = self.app.request_id()
        for volume in volumes:
            self.app.client_manager.volume.volume_admin_lock(
                volume,
                key,
                reqid=reqid,
            )
            results.append((volume, True))
        columns = ("Volume", "Success")
        return columns, results


class UnlockAdminVolume(Lister):
    """Unlock the specified volumes."""

    log = getLogger(__name__ + ".UnlockAdminVolume")

    def get_parser(self, prog_name):
        parser = super(UnlockAdminVolume, self).get_parser(prog_name)
        parser.add_argument(
            "volumes", metavar="<volumes>", nargs="+", help="IDs of the rawx services"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        volumes = parsed_args.volumes

        results = []
        reqid = self.app.request_id()
        for volume in volumes:
            self.app.client_manager.volume.volume_admin_unlock(volume, reqid=reqid)
            results.append((volume, True))
        columns = ("Volume", "Success")
        return columns, results
