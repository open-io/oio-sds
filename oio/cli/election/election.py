# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

from six import iteritems
from logging import getLogger
from cliff.lister import Lister


def format_json(parsed_args, json):
    from oio.common.json import json as jsonlib

    if json and parsed_args.formatter == 'table':
        json = jsonlib.dumps(json, indent=4, sort_keys=True)
    return json


class ElectionCmd(Lister):
    """Base class for election subcommands"""

    log = getLogger(__name__ + '.Election')

    def get_parser(self, prog_name):
        parser = super(ElectionCmd, self).get_parser(prog_name)
        parser.add_argument(
            'service_type',
            help="Service type")
        parser.add_argument(
            'reference',
            metavar='<reference>',
            help="Reference name")
        parser.add_argument(
            '--cid',
            dest='is_cid',
            default=False,
            help="Interpret <reference> as a CID",
            action='store_true')
        # TODO(FVE): add the timeout option to all openio subcommands
        # FVE: I chose 32s because the timeout between the proxy and the
        # services is usually 30s.
        parser.add_argument(
            '--timeout',
            default=32.0,
            type=float,
            help="Timeout toward the proxy (defaults to 32.0 seconds)")
        return parser

    def get_params(self, parsed_args):
        service_type = parsed_args.service_type
        if parsed_args.is_cid:
            cid = parsed_args.reference
            account = None
            reference = None
        else:
            account = self.app.client_manager.account
            reference = parsed_args.reference
            cid = None
        return service_type, account, reference, cid


class ElectionPing(ElectionCmd):
    """Trigger or refresh an election."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.election.election_ping(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout)

        columns = ('Id', 'Status', 'Message')
        data = sorted(iteritems(data))
        results = ((k, v["status"]["status"], v["status"]["message"]
                    ) for k, v in data)
        return columns, results


class ElectionStatus(ElectionCmd):
    """Get the status of an election (trigger it if necessary)."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.election.election_status(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout)

        columns = ('Id', 'Status', 'Message')
        data = sorted(iteritems(data["peers"]))
        results = ((k, v["status"]["status"], v["status"]["message"]
                    ) for k, v in data)
        return columns, results


class ElectionDebug(ElectionCmd):
    """Get debugging information about an election."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.election.election_debug(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout)

        columns = ('Id', 'Status', 'Message', 'Body')
        data = sorted(iteritems(data))
        results = ((k, v["status"]["status"], v["status"]["message"],
                    format_json(parsed_args, v["body"])
                    ) for k, v in data)
        return columns, results


class ElectionSync(ElectionCmd):
    """Try to synchronize a dubious election."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.election.election_sync(
            service_type, account=account, reference=reference, cid=cid,
            timeout=parsed_args.timeout)

        columns = ('Id', 'Status', 'Message', 'Body')
        data = sorted(iteritems(data))
        results = ((k, v["status"]["status"], v["status"]["message"],
                    format_json(parsed_args, v["body"])
                    ) for k, v in data)
        return columns, results


class ElectionLeave(ElectionCmd):
    """Ask all peers to leave an election."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.election.election_leave(
            service_type, account=account, reference=reference, cid=cid,
            timeout=parsed_args.timeout)

        columns = ('Id', 'Status', 'Message')
        data = sorted(iteritems(data))
        results = ((k, v["status"]["status"], v["status"]["message"])
                   for k, v in data)
        return columns, results
