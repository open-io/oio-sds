# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2022 OVH SAS
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

from kazoo.client import KazooClient
from kazoo.exceptions import KazooException
from six import iteritems
from logging import getLogger

from oio.cli import Lister


def format_json(parsed_args, json):
    from oio.common.json import json as jsonlib

    if json and parsed_args.formatter == 'table':
        json = jsonlib.dumps(json, indent=4, sort_keys=True)
    return json


class ElectionCmd(Lister):
    """Base class for election subcommands"""

    log = getLogger(__name__ + '.Election')
    reqid_prefix = "ACLI-EL-"

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
        parser.add_argument(
            '--service-id',
            metavar='<service-id>',
            action='append',
            help="Query only this service ID")

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
            account = self.app.options.account
            reference = parsed_args.reference
            cid = None
        return service_type, account, reference, cid


class ElectionPing(ElectionCmd):
    """Trigger or refresh an election."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.admin.election_ping(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout,
            service_id=parsed_args.service_id)

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

        data = self.app.client_manager.admin.election_status(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout,
            service_id=parsed_args.service_id)

        columns = ('Id', 'Status', 'Message')
        data = sorted(iteritems(data["peers"]))
        results = ((k, v["status"]["status"], v["status"]["message"]
                    ) for k, v in data)
        return columns, results


class ElectionCheckPeers(ElectionCmd):
    """
    Check that the peers registered in the directory and in Zookeeper
    are the same. Optionally try to delete rogue nodes.
    """

    def get_parser(self, prog_name):
        parser = super(ElectionCheckPeers, self).get_parser(prog_name)
        parser.add_argument(
            '--clean', action='store_true',
            help="Try to delete rogue nodes from Zookeeper")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        reqid = self.app.request_id(self.reqid_prefix)
        data = self.app.client_manager.admin.election_debug(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout,
            service_id=parsed_args.service_id, reqid=reqid)
        valid_resps = [x for x in data.items()
                       if x[1]['status']['status'] == 200]
        zk_servers = ','.join(x[1]['body']['base']['zk_server']
                              for x in valid_resps)
        zk = KazooClient(hosts=zk_servers, logger=self.log)
        real_peers = list(data.keys())
        zk_node = valid_resps[0][1]['body']['base']['zk']
        parent_node, node_prefix = zk_node.rsplit('/', 1)
        zk.start()
        try:
            master_found = False
            rogue_found = False
            results = []
            nodes = [n for n in zk.get_children(parent_node)
                     if n.startswith(node_prefix)]
            nodes.sort()
            for node in nodes:
                node_path = f'{parent_node}/{node}'
                svc_host = zk.get(node_path)[0].decode('utf-8')
                if svc_host not in real_peers:
                    rogue_found = True
                    self.log.warning(
                        'Rogue node %s left by %s, not in peers %s',
                        node_path, svc_host, ','.join(real_peers))
                    if parsed_args.clean:
                        # TODO(FVE): ask the peer to leave the election
                        # Sometimes the peer is still alive and will
                        # create a rogue node right after we delete it...
                        # Note that we must start by the last rogue node
                        # or the second will become master.
                        try:
                            zk.delete(node_path)
                            results.append((node_path, svc_host, "rogue",
                                            "deleted"))
                            self.log.warning(
                                'Rogue node %s deleted', node_path)
                        except KazooException as exc:
                            results.append((node_path, svc_host, "rogue",
                                            str(exc)))
                            self.log.warning(
                                'Failed to delete %s: %s', node_path, exc)
                    else:
                        results.append((node_path, svc_host, "rogue", "None"))
                else:
                    if master_found:
                        status = "slave"
                    else:
                        status = "master"
                        master_found = True
                    if rogue_found:
                        status = "should be " + status
                    results.append((node_path, svc_host, status, "None"))

            columns = ('Node', 'Host', 'Status', 'Action')
            return columns, results
        finally:
            zk.stop()


class ElectionDebug(ElectionCmd):
    """Get debugging information about an election."""

    def get_parser(self, prog_name):
        parser = super(ElectionDebug, self).get_parser(prog_name)
        parser.add_argument('--human', action='store_true',
                            help="Display human-readable dates")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        reqid = self.app.request_id(self.reqid_prefix)
        data = self.app.client_manager.admin.election_debug(
            service_type=service_type, account=account, reference=reference,
            cid=cid, timeout=parsed_args.timeout,
            service_id=parsed_args.service_id, reqid=reqid)

        columns = ('Id', 'Status', 'Message', 'Body')
        data = sorted(iteritems(data))
        import time

        def format_item(x, v):
            if not v:
                return format_json(x, v)
            patched_times = list()
            for entry in v.get("log", []):
                date, bef, act, aft = entry.split(':', 3)
                secs = float(date)
                date = (time.strftime("%Y-%m-%d %H:%M:%S",
                                      time.localtime(secs / 1000.0)) +
                        '.%03d' % (secs % 1000))
                patched_times.append("%s %s, %s -> %s" % (date, bef, act, aft))
            v['log'] = patched_times
            return format_json(x, v)

        formatter = format_item if parsed_args.human else format_json
        results = ((k, v["status"]["status"], v["status"]["message"],
                    formatter(parsed_args, v["body"])
                    ) for k, v in data)
        return columns, results


class ElectionSync(ElectionCmd):
    """Try to synchronize a dubious election."""

    def get_parser(self, prog_name):
        parser = super(ElectionSync, self).get_parser(prog_name)
        parser.add_argument('--check-type', type=int, choices=(-1, 0, 1, 2),
                            default=-1,
                            help=("Choose how to check the database before "
                                  "syncing it. -1: use server default, "
                                  "0: do not check, 1: quick check, "
                                  "2: full check."))
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        service_type, account, reference, cid = self.get_params(parsed_args)

        data = self.app.client_manager.admin.election_sync(
            service_type, account=account, reference=reference, cid=cid,
            check_type=parsed_args.check_type,
            timeout=parsed_args.timeout, service_id=parsed_args.service_id)

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

        data = self.app.client_manager.admin.election_leave(
            service_type, account=account, reference=reference, cid=cid,
            timeout=parsed_args.timeout, service_id=parsed_args.service_id)

        columns = ('Id', 'Status', 'Message')
        data = sorted(iteritems(data))
        results = ((k, v["status"]["status"], v["status"]["message"])
                   for k, v in data)
        return columns, results


class ElectionBalance(Lister):
    """Ask all the services to leave many elections."""

    log = getLogger(__name__ + '.Election')

    def get_parser(self, prog_name):
        parser = super(ElectionBalance, self).get_parser(prog_name)
        parser.add_argument(
            'service_type',
            nargs='*',
            metavar='<service_type>',
            help="Service type")
        parser.add_argument(
            '--service-id',
            metavar='<service-id>',
            action='append',
            help="Query only this service ID")
        parser.add_argument(
            '--inactivity',
            type=int, default=0,
            help="Specify an inactivity in seconds."
                 " Ignored with --average")
        parser.add_argument(
            '--max', type=int, default=100,
            help="Do not leave more than `max` elections."
                 "Ignored with --average")
        parser.add_argument(
            '--average',
            action='store_true',
            help="Only rebalance on services higher than the average")
        parser.add_argument(
            '--timeout',
            default=32.0,
            type=float,
            help="Timeout toward the proxy (defaults to 32.0 seconds)")
        return parser

    def _balance(self, id_, max_, inactivity):
        return self.app.client_manager.admin.service_balance_elections(
                id_, max_ops=max_, inactivity=inactivity)

    def _srvtypes(self, parsed_args):
        srvtypes = ('meta0', 'meta1', 'meta2')
        if parsed_args.service_type:
            srvtypes = parsed_args.service_type
        for s in srvtypes:
            yield s

    def _allsrv(self, parsed_args):
        max_ = int(parsed_args.max)
        inactivity = int(parsed_args.inactivity)
        if parsed_args.service_id:
            for id_ in parsed_args.service_id:
                yield id_, max_, inactivity
        else:
            for _st in self._srvtypes(parsed_args):
                srvs = self.app.client_manager.conscience.all_services(
                        _st, full=False)
                for srv in srvs:
                    yield srv.get('id', srv['addr']), max_, inactivity

    def _above_average(self, allids):
        qualified = list()
        total = 0
        for id_, max_, inactivity in allids:
            masters = 0
            try:
                conf = self.app.client_manager.admin.service_get_info(id_)
                masters = conf.get('elections', {}).get('master', 0)
            except Exception:
                pass
            qualified.append((id_, max_, inactivity, masters))
            total += masters
        avg = 0
        if qualified:
            avg = total / len(qualified)
        for id_, max_, inactivity, masters in qualified:
            if masters > avg:
                yield id_, (masters - avg), 0
            else:
                yield id_, 0, 0

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        data = list()
        if parsed_args.average:
            if len(parsed_args.service_type) != 1:
                raise ValueError("The --average option only works with"
                                 " exactly 1 type of service")
        allids = self._allsrv(parsed_args)
        if parsed_args.average:
            allids = self._above_average(allids)
        for id_, max_, inactivity in allids:
            if max_ > 0:
                rc, count = self._balance(id_, max_, inactivity)
            else:
                rc, count = 0, 0
            data.append((id_, rc, count))

        columns = ('Id', 'Status', 'Count')
        return columns, data
