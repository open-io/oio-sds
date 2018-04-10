# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
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

from logging import getLogger
from cliff.command import Command
from eventlet import Queue, GreenPile
from oio.common.configuration import load_namespace_conf
from oio.common.exceptions import ClientException
from oio.common import green
from oio.directory.meta0 import generate_prefixes, count_prefixes


class DirectoryCmd(Command):
    """Base class for directory subcommands"""

    log = getLogger(__name__ + '.Directory')

    def get_parser(self, prog_name):
        parser = super(DirectoryCmd, self).get_parser(prog_name)
        parser.add_argument('--replicas', metavar='<N>', dest='replicas',
                            type=int, default=3,
                            help='Set the number of replicas (3 by default)')
        parser.add_argument('--min-dist', type=int, default=1,
                            help="Minimum distance between replicas")
        parser.add_argument(
            '--meta0-timeout', metavar='<SECONDS>', type=float, default=60.0,
            help="Timeout for meta0-related operations (60.0s by default)")
        return parser

    def get_prefix_mapping(self, parsed_args):
        from oio.directory.meta0 import PrefixMapping

        meta0_client = self.app.client_manager.directory.meta0
        conscience_client = self.app.client_manager.directory.cluster
        digits = self.app.client_manager.meta1_digits
        return PrefixMapping(meta0_client, conscience_client,
                             replicas=parsed_args.replicas,
                             digits=digits,
                             min_dist=parsed_args.min_dist,
                             logger=self.log)


class DirectoryInit(DirectoryCmd):
    """
    Initialize the service directory.

    Distribute database prefixes among meta1 services and fill the meta0.
    """

    def get_parser(self, prog_name):
        parser = super(DirectoryInit, self).get_parser(prog_name)
        parser.add_argument(
            '--no-rdir', action='store_true', help='Deprecated')
        parser.add_argument(
            '--force',
            action='store_true',
            help="Do the bootstrap even if already done")
        parser.add_argument(
            '--check',
            action='store_true',
            help="Check that all prefixes have the right number of replicas")
        return parser

    def _assign_meta1(self, parsed_args):
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)

        if mapping and not parsed_args.force:
            self.log.info("Meta1 prefix mapping already initialized")
            if not parsed_args.check:
                return True
            self.log.info("Checking...")
            return mapping.check_replicas()

        # Bootstrap with the 'random' strategy, then rebalance with the
        # 'less_prefixes' strategy to ensure the same number of prefixes
        # per meta1. This is faster than bootstrapping directly with the
        # 'less_prefixes' strategy.
        checked = False
        for i in range(3):
            self.log.info("Computing meta1 prefix mapping (pass %d)", i)
            mapping.bootstrap()

            self.log.info("Equilibrating...")
            mapping.rebalance()

            if parsed_args.check:
                self.log.info("Checking...")
                checked = mapping.check_replicas()
            else:
                checked = True

            if checked:
                break

        if checked:
            from time import sleep
            self.log.info("Saving...")
            max_attempts = 7
            for i in range(max_attempts):
                try:
                    mapping.apply(connection_timeout=30.0,
                                  read_timeout=parsed_args.meta0_timeout)
                    break
                except ClientException as ex:
                    # Manage several unretriable errors
                    retry = (503, 504)
                    if ex.status >= 400 and ex.status not in retry:
                        raise
                    # Monotonic backoff (retriable and net errors)
                    if i < max_attempts - 1:
                        sleep(i * 1.0)
                        continue
                    # Too many attempts
                    raise
        else:
            raise Exception("Failed to initialize prefix mapping")
        return checked

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        if parsed_args.no_rdir:
            self.log.warn('--no-rdir option is deprecated')
        checked = self._assign_meta1(parsed_args)

        if checked:
            self.log.info("Done")
        else:
            self.log.warn("Errors encountered")
            raise Exception("Bad meta1 prefix mapping")


class DirectoryList(DirectoryCmd):
    """
    List the content of meta0 database as a JSON object.

    WARNING: output is >2MB.
    """

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(connection_timeout=30.0,
                     read_timeout=parsed_args.meta0_timeout)
        print(mapping.to_json())


class DirectoryRebalance(DirectoryCmd):
    """Rebalance the container prefixes."""

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)
        moved = mapping.rebalance()
        mapping.apply(moved, read_timeout=parsed_args.meta0_timeout)
        self.log.info("Moved %s", moved)


class DirectoryDecommission(DirectoryCmd):
    """Decommission a Meta1 service (or only some bases)."""

    def get_parser(self, prog_name):
        parser = super(DirectoryDecommission, self).get_parser(prog_name)
        parser.add_argument('addr', metavar='<ADDR>',
                            help='Address of service to decommission')
        parser.add_argument('base', metavar='<BASE>', nargs='*',
                            help="Name of bases to decommission")
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load(read_timeout=parsed_args.meta0_timeout)
        moved = mapping.decommission(parsed_args.addr,
                                     bases_to_remove=parsed_args.base)
        mapping.apply(moved, read_timeout=parsed_args.meta0_timeout)
        self.log.info("Moved %s", moved)


class DirectoryWarmup(DirectoryCmd):
    """Ping each prefix of a Meta0 hash to prepare each Meta1 base"""

    def get_parser(self, prog_name):
        parser = super(DirectoryWarmup, self).get_parser(prog_name)
        parser.add_argument('--workers', type=int, default=1,
                            help="How many concurrent bases to warm up")
        parser.add_argument('--proxy', type=str, default=None,
                            help="Specific proxy IP:PORT")
        return parser

    def _ping_prefix(self, prefix):
        pass

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        digits = self.app.client_manager.get_meta1_digits()
        workers_count = parsed_args.workers

        conf = {'namespace': self.app.client_manager.namespace}
        if parsed_args.proxy:
            conf.update({'proxyd_url': parsed_args.proxy})
        else:
            ns_conf = load_namespace_conf(conf['namespace'])
            proxy = ns_conf.get('proxy')
            conf.update({'proxyd_url': proxy})

        workers = list()
        with green.ContextPool(workers_count) as pool:
            pile = GreenPile(pool)
            prefix_queue = Queue(16)

            # Prepare some workers
            for i in range(workers_count):
                w = WarmupWorker(conf, self.log)
                workers.append(w)
                pile.spawn(w.run, prefix_queue)

            # Feed the queue
            trace_increment = 0.01
            trace_next = trace_increment
            sent, total = 0, float(count_prefixes(digits))
            for prefix in generate_prefixes(digits):
                sent += 1
                prefix_queue.put(prefix)
                # Display the progression
                ratio = float(sent) / total
                if ratio >= trace_next:
                    self.log.info("... %d%%", int(ratio * 100.0))
                    trace_next += trace_increment

            self.log.debug("Send the termination marker")
            prefix_queue.join()

        self.log.info("All the workers are done")


class WarmupWorker(object):
    def __init__(self, conf, log):
        from oio.common.http import get_pool_manager
        self.log = log
        self.pool = get_pool_manager()
        self.url_prefix = 'http://%s/v3.0/%s/admin/status?type=meta1&cid=' % (
                conf['proxyd_url'], conf['namespace'])

    def run(self, prefix_queue):
        while True:
            prefix = prefix_queue.get()
            self.ping(prefix)
            prefix_queue.task_done()

    def ping(self, prefix):
        url = self.url_prefix + prefix.ljust(64, '0')
        max_attempts = 5
        for i in range(max_attempts):
            rep = self.pool.request('POST', url)
            if rep.status == 200:
                return
            self.log.warn("%d %s", rep.status, prefix)
            if rep.status == 503:
                from eventlet import sleep
                sleep(i * 0.5)
            else:
                break
