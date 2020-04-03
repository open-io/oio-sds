# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

from __future__ import print_function

from oio.common.green import Queue, GreenPile, sleep

from logging import getLogger, INFO

from oio.cli import Command
from oio.common.exceptions import \
        ClientException, ConfigurationException, PreconditionFailed
from oio.common import green
from oio.directory.meta0 import generate_prefixes, count_prefixes


M0_CONN_TIMEOUT = 30.0
M0_READ_TIMEOUT = 60.0


class DirectoryCmd(Command):
    """Base class for directory subcommands"""

    log = getLogger(__name__ + '.Directory')

    def get_parser(self, prog_name):
        parser = super(DirectoryCmd, self).get_parser(prog_name)
        parser.add_argument(
            '--no-rdir', action='store_true', help='Deprecated')
        parser.add_argument(
            '--replicas', metavar='<N>', dest='replicas',
            type=int, default=3,
            help='Set the number of replicas (3 by default)')
        parser.add_argument(
            '--min-dist',
            type=int, default=1,
            help="Minimum distance between replicas")
        parser.add_argument(
            '--meta0-timeout', metavar='<SECONDS>',
            type=float, default=M0_READ_TIMEOUT,
            help=("Timeout for meta0-related operations (%.3fs by default)" %
                  M0_READ_TIMEOUT))
        return parser

    def get_prefix_mapping(self, parsed_args):
        """
        Create a meta0 prefix mapping with the parsed parameters.
        """
        from oio.directory.meta0 import Meta0PrefixMapping

        meta0_client = self.app.client_manager.directory.meta0
        conscience_client = self.app.client_manager.directory.cluster
        digits = self.app.client_manager.meta1_digits
        return Meta0PrefixMapping(meta0_client,
                                  conscience_client=conscience_client,
                                  replicas=parsed_args.replicas,
                                  digits=digits,
                                  min_dist=parsed_args.min_dist,
                                  logger=self.log)

    def _apply(self, mapping, moved=None,
               max_attempts=7, read_timeout=M0_READ_TIMEOUT):
        """
        Upload the specified mapping to the meta0 service,
        retry in case or error.
        """
        self.log.info("Saving...")
        for i in range(max_attempts):
            try:
                mapping.apply(moved=moved,
                              connection_timeout=M0_CONN_TIMEOUT,
                              read_timeout=read_timeout)
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


class DirectoryCheck(DirectoryCmd):
    """
    Check that the service directory is ok.

    Currently only checks that all meta1 prefixes have the right number
    of replicas. More checks can be performed by running
    'openio-admin directory check'.
    """

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_meta0(read_timeout=parsed_args.meta0_timeout)
        if mapping.check_replicas():
            self.log.info("Everything is ok.")
        else:
            self.log.warn("Errors found.")
            self.success = False


class DirectoryInit(DirectoryCmd):
    """
    Initialize the service directory.

    Distribute database prefixes among meta1 services and fill the meta0.
    """

    def get_parser(self, prog_name):
        parser = super(DirectoryInit, self).get_parser(prog_name)
        parser.add_argument(
            '--level', metavar='<LEVEL>', dest='level',
            choices=('site', 'rack', 'host', 'volume'), default='volume',
            help='Which location level should be perfectly balanced')
        parser.add_argument(
            '--degradation', metavar='<DEGRADATION>', dest='degradation',
            type=int, default=None,
            help='How many location levels we accept to lose to keep the '
                 'quorums valid. Not set by default, it is then autodetected '
                 'to the replication set minus the quorum')
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
        # Pre-check
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_meta0(read_timeout=parsed_args.meta0_timeout)
        if mapping and not parsed_args.force:
            self.log.info("Meta1 prefix mapping already initialized")
            if not parsed_args.check:
                return True
            self.log.info("Checking...")
            return mapping.check_replicas()

        if parsed_args.degradation is None:
            quorum = parsed_args.replicas // 2 + 1
            parsed_args.degradation = parsed_args.replicas - quorum

        # Reset and bootstrap
        mapping = self.get_prefix_mapping(parsed_args)
        try:
            mapping.bootstrap(level=parsed_args.level,
                              degradation=parsed_args.degradation)
        except ConfigurationException:
            self.log.warn("Namespace poorly configured, some meta1 services "
                          "carry no location or an invalid one.")
            raise
        except PreconditionFailed:
            self.log.warn("Namespace too constrained, please consider a "
                          "less constrained setup, using either --level or "
                          "--degradation with different values.")
            raise

        if mapping.check_replicas():
            self._apply(mapping, read_timeout=parsed_args.meta0_timeout)
            return True
        else:
            raise Exception("Failed to initialize prefix mapping")

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        checked = self._assign_meta1(parsed_args)

        if checked:
            self.log.info("Done")
        else:
            self.log.warn("Errors encountered")
            raise Exception("Bad meta1 prefix mapping")


class DirectoryList(DirectoryCmd):
    """
    List the content of meta0 database as a JSON object.
    The output can be used later to restore the database.

    WARNING: output is >2MB.
    """

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_meta0(connection_timeout=M0_CONN_TIMEOUT,
                           read_timeout=parsed_args.meta0_timeout)
        print(mapping.to_json())


class DirectoryRebalance(DirectoryCmd):
    """
    Rebalance the container prefixes.

    WARNING: A maximum of 1 service per prefixe is modified
    """

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_meta0(read_timeout=parsed_args.meta0_timeout)
        moved = mapping.rebalance()
        if mapping.check_replicas():
            self._apply(mapping, moved=moved,
                        read_timeout=parsed_args.meta0_timeout)
            self.log.info("Moved %s", moved)
        else:
            self.log.warn("Nothing done due to errors")
            self.success = False


class DirectoryRestore(DirectoryCmd):
    """
    Restore the content of meta0 database from a JSON object.

    Use with caution.
    """

    def get_parser(self, prog_name):
        parser = super(DirectoryRestore, self).get_parser(prog_name)
        parser.add_argument(
            'backup', help='Path to the JSON-formatted backup file, or "-".')
        parser.add_argument(
            '--I-know-what-I-am-doing', action='store_true',
            help='Confirm that you know what you are doing.')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        if parsed_args.backup == '-':
            self.log.info('Loading from stdin...')
            from sys import stdin
            backup = stdin.read()
        else:
            with open(parsed_args.backup, 'r') as inputf:
                self.log.info('Loading from %s...', parsed_args.backup)
                backup = inputf.read()
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_json(backup)
        self.log.info('Checking...')
        if mapping.check_replicas():
            self.log.info('OK')
        elif parsed_args.I_know_what_I_am_doing:
            self.log.info('Errors encountered, but "I know what I am doing".')
        else:
            raise Exception('Bad meta1 prefix mapping')
        if parsed_args.I_know_what_I_am_doing:
            self.log.info('Applying...')
            self._apply(mapping, read_timeout=parsed_args.meta0_timeout)
        else:
            self.log.info('Please tell me that you know what you are doing.')


class DirectoryDecommission(DirectoryCmd):
    """
    Decommission a Meta1 service (or only some bases).
    """

    def get_parser(self, prog_name):
        parser = super(DirectoryDecommission, self).get_parser(prog_name)
        parser.add_argument('addr', metavar='<ADDR>',
                            help='Address of service to decommission')
        parser.add_argument('base', metavar='<BASE>', nargs='*',
                            help="Name of bases to decommission")
        parser.add_argument('--ignore-replicas-number-errors',
                            action='store_true',
                            help=("Continue even if the number of replicas "
                                  "is not as expected. Dangerous."))

        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        # Ensure we see 'info' logs.
        if self.log.getEffectiveLevel() > INFO:
            self.log.setLevel(INFO)
        mapping = self.get_prefix_mapping(parsed_args)
        mapping.load_meta0(read_timeout=parsed_args.meta0_timeout)
        self.log.info("meta1_digits=%d", mapping.digits)
        moved = mapping.decommission(parsed_args.addr,
                                     bases_to_remove=parsed_args.base)
        if (mapping.check_replicas() or
                parsed_args.ignore_replicas_number_errors):
            self._apply(mapping, moved=moved,
                        read_timeout=parsed_args.meta0_timeout)
            self.log.info("Moved %s", sorted(moved))
        else:
            self.log.warn("Did nothing due to errors.")
            self.log.warn("If the errors are not related to the bases "
                          "you want to decommission, try to rebalance.")
            return 1


class DirectoryWarmup(DirectoryCmd):
    """Ping each prefix of a Meta0 hash to prepare each Meta1 base"""

    def get_parser(self, prog_name):
        parser = super(DirectoryWarmup, self).get_parser(prog_name)
        parser.add_argument('--concurrency', '--workers', type=int, default=1,
                            help="How many concurrent bases to warm up")
        parser.add_argument('--proxy', type=str, default=None,
                            help="Specific proxy IP:PORT")
        return parser

    def _ping_prefix(self, prefix):
        pass

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        digits = self.app.client_manager.meta1_digits
        concurrency = parsed_args.concurrency

        conf = {'namespace': self.app.client_manager.namespace}
        if parsed_args.proxy:
            conf.update({'proxyd_url': parsed_args.proxy})
        else:
            ns_conf = self.app.client_manager.sds_conf
            proxy = ns_conf.get('proxy')
            conf.update({'proxyd_url': proxy})

        workers = list()
        with green.ContextPool(concurrency) as pool:
            pile = GreenPile(pool)
            prefix_queue = Queue(16)

            # Prepare some workers
            for _ in range(concurrency):
                worker = WarmupWorker(self.app.client_manager.client_conf,
                                      self.log)
                workers.append(worker)
                pile.spawn(worker.run, prefix_queue)

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
        from oio.common.http_urllib3 import get_pool_manager
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
                sleep(i * 0.5)
            else:
                break
