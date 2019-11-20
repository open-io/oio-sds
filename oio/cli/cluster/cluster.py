# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.cli import Lister, ShowOne
from oio.common.easy_value import boolean_value
from oio.common.exceptions import OioException, OioNetworkException, \
    ServiceBusy


def _batches_boundaries(srclen, size):
    for start in range(0, srclen, size):
        end = min(srclen, start + size)
        yield start, end


def _bounded_batches(src, size=1000):
    for start, end in _batches_boundaries(len(src), size):
        yield src[start:end]


class ClusterShow(ShowOne):
    """Show general information about the cluster."""

    log = getLogger(__name__ + '.ClusterShow')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.conscience.info()
        output = list()
        output.append(('namespace', data['ns']))
        output.append(('chunksize', data['chunksize']))
        for k, v in data['storage_policy'].iteritems():
            output.append(('storage_policy.%s' % k, v))
        for k, v in data['data_security'].iteritems():
            output.append(('data_security.%s' % k, v))
        for k, v in data['service_pools'].iteritems():
            output.append(('service_pool.%s' % k, v))
        for k, v in sorted(data['options'].iteritems()):
            output.append((k, v))
        return zip(*output)


class ClusterList(Lister):
    """List services of the namespace."""

    log = getLogger(__name__ + '.ClusterList')

    def get_parser(self, prog_name):
        parser = super(ClusterList, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_type>',
            nargs='*',
            help='Type of services to list.')
        parser.add_argument(
            '--stats', '--full',
            action='store_true',
            help='Display service statistics.')
        return parser

    def _list_services(self, parsed_args):
        if not parsed_args.srv_types:
            parsed_args.srv_types = \
                    self.app.client_manager.conscience.service_types()
        for srv_type in parsed_args.srv_types:
            try:
                data = self.app.client_manager.conscience.all_services(
                    srv_type, parsed_args.stats)
            except OioException as exc:
                self.success = False
                self.log.error("Failed to list services of type %s: %s",
                               srv_type, exc)
                continue
            for srv in data:
                tags = srv['tags']
                location = tags.get('tag.loc', 'n/a')
                slots = tags.get('tag.slots', 'n/a')
                volume = tags.get('tag.vol', 'n/a')
                service_id = tags.get('tag.service_id', 'n/a')
                addr = srv['addr']
                locked = boolean_value(tags.get('tag.lock'), False)
                up = tags.get('tag.up', 'n/a')
                score = srv['score']
                if parsed_args.stats:
                    stats = ["%s=%s" % (k, v) for k, v in tags.items()
                             if k.startswith('stat.')]
                    values = (srv_type, addr, service_id, volume, location,
                              slots, up, score, locked, " ".join(stats))
                else:
                    values = (srv_type, addr, service_id, volume, location,
                              slots, up, score, locked)
                yield values

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        if parsed_args.stats:
            columns = ('Type', 'Addr', 'Service Id', 'Volume', 'Location',
                       'Slots', 'Up', 'Score', 'Locked', 'Stats')
        else:
            columns = ('Type', 'Addr', 'Service Id', 'Volume', 'Location',
                       'Slots', 'Up', 'Score', 'Locked')
        return columns, self._list_services(parsed_args)


class ClusterLocalList(Lister):
    """List local services."""

    log = getLogger(__name__ + '.ClusterLocalList')

    def get_parser(self, prog_name):
        parser = super(ClusterLocalList, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='*',
            help='Service type(s).')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        results = []
        srv_types = parsed_args.srv_types
        local_scores = boolean_value(
            self.app.client_manager.sds_conf.get('proxy.quirk.local_scores'),
            False)
        if not local_scores:
            self.log.warn("'proxy.quirk.local_scores' not set, "
                          "scores won't be realistic.")
        data = self.app.client_manager.conscience.local_services()
        for srv in data:
            tags = srv['tags']
            location = tags.get('tag.loc', 'n/a')
            slots = tags.get('tag.slots', 'n/a')
            volume = tags.get('tag.vol', 'n/a')
            service_id = tags.get('tag.service_id', 'n/a')
            addr = srv['addr']
            up = tags.get('tag.up', 'n/a')
            score = srv['score']
            locked = boolean_value(tags.get('tag.lock'), False)
            srv_type = srv['type']
            if not srv_types or srv_type in srv_types:
                results.append((srv_type, addr, service_id, volume, location,
                                slots, up, score, locked))
        columns = ('Type', 'Addr', 'Service Id', 'Volume', 'Location',
                   'Slots', 'Up', 'Score', 'Locked')
        result_gen = (r for r in results)
        return columns, result_gen


class ClusterUnlock(Lister):
    """Unlock the score of specific services of the cluster."""

    log = getLogger(__name__ + '.ClusterUnlock')

    def get_parser(self, prog_name):
        parser = super(ClusterUnlock, self).get_parser(prog_name)
        parser.add_argument(
            'srv_type',
            metavar='<srv_type>',
            help='Service type.')
        parser.add_argument(
            'srv_ids',
            metavar='<srv_ids>',
            nargs='+',
            help='ID(s) of the services.')
        return parser

    def _unlock_services(self, parsed_args):
        srv_definitions = list()
        for srv_id in parsed_args.srv_ids:
            srv_definitions.append(
                self.app.client_manager.conscience.get_service_definition(
                    parsed_args.srv_type, srv_id))
        for batch in _bounded_batches(srv_definitions):
            result = "unlocked"
            try:
                self.app.client_manager.conscience.unlock_score(batch)
            except Exception as exc:
                self.success = False
                result = str(exc)
            for srv_definition in batch:
                yield (srv_definition['type'], srv_definition['addr'],
                       result)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        res = self._unlock_services(parsed_args)
        return (('Type', 'Service', 'Result'), res)


class ClusterUnlockAll(Lister):
    """Unlock all services of the cluster."""

    log = getLogger(__name__ + '.ClusterUnlockAll')

    def get_parser(self, prog_name):
        parser = super(ClusterUnlockAll, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='*',
            help='Service type(s) (or all if unset).')
        return parser

    def _unlock_all_services(self, parsed_args):
        srv_types = parsed_args.srv_types
        if not parsed_args.srv_types:
            srv_types = self.app.client_manager.conscience.service_types()
        for srv_type in srv_types:
            try:
                srv_definitions = \
                    self.app.client_manager.conscience.all_services(srv_type)
            except OioException as exc:
                self.success = False
                self.log.error("Failed to list services of type %s: %s",
                               srv_type, exc)
                continue
            for srv_definition in srv_definitions:
                srv_definition['type'] = srv_type
            for batch in _bounded_batches(srv_definitions):
                result = "unlocked"
                try:
                    self.app.client_manager.conscience.unlock_score(batch)
                except Exception as exc:
                    self.success = False
                    result = str(exc)
                for srv_definition in batch:
                    yield (srv_definition['type'],
                           srv_definition['addr'],
                           result)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        res = self._unlock_all_services(parsed_args)
        return (('Type', 'Service', 'Result'), res)


def _sleep_interval(*tab):
    for v in tab:
        yield v
    while True:
        yield tab[-1]


class ClusterWait(Lister):
    """Wait for services to get a score above specified value."""

    log = getLogger(__name__ + '.ClusterWait')

    def get_parser(self, prog_name):
        parser = super(ClusterWait, self).get_parser(prog_name)
        parser.add_argument(
            'types',
            metavar='<types>',
            nargs='*',
            help='Service type(s) to wait for (or all if unset).')
        parser.add_argument(
            '-n', '--count',
            metavar='<count>',
            type=int,
            default=0,
            help=('How many services are expected (0 by default).'))
        parser.add_argument(
            '-d', '--delay',
            metavar='<delay>',
            type=float,
            default=15.0,
            help='How long to wait for a score (15s by default).')
        parser.add_argument(
            '-s', '--score',
            metavar='<score>',
            type=int,
            default=1,
            help=('Minimum score value required for the chosen services '
                  '(1 by default).'))
        parser.add_argument(
            '-u', '--unlock',
            action='store_true',
            default=False,
            help='Should the service be unlocked.')
        return parser

    def _wait(self, parsed_args):
        from time import time as now, sleep

        min_score = parsed_args.score
        delay = parsed_args.delay
        deadline = now() + delay
        descr = []
        ko = -1
        exc_msg = ("Timeout ({0}s) while waiting for the services to get a "
                   "score >= {1}, {2}")

        def maybe_unlock(allsrv):
            if not parsed_args.unlock:
                return
            if not allsrv:
                return
            self.app.client_manager.conscience.unlock_score(allsrv)

        def check_deadline():
            if now() > deadline:
                if ko < 0:
                    msg = exc_msg.format(delay, min_score,
                                         "proxy and/or conscience not ready")
                else:
                    msg = exc_msg.format(delay, min_score,
                                         "still %d are not." % ko)
                for srv in descr:
                    if srv['score'] < min_score:
                        self.log.warn(
                            "%s %s %s",
                            srv['type'], srv.get('id', None), srv['score'])
                raise Exception(msg)

        interval = _sleep_interval(0.0, 1.0, 2.0, 4.0)
        types = parsed_args.types
        if not parsed_args.types:
            while True:
                check_deadline()
                sleep(next(interval))

                try:
                    types = self.app.client_manager.conscience.service_types()
                    break
                except OioNetworkException as exc:
                    self.log.debug("Proxy error: %s", exc)
                except ServiceBusy as exc:
                    self.log.debug("Conscience busy: %s", exc)

        interval = _sleep_interval(0.0, 1.0, 2.0, 4.0)
        while True:
            check_deadline()
            maybe_unlock(descr)
            sleep(next(interval))

            descr = []
            ko = -1
            try:
                for typ in types:
                    tmp = self.app.client_manager.conscience.all_services(typ)
                    for srv in tmp:
                        srv['type'] = typ
                    descr += tmp
            except OioNetworkException as exc:
                self.log.debug("Proxy error: %s", exc)
                continue
            except ServiceBusy as exc:
                self.log.debug("Conscience busy: %s", exc)
                continue

            ko = len([s['score'] for s in descr if s['score'] < min_score])
            if ko > 0:
                self.log.debug("Still %d services down", ko)
                continue

            # If a minimum has been specified, let's check we have enough
            # services
            if parsed_args.count:
                ok = len([s for s in descr if s['score'] >= min_score])
                if ok < parsed_args.count:
                    self.log.debug("Only %d services up", ok)
                    continue

            # No service down, and enough services, we are done.
            for srv in descr:
                yield srv['type'], srv['addr'], srv['score']
            return

    def take_action(self, parsed_args):
        columns = ('Type', 'Service', 'Score')
        return columns, self._wait(parsed_args)


class ClusterLock(ClusterUnlock):
    """Lock the score of a service."""

    log = getLogger(__name__ + '.ClusterLock')

    def get_parser(self, prog_name):
        parser = super(ClusterLock, self).get_parser(prog_name)
        parser.add_argument(
            '-s', '--score',
            metavar='<score>',
            type=int,
            default=0,
            help='Score to set (0 by default).'
        )
        return parser

    def _lock_services(self, parsed_args):
        srv_definitions = list()
        for srv_id in parsed_args.srv_ids:
            srv_definitions.append(
                self.app.client_manager.conscience.get_service_definition(
                    parsed_args.srv_type, srv_id, score=parsed_args.score))
        for batch in _bounded_batches(srv_definitions):
            result = "locked to %d" % int(parsed_args.score)
            try:
                self.app.client_manager.conscience.lock_score(batch)
            except Exception as exc:
                self.success = False
                result = str(exc)
            for srv_definition in batch:
                yield (srv_definition['type'], srv_definition['addr'],
                       result)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        res = self._lock_services(parsed_args)
        return (('Type', 'Service', 'Result'), res)


class ClusterFlush(Lister):
    """Deregister all services of the cluster."""

    log = getLogger(__name__ + '.ClusterFlush')

    def get_parser(self, prog_name):
        parser = super(ClusterFlush, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='*',
            help='Service type(s) (or all if unset).')
        return parser

    def _flush_srv_types(self, parsed_args):
        srv_types = parsed_args.srv_types
        if not parsed_args.srv_types:
            srv_types = self.app.client_manager.conscience.service_types()
        for srv_type in srv_types:
            result = "flushed"
            try:
                self.app.client_manager.conscience.flush(srv_type)
            except Exception as err:
                self.success = False
                result = err
            yield (srv_type, result)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        res = self._flush_srv_types(parsed_args)
        return (('Type', 'Result'), res)


class ClusterDeregister(Lister):
    """Deregister specific services of the cluster."""

    log = getLogger(__name__ + '.ClusterDeregister')

    def get_parser(self, prog_name):
        parser = super(ClusterDeregister, self).get_parser(prog_name)
        parser.add_argument(
            'srv_type',
            help='Service type.')
        parser.add_argument(
            'srv_ids',
            metavar='<srv_ids>',
            nargs='+',
            help='ID(s) of the services.')
        return parser

    def _deregister_services(self, parsed_args):
        srv_definitions = list()
        for srv_id in parsed_args.srv_ids:
            srv_definitions.append(
                self.app.client_manager.conscience.get_service_definition(
                    parsed_args.srv_type, srv_id))
        for batch in _bounded_batches(srv_definitions):
            result = "deregistered"
            try:
                self.app.client_manager.conscience.deregister(batch)
            except Exception as exc:
                self.success = False
                result = str(exc)
            for srv_definition in batch:
                yield (srv_definition['type'], srv_definition['addr'],
                       result)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        res = self._deregister_services(parsed_args)
        return (('Type', 'Service', 'Result'), res)


class ClusterResolve(ShowOne):
    """Resolve a service ID to an IP address and port."""

    log = getLogger(__name__ + '.ClusterFlush')

    def get_parser(self, prog_name):
        parser = super(ClusterResolve, self).get_parser(prog_name)
        parser.add_argument(
            'srv_type',
            help='Service type.')
        parser.add_argument(
            'srv_id',
            help='ID of the service.'
        )

        return parser

    def take_action(self, parsed_args):
        resolved = self.app.client_manager.conscience.resolve(
            parsed_args.srv_type, parsed_args.srv_id)
        return zip(*resolved.items())


class LocalNSConf(ShowOne):
    """Show namespace configuration values locally configured."""

    log = getLogger(__name__ + '.LocalNSConf')

    def get_parser(self, prog_name):
        parser = super(LocalNSConf, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        namespace = self.app.client_manager.client_conf['namespace']
        sds_conf = self.app.client_manager.sds_conf
        output = list()
        for k in sds_conf:
            output.append(("%s/%s" % (namespace, k), sds_conf[k]))
        return zip(*output)
