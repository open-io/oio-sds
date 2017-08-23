import logging

from cliff import lister
from cliff import show
from cliff import command
from time import time as now, sleep

from oio.common.utils import load_namespace_conf


class ClusterShow(show.ShowOne):
    """Show information of all services in the cluster"""

    log = logging.getLogger(__name__ + '.ClusterShow')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.admin.cluster_info()
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


class ClusterList(lister.Lister):
    """List services of the namespace"""

    log = logging.getLogger(__name__ + '.ClusterList')

    def get_parser(self, prog_name):
        parser = super(ClusterList, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_type>',
            nargs='*',
            help='Type of services to list')
        parser.add_argument(
            '--stats', '--full',
            action='store_true',
            help='Display service statistics')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        results = []
        if not parsed_args.srv_types:
            parsed_args.srv_types = \
                    self.app.client_manager.admin.cluster_list_types()
        for srv_type in parsed_args.srv_types:
            data = self.app.client_manager.admin.cluster_list(
                srv_type, parsed_args.stats)
            for srv in data:
                tags = srv['tags']
                location = tags.get('tag.loc', 'n/a')
                slots = tags.get('tag.slots', 'n/a')
                volume = tags.get('tag.vol', 'n/a')
                addr = srv['addr']
                up = tags.get('tag.up', 'n/a')
                score = srv['score']
                if parsed_args.stats:
                    stats = ["%s=%s" % (k, v) for k, v in tags.items()
                             if k.startswith('stat.')]
                    values = (srv_type, addr, volume, location,
                              slots, up, score, " ".join(stats))
                else:
                    values = (srv_type, addr, volume, location,
                              slots, up, score)
                results.append(values)
        if parsed_args.stats:
            columns = ('Type', 'Id', 'Volume', 'Location', 'Slots', 'Up',
                       'Score', 'Stats')
        else:
            columns = ('Type', 'Id', 'Volume', 'Location', 'Slots', 'Up',
                       'Score')
        result_gen = (r for r in results)
        return columns, result_gen


class ClusterLocalList(lister.Lister):
    """List local services"""

    log = logging.getLogger(__name__ + '.ClusterLocalList')

    def get_parser(self, prog_name):
        parser = super(ClusterLocalList, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='*',
            help='Service Type(s)')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        results = []
        srv_types = parsed_args.srv_types
        data = self.app.client_manager.admin.cluster_local_list()
        for srv in data:
            tags = srv['tags']
            location = tags.get('tag.loc', 'n/a')
            slots = tags.get('tag.slots', 'n/a')
            volume = tags.get('tag.vol', 'n/a')
            addr = srv['addr']
            up = tags.get('tag.up', 'n/a')
            score = srv['score']
            srv_type = srv['type']
            if not srv_types or srv_type in srv_types:
                results.append((srv_type, addr, volume, location,
                                slots, up, score))
        columns = ('Type', 'Id', 'Volume', 'Location',
                   'Slots', 'Up', 'Score')
        result_gen = (r for r in results)
        return columns, result_gen


class ClusterUnlock(lister.Lister):
    """Unlock score"""

    log = logging.getLogger(__name__ + '.ClusterUnlock')

    def get_parser(self, prog_name):
        parser = super(ClusterUnlock, self).get_parser(prog_name)
        parser.add_argument(
            'srv_type',
            metavar='<srv_type>',
            help='Service Type')
        parser.add_argument(
            'srv_addr',
            metavar='<srv_addr>',
            help='Network address of the service'
        )
        return parser

    def _unlock_one(self, type_, addr):
        service_info = {'type': type_, 'addr': addr}
        try:
            self.app.client_manager.admin.cluster_unlock_score(service_info)
            yield type_, addr, "unlocked"
        except Exception as exc:
            yield type_, addr, str(exc)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        return (('Type', 'Service', 'Result'),
                self._unlock_one(parsed_args.srv_type, parsed_args.srv_addr))


class ClusterUnlockAll(lister.Lister):
    """Unlock all services of the cluster"""

    log = logging.getLogger(__name__ + '.ClusterUnlockAll')

    def get_parser(self, prog_name):
        parser = super(ClusterUnlockAll, self).get_parser(prog_name)
        parser.add_argument(
            'types',
            metavar='<types>',
            nargs='*',
            help='Service Type(s) to unlock (or all if unset)')
        return parser

    def _unlock_all(self, parsed_args):
        types = parsed_args.types
        if not parsed_args.types:
            types = self.app.client_manager.admin.cluster_list_types()
        for type_ in types:
            all_descr = self.app.client_manager.admin.cluster_list(type_)
            for descr in all_descr:
                descr['type'] = type_
            try:
                self.app.client_manager.admin.cluster_unlock_score(all_descr)
                for descr in all_descr:
                    yield type_, descr['addr'], "unlocked"
            except Exception as exc:
                for descr in all_descr:
                    yield type_, descr['addr'], str(exc)

    def take_action(self, parsed_args):
        columns = ('Type', 'Service', 'Result')
        return columns, self._unlock_all(parsed_args)


class ClusterWait(lister.Lister):
    """Wait for the services to get a score"""

    log = logging.getLogger(__name__ + '.ClusterWait')

    def get_parser(self, prog_name):
        parser = super(ClusterWait, self).get_parser(prog_name)
        parser.add_argument(
            'types',
            metavar='<types>',
            nargs='*',
            help='Service Type(s) to wait for (or all if unset)')
        parser.add_argument(
            '-d', '--delay',
            metavar='<delay>',
            type=float,
            default=15.0,
            help='How long to wait for a score')
        return parser

    def _wait(self, parsed_args):

        types = parsed_args.types
        if not parsed_args.types:
            types = self.app.client_manager.admin.cluster_list_types()

        delay = float(parsed_args.delay)
        deadline = now() + delay

        while True:
            all_descr = []
            for type_ in types:
                tmp = self.app.client_manager.admin.cluster_list(type_)
                for s in tmp:
                    s['type'] = type_
                all_descr += tmp
            ko = len([s['score'] for s in tmp if s['score'] <= 0])
            if ko <= 0:
                for descr in all_descr:
                    yield descr['type'], descr['addr'], descr['score']
                return
            else:
                self.log.debug("Still %d services down", ko)
                if now() > deadline:
                    raise Exception(
                            "Timeout ({0}s) while waiting ".format(delay) +
                            "for the services to get a score, still " +
                            "{0} are zeroed".format(ko))
                else:
                    sleep(1.0)

    def take_action(self, parsed_args):
        columns = ('Type', 'Service', 'Score')
        return columns, self._wait(parsed_args)


class ClusterLock(ClusterUnlock):
    """Lock score"""

    log = logging.getLogger(__name__ + '.ClusterLock')

    def get_parser(self, prog_name):
        parser = super(ClusterLock, self).get_parser(prog_name)
        parser.add_argument(
            '-s', '--score',
            metavar='<score>',
            type=int,
            default=0,
            help='score to set'
        )
        return parser

    def _lock_one(self, type_, addr, score):
        service_info = {'type': type_, 'addr': addr, 'score': score}
        try:
            svc = self.app.client_manager.admin.cluster_lock_score(
                    service_info)
            yield type_, addr, "locked to %d" % int(svc.get("score", score))
        except Exception as exc:
            yield type_, addr, str(exc)

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        return (('Type', 'Service', 'Result'),
                self._lock_one(parsed_args.srv_type,
                               parsed_args.srv_addr,
                               parsed_args.score))


class ClusterFlush(command.Command):
    """Flush all services of the cluster"""

    log = logging.getLogger(__name__ + '.ClusterFlush')

    def get_parser(self, prog_name):
        parser = super(ClusterFlush, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='+',
            help='Service Type(s)')
        return parser

    def take_action(self, parsed_args):
        for srv_type in parsed_args.srv_types:
            try:
                self.app.client_manager.admin.cluster_flush(srv_type)
                self.log.warn('services %s flushed' % (srv_type))
            except Exception as e:
                raise Exception('Error while flushing service %s: %s' %
                                (srv_type, str(e)))


class LocalNSConf(show.ShowOne):
    """show namespace configuration values locally configured"""

    log = logging.getLogger(__name__ + '.LocalNSConf')

    def get_parser(self, prog_name):
        parser = super(LocalNSConf, self).get_parser(prog_name)
        return parser

    def take_action(self, parsed_args):

        self.log.debug('take_action(%s)', parsed_args)
        namespace = self.app.client_manager.admin.conf['namespace']
        sds_conf = load_namespace_conf(namespace)
        output = list()
        for k in sds_conf:
            output.append(("%s/%s" % (namespace, k), sds_conf[k]))
        return zip(*output)
