import logging

from cliff import lister
from cliff import show
from cliff import command

from oio.common.utils import load_namespace_conf


class ClusterShow(show.ShowOne):
    """Show information of all services in the cluster"""

    log = logging.getLogger(__name__ + '.ClusterInfo')

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
    """Cluster list"""

    log = logging.getLogger(__name__ + '.ClusterList')

    def get_parser(self, prog_name):
        parser = super(ClusterList, self).get_parser(prog_name)
        parser.add_argument(
            'srv_types',
            metavar='<srv_types>',
            nargs='+',
            help='Service Type(s)')
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        results = []
        for srv_type in parsed_args.srv_types:
            data = self.app.client_manager.admin.cluster_list(
                srv_type)
            for srv in data:
                tags = srv['tags']
                location = tags.get('tag.loc', 'n/a')
                slots = tags.get('tag.slots', 'n/a')
                volume = tags.get('tag.vol', 'n/a')
                addr = srv['addr']
                up = tags.get('tag.up', 'n/a')
                score = srv['score']
                results.append((srv_type, addr, volume, location,
                                slots, up, score))
        columns = ('Type', 'Id', 'Volume', 'Location', 'Slots', 'Up', 'Score')
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


class ClusterUnlockService(command.Command):
    """Unlock score"""

    log = logging.getLogger(__name__ + '.ClusterUnlock')

    def get_parser(self, prog_name):
        parser = super(ClusterUnlockService, self).get_parser(prog_name)
        parser.add_argument(
            'srv_type',
            metavar='<srv_type>',
            help='Service Type')
        parser.add_argument(
            'srv_addr',
            metavar='<srv_addr>',
            help='addr of the service'
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)
        addr = parsed_args.srv_addr
        srv_type = parsed_args.srv_type
        namespace = self.app.client_manager.admin.conf['namespace']
        service_desc = "[%s|%s|%s]" % (namespace,
                                       srv_type,
                                       addr)
        data = self.app.client_manager.admin.cluster_list(
            srv_type)
        for srv in data:
            service_info = {'type': srv_type,
                            'addr': srv['addr'],
                            'score': -1}
            if addr == service_info['addr']:
                try:
                    self.app.client_manager.admin.cluster_unlock_score(
                        service_info)
                    self.log.warn("Service " + service_desc +
                                  " has been successfully unlocked")
                    return
                except Exception as e:
                    raise Exception('service unlock error: ' + str(e))
        self.log.error('Failed to set score of service ' +
                       service_desc + ': Invalid Service Description')


class ClusterFlush(command.Command):
    """flush all services in the cluster"""

    log = logging.getLogger(__name__ + '.ClusterInfo')

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
