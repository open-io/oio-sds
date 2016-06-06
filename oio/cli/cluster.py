import logging

from cliff import lister
from cliff import show


class ClusterShow(show.ShowOne):
    """Cluster show"""

    log = logging.getLogger(__name__ + '.ClusterInfo')

    def take_action(self, parsed_args):
        self.log.debug('take_action(%s)', parsed_args)

        data = self.app.client_manager.storage_internal.cluster_info()
        output = list()
        output.append(('namespace', data['ns']))
        output.append(('chunksize', data['chunksize']))
        for k, v in data['storage_policy'].iteritems():
            output.append(('storage_policy.%s' % k, v))
        for k, v in data['storage_class'].iteritems():
            output.append(('storage_class.%s' % k, v))
        for k, v in data['data_security'].iteritems():
            output.append(('data_security.%s' % k, v))
        for k, v in sorted(data['options'].iteritems()):
            output.append((k, v))
        return zip(*output)


class ClusterList(lister.Lister):
    """Cluster List"""

    log = logging.getLogger(__name__ + '.ClusterInfo')

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
            data = self.app.client_manager.storage_internal.cluster_list(
                srv_type)
            for srv in data:
                tags = srv['tags']
                location = tags.get('tag.loc', 'n/a')
                volume = tags.get('tag.vol', 'n/a')
                addr = srv['addr']
                up = tags.get('tag.up', 'n/a')
                score = srv['score']
                results.append((srv_type, addr, volume, location, up, score))

        columns = ('Type', 'Id', 'Volume', 'Location', 'Up', 'Score')
        l = (r for r in results)
        return columns, l
