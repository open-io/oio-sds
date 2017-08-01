from oio.common.client import ProxyClient
from oio.common.exceptions import OioException
from oio.common.utils import json


class LbClient(ProxyClient):
    """Simple load balancer client"""

    def __init__(self, conf, **kwargs):
        super(LbClient, self).__init__(
            conf, request_prefix="/lb", **kwargs)

    def next_instances(self, pool, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        :keyword slot: comma-separated list of slots to poll
        :type slot: `str`
        """
        params = {'type': pool}
        params.update(kwargs)
        resp, body = self._request('GET', '/choose', params=params)
        if resp.status == 200:
            return body
        else:
            raise OioException(
                'ERROR while getting next instance %s' % pool)

    def next_instance(self, pool):
        """Get the next service instance from the specified pool"""
        return self.next_instances(pool, size=1)[0]

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        params = {'pool': pool}
        ibody = dict()
        ibody.update(kwargs)
        resp, obody = self._request('POST', '/poll', params=params,
                                    data=json.dumps(ibody))
        if resp.status == 200:
            return obody
        else:
            raise OioException("Failed to poll %s: %s" % (pool, resp.text))

    def create_pool(self, pool, targets, options=None):
        """
        Create a service pool on the local proxy.

        :param pool: a name for the pool
        :type pool: `str`
        :param targets: a list of tuples like (1, "rawx-usa", "rawx", ...)
        :param options: options for the pool
        :type options: `dict`
        :exception Conflict: if a pool with same name already exists
        """
        stargets = ";".join(','.join(str(y) for y in x) for x in targets)
        ibody = {'targets': stargets, 'options': options}
        _, _ = self._request('POST', "/create_pool",
                             params={'name': pool},
                             data=json.dumps(ibody))


class ConscienceClient(ProxyClient):
    """Conscience client. Some calls are actually redirected to LbClient."""

    def __init__(self, conf, **kwargs):
        super(ConscienceClient, self).__init__(
            conf, request_prefix="/conscience", **kwargs)
        lb_kwargs = dict(kwargs)
        lb_kwargs.pop("pool_manager", None)
        self.lb = LbClient(conf, pool_manager=self.pool_manager, **lb_kwargs)

    def next_instances(self, pool, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        :keyword slot: comma-separated list of slots to poll
        :type slot: `str`
        """
        return self.lb.next_instance(pool, **kwargs)

    def next_instance(self, pool):
        """Get the next service instance from the specified pool"""
        return self.lb.next_instance(pool)

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        return self.lb.poll(pool, **kwargs)

    def all_services(self, type_, full=False):
        params = {'type': type_}
        if full:
            params['full'] = '1'
        resp, body = self._request('GET', '/list', params=params)
        if resp.status == 200:
            return body
        else:
            raise OioException("failed to get list of %s services: %s"
                               % (type_, resp.text))

    def local_services(self):
        url = self.endpoint.replace('conscience', 'local/list')
        resp, body = self._direct_request('GET', url)
        if resp.status == 200:
            return body
        else:
            raise OioException("failed to get list of local services: %s" %
                               resp.text)

    def service_types(self):
        params = {'what': 'types'}
        resp, body = self._request('GET', '/info', params=params)
        if resp.status == 200:
            return body
        else:
            raise OioException("ERROR while getting services types: %s" %
                               resp.text)

    def register(self, pool, service_definition):
        data = json.dumps(service_definition)
        resp, body = self._request('POST', '/register', data=data)

    def info(self):
        resp, body = self._request("GET", '/info')
        return body

    def lock_score(self, infos_srv):
        resp, body = self._request('POST', '/lock',
                                   data=json.dumps(infos_srv))
        return body

    def unlock_score(self, infos_srv):
        resp, body = self._request('POST', '/unlock',
                                   data=json.dumps(infos_srv))

    def flush(self, srv_type):
        resp, body = self._request('POST', '/flush',
                                   params={'type': srv_type})
