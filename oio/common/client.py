from oio.common.utils import get_logger
from oio.common.utils import load_namespace_conf
from oio.common.utils import validate_service_conf
from oio.api.base import HttpApi
from oio.common.exceptions import ServiceBusy, OioException
from random import randrange
from eventlet import sleep


REQUEST_ATTEMPTS = 1


class ProxyClient(HttpApi):
    """
    Client directed towards oio-proxy, with logging facility
    """

    _slot_time = 0.5

    def __init__(self, conf, pool_manager=None, request_prefix="",
                 no_ns_in_url=False, endpoint=None,
                 request_attempts=REQUEST_ATTEMPTS,
                 logger=None, **kwargs):
        """
        :param pool_manager: an optional pool manager that will be reused
        :type pool_manager: `urllib3.PoolManager`
        :param request_prefix: text to insert in between endpoint and
            requested URL
        :type request_prefix: `str`
        :param no_ns_in_url: do not insert namespace name between endpoint
            and `request_prefix`
        :type no_ns_in_url: `bool`
        :param request_attempts: number of attempts for the request in case of
            error 503

        :raise oio.common.exceptions.ServiceBusy: if all attempts fail
        """
        assert(request_attempts > 0)

        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        self.conf = conf
        self.logger = logger or get_logger(conf)

        ep_parts = list()
        if endpoint:
            self.proxy_netloc = endpoint[7:]  # skip "http://"
            ep_parts.append(endpoint)
        else:
            ns_conf = load_namespace_conf(self.ns)
            self.proxy_netloc = ns_conf.get('proxy')
            ep_parts.append("http:/")
            ep_parts.append(self.proxy_netloc)

        ep_parts.append("v3.0")
        if not no_ns_in_url:
            ep_parts.append(self.ns)
        if request_prefix:
            ep_parts.append(request_prefix.lstrip('/'))

        self._request_attempts = request_attempts

        super(ProxyClient, self).__init__(endpoint='/'.join(ep_parts),
                                          **kwargs)

    def _direct_request(self, method, url, headers=None, request_attempts=None,
                        **kwargs):
        if not request_attempts:
            request_attempts = self._request_attempts
        if request_attempts <= 0:
            raise OioException("Negative request attempts: %d"
                               % request_attempts)
        if kwargs.get("autocreate"):
            if not headers:
                headers = dict()
            headers["X-oio-action-mode"] = "autocreate"
            kwargs = kwargs.copy()
            kwargs.pop("autocreate")
        for i in range(request_attempts):
            try:
                return super(ProxyClient, self)._direct_request(
                    method, url, headers=headers, **kwargs)
            except ServiceBusy:
                if i >= request_attempts - 1:
                    raise
                # retry with exponential backoff
                ProxyClient._exp_sleep(i + 1)

    @staticmethod
    def _exp_sleep(attempts):
        N = pow(2, attempts)
        k = randrange(N)
        sleep(k * ProxyClient._slot_time)
