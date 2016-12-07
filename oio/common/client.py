from oio.common.utils import get_logger
from oio.common.utils import load_namespace_conf
from oio.common.utils import validate_service_conf
from oio.api.base import HttpApi


class ProxyClient(HttpApi):
    """
    Client directed towards oio-proxy, with logging facility
    """

    def __init__(self, conf, session=None, request_prefix="",
                 no_ns_in_url=False, endpoint=None, **kwargs):
        """
        :param session: an optional session that will be reused
        :type session: `requests.Session`
        :param request_prefix: text to insert in between endpoint and
            requested URL
        :type request_prefix: `str`
        :param no_ns_in_url: do not insert namespace name between endpoint
            and `request_prefix`
        :type no_ns_in_url: `bool`
        """
        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        self.conf = conf
        self.ns_conf = load_namespace_conf(self.ns)
        self.logger = get_logger(conf)
        self.proxy_netloc = self.ns_conf.get('proxy')

        parts = list()
        if endpoint:
            parts.append(endpoint)
        else:
            parts.append("http:/")
            parts.append(self.proxy_netloc)
        parts.append("v3.0")
        if not no_ns_in_url:
            parts.append(self.ns)
        if request_prefix:
            parts.append(request_prefix.lstrip('/'))
        super(ProxyClient, self).__init__(endpoint='/'.join(parts), **kwargs)

    def _direct_request(self, method, url, session=None, headers=None,
                        **kwargs):
        if kwargs.get("autocreate"):
            if not headers:
                headers = dict()
            headers["X-oio-action-mode"] = "autocreate"
            kwargs = kwargs.copy()
            kwargs.pop("autocreate")
        return super(ProxyClient, self)._direct_request(method, url,
                                                        session=session,
                                                        headers=headers,
                                                        **kwargs)
