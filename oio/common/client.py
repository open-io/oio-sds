from oio.common.utils import get_logger
from oio.common.utils import load_namespace_conf
from oio.common.utils import validate_service_conf
from oio.api.base import API


class Client(API):
    """
    Client directed towards oio-proxy, with logging facility
    """

    def __init__(self, conf, session=None, request_prefix="",
                 no_ns_in_url=False, **kwargs):
        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        self.conf = conf
        self.ns_conf = load_namespace_conf(self.ns)
        self.logger = get_logger(conf)
        self.proxy_netloc = self.ns_conf.get('proxy')

        parts = ["http:/", self.proxy_netloc, "v3.0"]
        if not no_ns_in_url:
            parts.append(self.ns)
        if request_prefix:
            parts.append(request_prefix.lstrip('/'))
        super(Client, self).__init__(endpoint='/'.join(parts), **kwargs)
