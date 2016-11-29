from oio.common.exceptions import from_response
from oio.common.http import requests
from oio.common.http import CONNECTION_TIMEOUT, READ_TIMEOUT
from oio.common.utils import get_logger
from oio.common.utils import load_namespace_conf
from oio.common.utils import validate_service_conf
from oio.common.utils import int_value


class Client(object):
    def __init__(self, conf, session=None, **kwargs):
        super(Client, self).__init__()
        validate_service_conf(conf)
        self.ns = conf.get('namespace')
        ns_conf = load_namespace_conf(self.ns)
        self.conf = conf
        self.ns_conf = ns_conf
        self.logger = get_logger(conf)
        if not session:
            session = requests.Session()
            if "pool_maxsize" in kwargs:
                pool_maxsize = int_value(kwargs.get("pool_maxsize"), 20)
                adapter = requests.adapters.HTTPAdapter(
                    pool_maxsize=pool_maxsize)
                session.mount("http://", adapter)
        self.session = session
        self.endpoint = 'http://%s' % ns_conf.get('proxy')

    def _direct_request(self, method, full_url, **kwargs):
        headers = kwargs.get('headers') or {}
        headers = dict([k, str(headers[k])] for k in headers)
        kwargs['headers'] = headers
        if "timeout" not in kwargs:
            resp = self.session.request(
                method, full_url,
                timeout=(CONNECTION_TIMEOUT, READ_TIMEOUT),
                **kwargs)
        else:
            resp = self.session.request(method, full_url, **kwargs)
        try:
            body = resp.json()
        except ValueError:
            body = resp.content
        if resp.status_code >= 400:
            raise from_response(resp, body)
        return resp, body

    def _request(self, method, url, **kwargs):
        endpoint = self.endpoint
        url = '/'.join([endpoint.rstrip('/'), url.lstrip('/')])
        return self._direct_request(method, url, **kwargs)
