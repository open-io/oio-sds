from eventlet import Timeout
from urlparse import urlparse
from urllib import urlencode
from oio.common.http import http_request
from oio.event.evob import Event, EventError
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


ACCOUNT_TIMEOUT = 30

CONTAINER_EVENTS = [
        EventTypes.CONTAINER_STATE,
        EventTypes.CONTAINER_NEW,
        EventTypes.CONTAINER_DELETED]


class AccountUpdateFilter(Filter):

    def process(self, env, cb):
        event = Event(env)

        if event.event_type in CONTAINER_EVENTS:
            uri = '/v1.0/account/container/update'
            mtime = event.when
            data = event.data
            url = event.env.get('url')
            name = url.get('user')
            account = url.get('account')
            body = {'name': name}
            if event.event_type == EventTypes.CONTAINER_STATE:
                body['bytes'] = data.get('bytes-count', 0)
                body['objects'] = data.get('object-count', 0)
            elif event.event_type == EventTypes.CONTAINER_DELETED:
                body['dtime'] = mtime
            elif event.event_type == EventTypes.CONTAINER_NEW:
                body['mtime'] = mtime
            query = urlencode({'id': account})
            p = urlparse('http://' + self.app.app.acct_addr)
            try:
                with Timeout(ACCOUNT_TIMEOUT):
                    resp, body = http_request(p.netloc, 'POST', uri,
                                              query_string=query, body=body)
            except Timeout as e:
                msg = 'account update failure: %s' % str(e)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
