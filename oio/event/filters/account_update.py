from eventlet import Timeout
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
            mtime = event.when / 1000000.0  # convert to seconds
            data = event.data
            url = event.env.get('url')
            body = {'name': url.get('user')}
            if event.event_type == EventTypes.CONTAINER_STATE:
                body['bytes'] = data.get('bytes-count', 0)
                body['objects'] = data.get('object-count', 0)
                body['mtime'] = mtime
            elif event.event_type == EventTypes.CONTAINER_DELETED:
                body['dtime'] = mtime
            elif event.event_type == EventTypes.CONTAINER_NEW:
                body['mtime'] = mtime
            query = urlencode({'id': url.get('account')})
            try:
                with Timeout(ACCOUNT_TIMEOUT):
                    # TODO(FVE): fix and use AccountClient
                    _, _ = http_request(self.app_env['acct_addr'](), 'POST',
                                        '/v1.0/account/container/update',
                                        query_string=query, body=body)
            except Timeout as exc:
                msg = 'account update failure: %s' % str(exc)
                resp = EventError(event=Event(env), body=msg)
                return resp(env, cb)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
