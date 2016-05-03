from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


CONTAINER_EVENTS = [
        EventTypes.CONTAINER_STATE,
        EventTypes.CONTAINER_NEW,
        EventTypes.CONTAINER_DELETED]


class AccountUpdateFilter(Filter):

    def process(self, env, cb):
        event = Event(env)

        if event.event_type in CONTAINER_EVENTS:
            uri = 'http://%s/v1.0/account/container/update' % \
                    self.app.app.acct_addr
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
            self.app.session.post(uri, params={'id': account}, json=body)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
