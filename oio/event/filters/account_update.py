from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter


class AccountUpdateFilter(Filter):

    def process(self, env, cb):
        event = Event(env)

        if event.event_type == EventTypes.CONTAINER_UPDATE:
            uri = 'http://%s/v1.0/account/container/update' % self.app.acct_addr
            mtime = event.env.get('when')
            data = event.env.get('data')
            url = event.env.get('url')
            name = url.get('user')
            account = url.get('account')
            bytes_count = data.get('bytes-count', 0)
            object_count = data.get('object-count', 0)

            body = {
                'mtime': mtime,
                'name': name,
                'bytes': bytes_count,
                'objects': object_count
            }
            self.app.session.post(uri, params={'id': account}, json=body)
        elif event.event_type == EventTypes.CONTAINER_NEW:
            uri = 'http://%s/v1.0/account/container/update' % \
                self.app.acct_addr
            mtime = event.when
            url = event.data.get('url')
            name = url.get('user')
            account = url.get('account')

            body = {'mtime': mtime, 'name': name}
            self.app.session.post(uri, params={'id': account}, json=body)
        elif event.event_type == EventTypes.CONTAINER_DELETED:
            uri = 'http://%s/v1.0/account/container/update' % self.app.acct_addr
            dtime = event.env.get('when')
            data = event.env.get('data')
            url = data.get('url')
            name = url.get('user')
            account = url.get('account')

            body = {'dtime': dtime, 'name': name}
            self.app.session.post(uri, params={'id': account}, json=body)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def account_filter(app):
        return AccountUpdateFilter(app, conf)
    return account_filter
