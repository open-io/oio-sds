from oio.event.evob import Event
from oio.event.consumer import EventTypes
from oio.event.filters.base import Filter
from oio.crawler.storage_tierer import StorageTiererWorker, CONF_ACCOUNT, \
    CONF_FILTER_CONF, CONF_NEW_POLICY
import yaml

ACCOUNT_TIMEOUT = 30


class TieringFilter(Filter):

    def process(self, env, cb):
        event = Event(env)

        if event.event_type == EventTypes.CONTENT_TOUCH:
            self.logger.warn("event : " + str(env))
            url = env.get('url')
            account = url[CONF_ACCOUNT]
            ns = url['ns']
            user = url['user']
            container_id = url['id']
            container = url['user']
            path = url['path']
            key_file = self.conf.get('key_file')
            conf_filter = {CONF_ACCOUNT: account,
                           'ns': ns,
                           'user': user,
                           'container_id': container_id,
                           'path': path}
            try:
                settings_file = self.conf.get('tiering_settings_file')
                with open(settings_file) as f:
                    conf_yaml = yaml.load(f)
            except ValueError:
                conf_yaml = {}
            conf_filter.update(conf_yaml)
            new_policy = conf_filter.get(CONF_NEW_POLICY, None)
            if not new_policy:
                return self.app(env, cb)
            if not conf_filter.get('type', None):
                conf_filter['type'] = 'none'
            conf = {CONF_ACCOUNT: account,
                    'namespace': ns,
                    'key_file': key_file,
                    CONF_FILTER_CONF: conf_filter,
                    CONF_NEW_POLICY: new_policy}
            tierer = StorageTiererWorker(conf, self.logger)
            obj = tierer._recover_content_by_content_name(container, path)
            if obj and obj['policy'] != new_policy:
                tierer._try_change_policy(container_id, obj)
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def tiering_filter(app):
        return TieringFilter(app, conf)
    return tiering_filter
