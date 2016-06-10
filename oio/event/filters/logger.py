from oio.event.filters.base import Filter


class LoggerFilter(Filter):

    def init(self):
        pass

    def process(self, env, cb):
        self.logger.info("got event: %s", str(env))
        return self.app(env, cb)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def except_filter(app):
        return LoggerFilter(app, conf)
    return except_filter
