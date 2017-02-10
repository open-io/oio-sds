from oio.event.filters.base import Filter


class NoopFilter(Filter):
    """
    Does nothing with the input event.

    Useful if you just want to drop the events.
    """
    pass


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def noop_filter(app):
        return NoopFilter(app, conf)
    return noop_filter
