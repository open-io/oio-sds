TYPE = 'type'
_STORAGE_TIERER_FILTER = None


def load_storage_filter():
    global _STORAGE_TIERER_FILTER
    filters = {'none': StorageFilterNone}
    _STORAGE_TIERER_FILTER = filters


class StorageTiererFilters(object):
    def __init__(self, methods):
        self.index = methods
        self.cache = {}

    def load(self, conf):
        type_filter = self.cache.get(TYPE)
        if type_filter:
            return type_filter
        try:
            type_filter = conf.get(TYPE)
            cls = self.index[type_filter]
        except Exception:
            raise InvalidStorageTiererFilterException()
        return cls.build(cls, conf)


class StorageTiererFilter(object):
    def __init__(self, conf):
        self._conf = conf

    def filter_content(self, contents):
        pass


class StorageFilterNone(StorageTiererFilter):
    def __init__(self, conf):
        super(StorageFilterNone, self).__init__(conf)

    @classmethod
    def build(self, cls, conf):
        return cls(conf)

    def filter_content(self, content):
        return True

    def __str__(self):
        return 'none'


class InvalidStorageTiererFilterException(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return 'Invalid Filter !'

load_storage_filter()
STORAGE_TIERER_FILTERS = _STORAGE_TIERER_FILTER
