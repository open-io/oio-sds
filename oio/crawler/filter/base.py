import sys
import StringIO
TYPE = 'type'
_STORAGE_TIERER_FILTER = None


def get_bool(answer):
    if answer.rstrip() == "True":
                return True
    elif answer.rstrip() == 'False':
                return False


def load_storage_filter():
    global _STORAGE_TIERER_FILTER
    filters = {'none': StorageFilterNone,
               'python_script': StorageFilterPythonScript}
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

    @property
    def conf(self):
        return self._conf


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


class StorageFilterPythonScript(StorageTiererFilter):
    def __init__(self, conf):
        super(StorageFilterPythonScript, self).__init__(conf)

    @classmethod
    def build(self, cls, conf):
        return cls(conf)

    def filter_content(self, content):
        container_id, obj_infos = content
        filter_args = self.conf.get('filter_conf')
        filter_args
        python_file = self.conf.get('filter_conf', {}).get('python_file', None)
        if python_file:
            try:
                with open(python_file) as fd:
                    python_code = fd.read()
            except ValueError:
                python_code = 'print "True"'
            codeOut = StringIO.StringIO()
            sys.stdout = codeOut
            exec(python_code)
            sys.stdout = sys.__stdout__
            return get_bool(codeOut.getvalue())
        return True

    def __str__(self):
        return 'python_script'


class InvalidStorageTiererFilterException(Exception):
    def __init__(self):
        pass

    def __str__(self):
        return 'Invalid Filter !'

load_storage_filter()
STORAGE_TIERER_FILTERS = _STORAGE_TIERER_FILTER
