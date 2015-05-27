from eventlet import patcher

requests = patcher.import_patched('requests.__init__')

