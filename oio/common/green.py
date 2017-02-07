import time
import logging
import eventlet

import eventlet.semaphore
from eventlet.green import threading
from eventlet import Timeout

logging.thread = eventlet.green.thread
logging.threading = threading
logging._lock = logging.threading.RLock()


class ClientReadTimeout(Timeout):
    pass


class ConnectionTimeout(Timeout):
    pass


class SourceReadTimeout(Timeout):
    pass


class ChunkWriteTimeout(Timeout):
    pass


class ChunkReadTimeout(Timeout):
    pass


def get_hub():
    return 'poll'


def ratelimit(run_time, max_rate, increment=1, rate_buffer=5):
    if max_rate <= 0 or increment <= 0:
        return run_time
    clock_accuracy = 1000.0
    now = time.time() * clock_accuracy
    time_per_request = clock_accuracy * (float(increment) / max_rate)
    if now - run_time > rate_buffer * clock_accuracy:
        run_time = now
    elif run_time - now > time_per_request:
        eventlet.sleep((run_time - now) / clock_accuracy)
    return run_time + time_per_request


class ContextPool(eventlet.GreenPool):
    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        for coroutine in list(self.coroutines_running):
            coroutine.kill()
