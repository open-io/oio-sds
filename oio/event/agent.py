from __future__ import print_function
import sys
import random
import errno
import signal
import time
import os
import eventlet
from oio.common.utils import read_conf, get_logger, \
    int_value, CPU_COUNT, drop_privileges, \
    redirect_stdio


class HaltServer(BaseException):
    def __init__(self, reason, exit_status=1):
        self.reason = reason
        self.exit_status = exit_status


class Runner(object):

    WORKER_START_ERROR = 3

    SIGNALS = [getattr(signal, "SIG%s" % x)
               for x in "HUP QUIT INT TERM".split()]
    SIG_NAMES = dict(
        (getattr(signal, name), name[3:].lower()) for name in dir(signal)
        if name[:3] == "SIG" and name[3] != "_"
    )

    def __init__(self, conf_file, worker_class, **kwargs):
        section_name = 'event-agent'
        self.conf = read_conf(conf_file, section_name)
        self.logger = get_logger(
            self.conf, verbose=kwargs.pop('verbose', False))
        redirect_stdio(self.logger)
        drop_privileges(self.conf.get('user', 'openio'))
        self.num_workers = int_value(self.conf.get('workers'), CPU_COUNT)
        self.worker_class = worker_class
        self.workers = {}
        self.sig_queue = []

    def start(self):
        self.logger.info('Starting event-agent')
        self.pid = os.getpid()
        self.configure_signals()

    def configure_signals(self):
        [signal.signal(s, self.signal) for s in self.SIGNALS]
        signal.signal(signal.SIGCHLD, self.handle_chld)

    def signal(self, sig, frame):
        if len(self.sig_queue) < 5:
            self.sig_queue.append(sig)

    def run(self):
        self.start()

        try:
            self.manage_workers()

            while True:
                sig = self.sig_queue.pop(0) if len(self.sig_queue) else None
                if sig is None:
                    eventlet.sleep(1)
                    self.manage_workers()
                    continue

                if sig not in self.SIG_NAMES:
                    self.logger.info('Ignoring unknown signal: %s', sig)
                    continue

                signame = self.SIG_NAMES.get(sig)
                handler = getattr(self, "handle_%s" % signame, None)
                if not handler:
                    self.logger.error("Unhandled signal: %s", signame)
                    continue
                self.logger.info("Handling signal: %s", signame)
                handler()
        except StopIteration:
            self.halt()
        except KeyboardInterrupt:
            self.halt()
        except HaltServer as h:
            self.halt(reason=h.reason, exit_status=h.exit_status)
        except SystemExit:
            raise
        except Exception:
            self.logger.info("Unhandled exception in main loop", exc_info=True)
            self.stop(False)
            sys.exit(-1)

    def handle_chld(self, sig, frame):
        self.reap_workers()

    def handle_hup(self):
        self.logger.info("Shutdown gracefully")
        self.reload()

    def handle_term(self):
        raise StopIteration

    def handle_int(self):
        self.stop(False)
        raise StopIteration

    def handle_quit(self):
        self.stop(False)
        raise StopIteration

    def halt(self, reason=None, exit_status=0):
        self.stop()
        self.logger.info("Shutting down")
        if reason is not None:
            self.logger.info("Reason: %s", reason)
        sys.exit(exit_status)

    def stop(self, graceful=True):
        sig = signal.SIGTERM
        if not graceful:
            sig = signal.SIGQUIT
        limit = time.time() + 5
        self.kill_workers(sig)
        while self.workers and time.time() < limit:
            eventlet.sleep(0.1)
        self.kill_workers(signal.SIGKILL)

    def reap_workers(self):
        try:
            while True:
                wpid, status = os.waitpid(-1, os.WNOHANG)
                if not wpid:
                    break
                exitcode = status >> 8
                if exitcode == self.WORKER_START_ERROR:
                    reason = "Worker failed to start"
                    raise HaltServer(reason, self.WORKER_START_ERROR)
                worker = self.workers.pop(wpid, None)
                if not worker:
                    continue
        except OSError as e:
            if e.errno != errno.ECHILD:
                raise

    def manage_workers(self):
        if len(self.workers.keys()) < self.num_workers:
            self.spawn_workers()

        workers = self.workers.items()
        while len(workers) > self.num_workers:
            (pid, _) = workers.pop(0)
            self.kill_worker(pid, signal.SIGTERM)

    def spawn_worker(self):
        worker = self.worker_class(self.pid, self.conf, self.logger)
        pid = os.fork()
        if pid != 0:
            self.workers[pid] = worker
            return pid

        # child process
        worker_pid = os.getpid()
        try:
            self.logger.info("Booting worker with pid: %s", worker_pid)
            worker.init()
            sys.exit(0)
        except SystemExit:
            raise
        except:
            self.logger.exception("Exception in worker process")
            if not worker.started:
                sys.exit(self.WORKER_START_ERROR)
            sys.exit(-1)
        finally:
            self.logger.info("Worker exiting (pid: %s)", worker_pid)

    def spawn_workers(self):
        for i in range(self.num_workers - len(self.workers.keys())):
            self.spawn_worker()
            eventlet.sleep(0.1 * random.random())

    def kill_workers(self, sig):
        worker_pids = list(self.workers.keys())
        for pid in worker_pids:
            self.kill_worker(pid, sig)

    def kill_worker(self, pid, sig):
        try:
            os.kill(pid, sig)
        except OSError as e:
            if e.errno == errno.ESRCH:
                try:
                    self.workers.pop(pid)
                    return
                except (KeyError, OSError):
                    return
            raise


def validate_msg(msg):
    return len(msg) == 4
