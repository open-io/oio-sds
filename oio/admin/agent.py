# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


from __future__ import print_function

import uuid
import os
import time
import signal
import multiprocessing as mp
import re
import sys
from traceback import format_exc
import json
import cgi

from BaseHTTPServer import BaseHTTPRequestHandler

from oio.blob.mover import BlobMoverWorker
from oio.blob.rebuilder import BlobRebuilder
from oio.conscience.client import ConscienceClient
from oio.directory.meta2 import Meta2Database


UUID4_RE = "".join((
    r'([0-9a-f]{8}\-[0-9a-f]{4}\-4[0-9a-f]{3}',
    r'\-[89ab][0-9a-f]{3}\-[0-9a-f]{12})'
))


class BlobStatsLogger(object):
    """
    Log interceptor to parse logs coming from blob mover
    and turn them into stats
    """

    def __init__(self, logger, success, fail, size):
        self.log = logger
        self.success = success
        self.fail = fail
        self.size = size

    def info(self, msg, *args, **kwargs):
        self.log.debug(msg, *args, **kwargs)
        if msg.startswith("moved"):
            self.success.value += 1

    def warn(self, msg, *args, **kwargs):
        self.log.debug(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        self.log.debug(msg, *args, **kwargs)
        if msg.startswith("ERROR"):
            self.fail.value += 1

    def debug(self, msg, *args, **kwargs):
        self.log.debug(msg, *args, **kwargs)


class OioAdminAgent(object):
    """
    Main class for the admin agent
    Responsible of running admin tasks via multiprocessing
    """
    jobs = dict()

    blob_mover_cls = BlobMoverWorker
    blob_rebuilder_cls = BlobRebuilder
    meta2_mover_cls = Meta2Database

    def __init__(self, namespace, location,
                 conscience_client=None, logger=None,
                 **kwargs):
        self.ns = namespace
        self.loc = location
        self.log = logger
        self.cs = conscience_client or \
            ConscienceClient({'namespace': self.ns}, logger=self.log,
                             **kwargs)
        self.log.info("Starting oio-mover-agent")
        self.jobs = dict()

        signal.signal(signal.SIGINT, self._clean_exit)
        signal.signal(signal.SIGTERM, self._clean_exit)

    def _clean_exit(self, _signum, _frame):
        self.log.info(
            "Clean exit requested: cleaning %d running jobs",
            len([j for j in self.jobs.values() if j.get('status') == 0])
        )
        for job in self.jobs.values():
            self._clean_stop(job)
        self.log.info("Job cleanup completed. Shutting down")
        sys.exit(0)

    def _clean_stop(self, job):
        if job.get('type') == 'meta2':
            job['control'].get('signal').value = True
            for proc in job['processes']:
                try:
                    proc.join()
                except AssertionError:
                    pass

        elif job.get('type') == 'rawx':
            for proc in job['processes']:
                try:
                    proc.terminate()
                except Exception:
                    pass

    def _terminate(self, job):
        for proc in job['processes']:
            try:
                proc.terminate()
            except Exception:
                pass

    def move_meta2(self, config, stats, control):
        """
        Job for meta2 mover
        In:
        - config
        - stats
        - control
        """
        def _set(lock_, field, value):
            lock_.acquire()
            field.value = value
            lock_.release()

        def _add(lock_, field, value):
            lock_.acquire()
            field.value += value
            lock_.release()

        lock = control.get('lock')
        src = config.get('src')
        conf_str = ",".join(["%s=%s" % (k, v) for k, v in config.items()])
        self.cs.lock_score({'type': "meta2", 'addr': src})
        self.log.info("Starting meta2 mover on %s with config %s",
                      config['volume'], conf_str)
        for base in config.get('bases'):
            if control.get('signal').value:
                return
            try:
                meta2 = self.meta2_mover_cls({'namespace': self.ns})
                moved = meta2.move(base[0], src)
                for res in moved:
                    if res['err']:
                        _add(lock, stats.get("fail"), 1)
                    else:
                        _add(lock, stats.get("success"), 1)
                        _add(lock, stats.get("bytes"), 1)
            except Exception as exc:
                # TODO: Log job id here
                self.log.warn("Meta2 mover for job %s returned %s",
                              "unknown", format_exc(exc))
                _add(lock, stats.get("fail"), 1)
        _set(lock, control.get('status'), 2)
        _set(lock, control.get('end'), int(time.time()))

    def rebuild_rawx(self, config, stats, control):
        """
        Job for distributed blob rebuild
        In:
        - config
        - stats
        - control
        """
        src = config.get('src')
        status = 2
        conf_str = ",".join(["%s=%s" % (k, v) for k, v in config.items()])
        self.log.info("Starting blob rebuilder on %s with config %s",
                      config['volume'], conf_str)
        worker = self.blob_rebuilder_cls(
            config,
            service_id=src,
            logger=None
        )
        volume_stats = worker.rdir_client.status(src)
        stats.get('total').value = volume_stats.get('chunk', {})\
            .get('to_rebuild', 0)

        worker.prepare_distributed_dispatcher()
        events = worker.run()
        for _, _, err in events:
            if control.get('signal').value:
                # Stop sending events
                if status != 1:
                    self.log.info("Terminating blob rebuilder with config %s",
                                  conf_str)
                worker.dispatcher.terminate = True
                status = 1
            if err:
                stats.get('fail').value += 1
            else:
                stats.get('success').value += 1
        control.get('status').value = status
        control.get('end').value = int(time.time())

    def move_blobs(self, config, stats, control):
        """
        Job for blob mover
        In:
        - config
        - stats
        - control
        """
        src = config.get('src')
        del config['src']
        self.cs.lock_score(dict(type="rawx", addr=src))

        self.log.info("Starting blob mover on %s with config %s",
                      config['volume'],
                      ",".join(["%s=%s" % (k, v) for k, v in config.items()]))
        try:
            logger = BlobStatsLogger(self.log,
                                     stats.get("success"),
                                     stats.get("fail"),
                                     stats.get("bytes"))
            worker = self.blob_mover_cls(config, logger, config['volume'])
            worker.mover_pass()
        except Exception:
            self.log.exception("Blob mover failed with error:")
        self.cs.unlock_score(dict(type="rawx", addr=src))
        control.get('status').value = 2
        control.get('end').value = int(time.time())

    def check_running(self, vol):
        """
        Check if a mover job is already running on the specified volume
        """
        for job in self.jobs.values():
            if (self.on_same_host(job.get("loc")) and
                    job['config'].get("volume") == vol and
                    job['control'].get("end").value == 0):
                return job['id']
        return None

    def on_same_host(self, location):
        """Tell if the location is on the same host as the current process."""
        return self.loc.split('.', 1)[0] == location.rsplit('.', 1)[0]

    def volume(self, type_, src):
        """
        Resolve the volume for the specified service
        """
        for svc in self.cs.all_services(type_):
            tags = svc.get("tags", {})
            location = tags.get("tag.loc")
            if svc.get("id") == src and self.on_same_host(location):
                return tags.get("tag.vol")
        return None

    def excluded(self, type_, exclude):
        """
        Resolve excluded rawx services from the exclude list
        """
        to_exclude = []
        services = self.cs.all_services(type_)

        for excl in exclude:
            incl_ = False
            if excl.startswith("re:"):
                excl = excl.split("re:", 1)[1]
                if excl.startswith("!"):
                    # Include instead of exclude
                    incl_ = True
                    excl = excl[1:]
                loc = re.compile(excl)
                for svc in services:
                    tags_loc = svc.get("tags", {}).get("tag.loc", "")
                    if incl_ ^ bool(loc.match(tags_loc)):
                        to_exclude.append(svc.get("addr"))
            else:
                for svc in services:
                    for excl1 in exclude:
                        if excl1 in svc.get("tags", {}).get("tag.loc", []):
                            to_exclude.append(svc.get("addr"))
            return to_exclude

    def chunk_bases(self, bases, into=1):
        """
        Chunk meta2 bases into N chunks to allow
        for mover parallelization
        """
        chunks = [bases[i::into] for i in range(into)]
        for i, chunk in enumerate(chunks):
            chunks[i] = list(dict(chunk).items())
        return chunks

    def fetch_jobs(self):
        """
        Get the status/stats of all running jobs
        """
        res = []
        for jid, job in self.jobs.items():
            data = {
                'action': job["action"],
                'id': str(jid),
                'config': job["config"],
                'stats': dict(),
                'service': job["config"]["src"],
                'volume': job["config"]["volume"],
                'loc': job["loc"],
                'type': job["type"],
                'start': job["control"]["start"],
                'end': job["control"]["end"].value,
                'status': job["control"]["status"].value
            }
            for k, v in job["stats"].items():
                if k == 'total' and v == 0:
                    data['stats'][k] = job['stats']['success'].value + \
                        job['stats']['fail'].value
                    continue
                try:
                    data['stats'][k] = v.value
                except Exception:
                    data['stats'][k] = v

            res.append(data)
        return res

    def run_job(self, action, type_, src, vol, opts):
        """
        Create a mover job on the specified service
        """

        jid = str(uuid.uuid4())
        job = {
            'id': jid,
            'type': type_,
            'action': action,
            'loc': self.loc,
            'processes': [],
            'stats': dict(
                success=mp.Value('i'),
                fail=mp.Value('i'),
                bytes=mp.Value('i'),
                total=0
            ),
            'control': dict(
                status=mp.Value('i'),
                signal=mp.Value('b'),
                start=int(time.time()),
                end=mp.Value('i'),
                lock=mp.Lock(),
            ),
        }

        if type_ == "meta2" and action == "move":
            bases = []
            for path, _, files in os.walk(vol):
                for file_ in files:
                    size = os.path.getsize(os.path.join(path, file_))
                    if size < opts.get("minsize", 0):
                        continue
                    elif size > opts.get("maxsize", 1e32):
                        continue
                    bases.append([file_.split('.1.meta2')[0], size])

            job['config'] = dict(src=src, volume=vol, namespace=self.ns)
            for field in ("min_base_size", "max_base_size", "concurrency"):
                if opts.get(field):
                    job['config'][field] = opts.get(field)

            bases_all = self.chunk_bases(bases, int(
                job['config'].get('concurrency', '1')))

            for bases in bases_all:
                job["config"]["bases"] = bases
                job["processes"].append(mp.Process(
                    target=self.move_meta2,
                    args=(
                        job["config"],
                        job["stats"],
                        job["control"],
                    )
                ))
            job['stats']['total'] = len(bases)

        elif type_ == "rawx" and action == "move":
            try:
                excluded = self.excluded("rawx", opts.get('exclude', []))
            except Exception as exc:
                err = "Could not parse exclusion list: %s" % format_exc(exc)
                return None, err

            job['config'] = dict(
                src=src,
                volume=vol,
                namespace=self.ns,
            )
            for field in [("bps", "bytes_per_second"),
                          ("cps", "chunks_per_second"),
                          ("concurrency", "concurrency"),
                          ("target", "usage_target"),
                          ("minsize", "min_chunk_size"),
                          ("maxsize", "max_chunk_size")]:
                if opts.get(field[0]):
                    job["config"][field[1]] = opts[field[0]]
            if excluded:
                job["config"]["excluded_rawx"] = ",".join(excluded)

            job["processes"].append(mp.Process(
                target=self.move_blobs,
                args=(
                    job['config'],
                    job["stats"],
                    job["control"]
                )
            ))
        elif type_ == "rawx" and action == "rebuild":
            job['config'] = dict(
                src=src,
                volume=vol,
                namespace=self.ns,
                report_interval=0,
            )

            job['stats']['total'] = mp.Value('i')

            # TODO: VDO: support rdir_fetch_limit, rdir_timeout, retry_delay
            job["processes"].append(mp.Process(
                target=self.rebuild_rawx,
                args=(
                    job['config'],
                    job["stats"],
                    job["control"]
                )
            ))
        else:
            return None, "Unknown job %s %s" % (type_, action)

        for proc in job['processes']:
            proc.start()
        self.jobs[jid] = job
        return jid, None


class BaseAdminAgentHandler(BaseHTTPRequestHandler):
    """
    Mover agent handler
    Handles incoming HTTP requests
    """
    agent = None

    def http(self, code, data=None, json_=None, err=None):
        self.send_response(code)
        self.end_headers()
        if data:
            self.wfile.write(data)
            return
        if err:
            json_ = {'error': err}
        if json_:
            self.wfile.write(json.dumps(json_))

    def do_GET(self):
        """
            Retrieve stats of a mover
        """
        if not self.path.startswith("/api/v1/jobs"):
            return self.http(404, err="Invalid URI")
        self.http(200, json_=self.agent.fetch_jobs())

    def do_POST(self):
        """
            Create a new job
        """

        if not self.path.startswith("/api/v1/jobs"):
            return self.http(404, err="Invalid URI")

        ct = self.headers.getheader('content-type')
        if not ct:
            return self.http(400, err="Invalid content-type, json expected")
        ctype, _ = cgi.parse_header(ct)

        if ctype != 'application/json':
            return self.http(400, err="Invalid content-type, json expected")

        length = int(self.headers.getheader('content-length'))
        req = json.loads(self.rfile.read(length))
        type_ = req.get('type')
        src = req.get('id')
        action = req.get('action', 'move')  # TODO: remove this default

        if type_ not in ("meta2", "rawx"):
            return self.http(400, err="Invalid service type '%s'" % type_)
        if not src:
            return self.http(400, err="Invalid service '%s'" % src)

        vol = self.agent.volume(type_, src)
        if not vol:
            return self.http(
                400,
                err="Volume not found for '%s', not a local service?" % src)

        already = self.agent.check_running(vol)
        if already:
            return self.http(
                400,
                err=("A job is already running on the target volume (id=%s)" %
                     already),
            )

        jid, err = self.agent.run_job(action, type_, src, vol, req)
        if err:
            return self.http(400, err=err)
        self.http(201, json_={'id': jid})

    def do_DELETE(self):
        """
            Terminate a job
        """
        route = re.compile(r'^/api/v1/jobs/%s$' % UUID4_RE, re.I)
        match = route.match(self.path)
        if not match:
            return self.http(404, err="Invalid URI")
        job_id = match.group(1)
        job = self.agent.jobs.get(job_id)
        if not job:
            return self.http(404, err="No such job %s" % job_id)

        type_, action = job.get('type'), job.get('action')

        if type_ == 'meta2' and action == "move":
            job['control'].get('signal').value = True
            for proc in job['processes']:
                proc.join()

        elif type_ == 'rawx' and action == "move":
            for proc in job['processes']:
                try:
                    proc.terminate()
                except Exception:
                    pass
        elif type_ == 'rawx' and action == "rebuild":
            job['control'].get('signal').value = True
            for proc in job['processes']:
                proc.join()

        if job['control']['status'].value == 0:
            with job['control'].get('lock'):
                job['control']['status'].value = 1
                job['control']['end'].value = int(time.time())
        return self.http(204)
