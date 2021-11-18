# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from functools import wraps

from datetime import datetime
import redis
import random
from fnmatch import fnmatchcase

from oio.common.easy_value import debinarize, true_value
from oio.common.exceptions import Forbidden, NotFound
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.redis_conn import RedisConnection
from oio.common.timestamp import Timestamp


END_MARKER = u"\U0010fffd"


def handle_redis_exceptions(func):
    @wraps(func)
    def handle_redis_exceptions(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except redis.exceptions.ResponseError as exc:
            error_parts = str(exc).split(':', 1)
            error_type = error_parts[0]
            error_param = error_parts[1:]

            error = self._lua_errors.get(error_type)
            if error is None:
                raise
            error_cls, error_msg = error
            raise error_cls(message=error_msg.format(*error_param))
    return handle_redis_exceptions


class XcuteBackend(RedisConnection):

    DEFAULT_LIMIT = 1000

    _lua_errors = {
        'job_exists': (
            Forbidden,
            'The job already exists'),
        'lock_exists': (
            Forbidden,
            'A job with the same lock ({}) is already in progress'),
        'no_job': (
            NotFound,
            'The job does not exist'),
        'job_must_be_paused': (
            Forbidden,
            'The job must be paused'),
        'job_must_be_running': (
            Forbidden,
            'The job must be running'),
        'job_cannot_be_paused_all_tasks_sent': (
            Forbidden,
            'The job cannot be paused anymore, all jobs have been sent'),
        'job_on_hold': (
            Forbidden,
            'The job is on hold'),
        'job_running': (
            Forbidden,
            'The job running'),
        'job_finished': (
            Forbidden,
            'The job is finished'),
        }

    key_job_ids = 'xcute:job:ids'
    key_job_info = 'xcute:job:info:%s'
    key_on_hold_jobs = 'xcute:on_hold:jobs:%s'
    key_waiting_jobs = 'xcute:waiting:jobs'
    key_tasks_running = 'xcute:tasks:running:%s'
    key_orchestrator_jobs = 'xcute:orchestrator:jobs:%s'
    key_locks = 'xcute:locks'

    _lua_update_mtime = """
        redis.call('HSET', 'xcute:job:info:' .. job_id, 'job.mtime', mtime);
    """

    _lua_release_lock = """
        local waiting_lock_job_id = redis.call(
            'LPOP', 'xcute:on_hold:jobs:' .. lock);
        if waiting_lock_job_id == nil or waiting_lock_job_id == false then
            redis.call('HDEL', 'xcute:locks', lock);
        else
            redis.call('HSET', 'xcute:locks', lock, waiting_lock_job_id);
            redis.call('HSET', 'xcute:job:info:' .. waiting_lock_job_id,
                       'job.status', 'WAITING');
            redis.call('HSET', 'xcute:job:info:' .. waiting_lock_job_id,
                       'job.mtime', mtime);
            redis.call('RPUSH', 'xcute:waiting:jobs', waiting_lock_job_id);
        end;
    """

    lua_create = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local job_type = KEYS[3];
        local job_config = KEYS[4];
        local lock = KEYS[5];
        local put_on_hold_if_locked = KEYS[6];

        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. job_id);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        local job_status;
        local lock_exists = redis.call('HEXISTS', 'xcute:locks', lock);
        if lock_exists ~= 0 then
            if put_on_hold_if_locked ~= 'True' then
                return redis.error_reply('lock_exists:' .. lock);
            end;
            redis.call('RPUSH', 'xcute:on_hold:jobs:' .. lock, job_id);
            job_status = 'ON_HOLD';
        else
            redis.call('HSET', 'xcute:locks', lock, job_id);
            job_status = 'WAITING';
            redis.call('RPUSH', 'xcute:waiting:jobs', job_id);
        end;

        redis.call('ZADD', 'xcute:job:ids', 0, job_id);
        redis.call(
            'HMSET', 'xcute:job:info:' .. job_id,
            'job.id', job_id,
            'job.type', job_type,
            'job.status', job_status,
            'job.request_pause', 'False',
            'job.lock', lock,
            'tasks.all_sent', 'False',
            'tasks.sent', '0',
            'tasks.processed', '0',
            'tasks.total', '0',
            'tasks.is_total_temp', 'True',
            'errors.total', '0',
            'config', job_config);
    """ + _lua_update_mtime + """
        redis.call('HSET', 'xcute:job:info:' .. job_id, 'job.ctime', mtime);
    """

    lua_run_next = """
        local mtime = KEYS[1];
        local orchestrator_id = KEYS[2];

        local job_id = redis.call('LPOP', 'xcute:waiting:jobs');
        if job_id == nil or job_id == false then
            return nil;
        end;

        redis.call('HMSET', 'xcute:job:info:' .. job_id,
                   'job.status', 'RUNNING',
                   'orchestrator.id', orchestrator_id);
        redis.call('SADD', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                   job_id);
    """ + _lua_update_mtime + """
        local job_info = redis.call('HGETALL', 'xcute:job:info:' .. job_id);
        return job_info;
    """

    lua_free = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'RUNNING' then
            return redis.error_reply('job_must_be_running');
        end;

        local orchestrator_id = redis.call(
            'HGET', 'xcute:job:info:' .. job_id, 'orchestrator.id');
        redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                   job_id);

        redis.call('HSET', 'xcute:job:info:' .. job_id,
                   'job.status', 'WAITING');
        redis.call('LPUSH', 'xcute:waiting:jobs', job_id);
    """ + _lua_update_mtime

    lua_fail = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];

        local info = redis.call('HMGET', 'xcute:job:info:' .. job_id,
                                'job.status', 'job.lock');
        local status = info[1];
        local lock = info[2];
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status ~= 'RUNNING' then
            return redis.error_reply('job_must_be_running');
        end;

        redis.call('HSET', 'xcute:job:info:' .. job_id,
                   'job.status', 'FAILED');
    """ + _lua_release_lock + """
        -- remove the job of the orchestrator
        local orchestrator_id = redis.call(
            'HGET', 'xcute:job:info:' .. job_id, 'orchestrator.id');
        redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                   job_id);
    """ + _lua_update_mtime

    lua_request_pause = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'ON_HOLD' then
            return redis.error_reply('job_on_hold');
        end;

        if status == 'WAITING' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'job.status', 'PAUSED');
            redis.call('LREM', 'xcute:waiting:jobs', 1, job_id);
    """ + _lua_update_mtime + """
            return;
        end;

        if status == 'RUNNING' then
            local all_tasks_sent = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'tasks.all_sent');
            if all_tasks_sent == 'True' then
                return redis.error_reply(
                    'job_cannot_be_paused_all_tasks_sent');
            else
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'job.request_pause', 'True');
    """ + _lua_update_mtime + """
                return;
            end;
        end;

        if status == 'FINISHED' then
            return redis.error_reply('job_finished');
        end;
    """

    lua_resume = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'RUNNING' then
            local request_pause = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'job.request_pause');
            if request_pause == 'True' then
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'job.request_pause', 'False');
    """ + _lua_update_mtime + """
                return;
            end;
        end;

        if status == 'PAUSED' or status == 'FAILED' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'job.request_pause', 'False');
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'job.status', 'WAITING');
            redis.call('RPUSH', 'xcute:waiting:jobs', job_id);
    """ + _lua_update_mtime + """
            return;
        end;

        if status == 'FINISHED' then
            return redis.error_reply('job_finished');
        end;
    """

    lua_update_config = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local job_config = KEYS[3];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'ON_HOLD' and status ~= 'PAUSED'
                and status ~= 'FAILED' then
            return redis.error_reply('job_must_be_paused');
        end;

        redis.call('HSET', 'xcute:job:info:' .. job_id, 'config', job_config);
    """ + _lua_update_mtime

    lua_update_tasks_sent = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local all_tasks_sent = KEYS[3];
        local tasks_sent = ARGV;
        local tasks_sent_length = #tasks_sent;
        local info_key = 'xcute:job:info:' .. job_id;

        local info = redis.call('HMGET', info_key, 'job.status', 'job.lock');
        local status = info[1];
        local lock = info[2];
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local old_last_sent = redis.call('HGET', info_key, 'tasks.last_sent');

        local nb_tasks_sent = 0;
        if tasks_sent_length > 0 then
            nb_tasks_sent = redis.call(
                'SADD', 'xcute:tasks:running:' .. job_id, unpack(tasks_sent));
            redis.call('HSET', info_key,
                       'tasks.last_sent', tasks_sent[tasks_sent_length]);
        end;
        local total_tasks_sent = redis.call(
            'HINCRBY', info_key,
            'tasks.sent', nb_tasks_sent);

        if all_tasks_sent == 'True' then
            redis.call('HSET', info_key,
                       'tasks.all_sent', 'True');
            -- remove the job of the orchestrator
            local orchestrator_id = redis.call(
                'HGET', info_key, 'orchestrator.id');
            redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                       job_id);

            local total_tasks_processed = redis.call(
                'HGET', info_key, 'tasks.processed');
            if tonumber(total_tasks_processed) >= tonumber(
                    total_tasks_sent) then
                redis.call('HSET', info_key, 'job.status', 'FINISHED');
    """ + _lua_release_lock + """
            end;
        else
            local request_pause = redis.call(
                'HGET', info_key, 'job.request_pause');
            if request_pause == 'True' then
                -- if waiting pause, pause the job
                redis.call('HMSET', info_key,
                           'job.status', 'PAUSED',
                           'job.request_pause', 'False');
                local orchestrator_id = redis.call(
                    'HGET', info_key, 'orchestrator.id');
                redis.call(
                    'SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                    job_id);
            end;
        end;
    """ + _lua_update_mtime + """
        return {nb_tasks_sent, redis.call('HGET', info_key, 'job.status'),
                old_last_sent};
    """

    lua_abort_tasks_sent = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local old_last_sent = KEYS[3];
        local tasks_sent = ARGV;
        local tasks_sent_length = #tasks_sent;
        local info_key = 'xcute:job:info:' .. job_id;

        local status = redis.call('HGET', info_key, 'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if tonumber(tasks_sent_length) == 0 then
            return;
        end;

        redis.call('HSET', info_key, 'tasks.all_sent', 'False');
        redis.call('HINCRBY', info_key, 'tasks.sent', -tasks_sent_length);
        redis.call(
            'SREM', 'xcute:tasks:running:' .. job_id, unpack(tasks_sent));
        if old_last_sent == 'None' then
            redis.call('HDEL', info_key, 'tasks.last_sent');
        else
            redis.call('HSET', info_key, 'tasks.last_sent', old_last_sent);
        end;

        local request_pause = redis.call(
            'HGET', info_key, 'job.request_pause');
        if request_pause == 'True' then
            -- if waiting pause, pause the job
            redis.call('HMSET', info_key,
                        'job.status', 'PAUSED',
                        'job.request_pause', 'False');
            local orchestrator_id = redis.call(
                'HGET', info_key, 'orchestrator.id');
            redis.call(
                'SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                job_id);
        end;
    """ + _lua_update_mtime + """
        return {redis.call('HGET', info_key, 'job.status')};
    """

    lua_update_tasks_processed = """
        local function get_counters(tbl, first, last)
            local sliced = {}
            for i = first or 1, last or #tbl, 2 do
                sliced[tbl[i]] = tbl[i+1];
            end;
            return sliced;
        end;

        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local counters = get_counters(KEYS, 3, nil);
        local tasks_processed = ARGV;

        local info = redis.call('HMGET', 'xcute:job:info:' .. job_id,
                                'job.status', 'job.lock');
        local status = info[1];
        local lock = info[2];
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local nb_tasks_processed  = redis.call(
            'SREM', 'xcute:tasks:running:' .. job_id, unpack(tasks_processed));
        local total_tasks_processed = redis.call(
            'HINCRBY', 'xcute:job:info:' .. job_id,
            'tasks.processed', nb_tasks_processed);

        for key, value in pairs(counters) do
            redis.call('HINCRBY', 'xcute:job:info:' .. job_id,
                       key, value);
        end;

        local finished = false;
        local all_tasks_sent = redis.call(
            'HGET', 'xcute:job:info:' .. job_id, 'tasks.all_sent');
        if all_tasks_sent == 'True' and status ~= 'FINISHED' then
            local total_tasks_sent = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'tasks.sent');
            if tonumber(total_tasks_processed) >= tonumber(
                    total_tasks_sent) then
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'job.status', 'FINISHED');
    """ + _lua_release_lock + """
                finished = true;
            end;
        end;
    """ + _lua_update_mtime + """
        return finished;
    """

    lua_incr_total = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local marker = KEYS[3];
        local incr_by = KEYS[4];
        local info_key = 'xcute:job:info:' .. job_id;

        local info = redis.call(
            'HMGET', info_key,
            'job.status', 'tasks.all_sent', 'tasks.is_total_temp');
        local status = info[1];
        local all_sent = info[2];
        local is_total_temp = info[3];

        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local stop = false;
        if all_sent == 'True' then
            stop = true
        elseif is_total_temp == 'False' then
            stop = true
        else
            redis.call('HINCRBY', info_key, 'tasks.total', incr_by);
            redis.call('HSET', info_key, 'tasks.total_marker', marker);

            if status == 'PAUSED' or status == 'FAILED' then
                stop = true;
            end;
        end;

    """ + _lua_update_mtime + """
        return stop;
    """

    lua_total_tasks_done = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local info_key = 'xcute:job:info:' .. job_id;

        local status = redis.call('HGET', info_key, 'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        redis.call('HSET', info_key, 'tasks.is_total_temp', 'False');
        local total_tasks = redis.call('HGET', info_key, 'tasks.total');

    """ + _lua_update_mtime + """
        return tonumber(total_tasks);
    """

    lua_delete = """
        local job_id = KEYS[1];

        local info = redis.call('HMGET', 'xcute:job:info:' .. job_id,
                                'job.status', 'job.lock');
        local status = info[1];
        local lock = info[2];
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'ON_HOLD' then
            redis.call('LREM', 'xcute:on_hold:jobs:' .. lock, 1, job_id);
        end;

        if status == 'WAITING' then
            redis.call('LREM', 'xcute:waiting:jobs', 1, job_id);
        end;

        if status == 'RUNNING' then
            return redis.error_reply('job_running');
        end;

        if status == 'PAUSED' or status == 'FAILED' then
    """ + _lua_release_lock + """
        end;

        redis.call('ZREM', 'xcute:job:ids', job_id);
        redis.call('DEL', 'xcute:job:info:' .. job_id);
        redis.call('DEL', 'xcute:tasks:running:' .. job_id);
    """

    def __init__(self, conf, logger=None):
        self.conf = conf
        self.logger = logger or get_logger(self.conf)

        redis_conf = {k[6:]: v for k, v in self.conf.items()
                      if k.startswith('redis_')}
        super(XcuteBackend, self).__init__(**redis_conf)

        self.script_create = self.register_script(
            self.lua_create)
        self.script_run_next = self.register_script(
            self.lua_run_next)
        self.script_free = self.register_script(
            self.lua_free)
        self.script_fail = self.register_script(
            self.lua_fail)
        self.script_request_pause = self.register_script(
            self.lua_request_pause)
        self.script_resume = self.register_script(
            self.lua_resume)
        self.script_update_config = self.register_script(
            self.lua_update_config)
        self.script_update_tasks_sent = self.register_script(
            self.lua_update_tasks_sent)
        self.script_abort_tasks_sent = self.register_script(
            self.lua_abort_tasks_sent)
        self.script_update_tasks_processed = self.register_script(
            self.lua_update_tasks_processed)
        self.script_incr_total = self.register_script(
            self.lua_incr_total)
        self.script_total_tasks_done = self.register_script(
            self.lua_total_tasks_done)
        self.script_delete = self.register_script(
            self.lua_delete)

    def status(self):
        job_count = self.conn.zcard(self.key_job_ids)
        status = {'job_count': job_count}
        return status

    def list_jobs(self, prefix=None, marker=None, limit=1000,
                  job_status=None, job_type=None, job_lock=None):
        limit = limit or self.DEFAULT_LIMIT

        if job_status:
            job_status = job_status.upper().strip()
        if job_type:
            job_type = job_type.lower().strip()
        if job_lock:
            job_lock = job_lock.lower().strip()

        jobs = list()
        while True:
            limit_ = limit - len(jobs)
            if limit_ <= 0:
                break

            range_min = '-'
            range_max = '+'
            if prefix:
                range_min = '[' + prefix
                range_max = '[' + prefix + END_MARKER
            if marker and (not prefix or marker > prefix):
                range_min = '(' + marker

            job_ids = self.conn.zrevrangebylex(
                self.key_job_ids, range_max, range_min, 0, limit_)

            pipeline = self.conn.pipeline()
            for job_id in job_ids:
                self._get_job_info(job_id, client=pipeline)
            job_infos = pipeline.execute()

            for job_info in job_infos:
                if not job_info:
                    # The job can be deleted between two requests
                    continue

                if job_status and job_info['job.status'] != job_status:
                    continue
                if job_type and job_info['job.type'] != job_type:
                    continue
                if job_lock and not fnmatchcase(
                        job_info.get('job.lock') or '', job_lock):
                    continue

                jobs.append(self._unmarshal_job_info(job_info))

            if len(job_ids) < limit_:
                break
            marker = job_id
        return jobs

    def _get_timestamp(self):
        return Timestamp().normal

    @handle_redis_exceptions
    def create(self, job_type, job_config, lock, put_on_hold_if_locked=False):
        job_id = datetime.utcnow().strftime('%Y%m%d%H%M%S%f') \
            + '-%011x' % random.randrange(16**11)

        job_config = json.dumps(job_config)

        self.script_create(
            keys=[self._get_timestamp(), job_id, job_type, job_config, lock,
                  str(put_on_hold_if_locked)],
            client=self.conn)
        return job_id

    def list_orchestrator_jobs(self, orchestrator_id):
        orchestrator_jobs_key = self.key_orchestrator_jobs % orchestrator_id
        job_ids = self.conn.smembers(orchestrator_jobs_key)

        pipeline = self.conn.pipeline()
        for job_id in job_ids:
            self._get_job_info(job_id, client=pipeline)
        job_infos = pipeline.execute()

        jobs = list()
        for job_info in job_infos:
            if not job_info:
                # The job can be deleted between two requests
                continue
            jobs.append(self._unmarshal_job_info(job_info))
        return jobs

    @handle_redis_exceptions
    def run_next(self, orchestrator_id):
        job_info = self.script_run_next(
            keys=[self._get_timestamp(), orchestrator_id],
            client=self.conn)
        if not job_info:
            return None

        job_info = self._unmarshal_job_info(
            self._lua_array_to_dict(job_info))
        return job_info

    @handle_redis_exceptions
    def free(self, job_id):
        self.script_free(
            keys=[self._get_timestamp(), job_id],
            client=self.conn)

    @handle_redis_exceptions
    def fail(self, job_id):
        self.script_fail(
            keys=[self._get_timestamp(), job_id],
            client=self.conn)

    @handle_redis_exceptions
    def request_pause(self, job_id):
        self.script_request_pause(
            keys=[self._get_timestamp(), job_id],
            client=self.conn)

    @handle_redis_exceptions
    def resume(self, job_id):
        self.script_resume(
            keys=[self._get_timestamp(), job_id],
            client=self.conn)

    @handle_redis_exceptions
    def update_config(self, job_id, job_config):
        job_config = json.dumps(job_config)

        self.script_update_config(
            keys=[self._get_timestamp(), job_id, job_config],
            client=self.conn)

    @handle_redis_exceptions
    def update_tasks_sent(self, job_id, task_ids, all_tasks_sent=False):
        nb_tasks_sent, status, old_last_sent = self.script_update_tasks_sent(
            keys=[self._get_timestamp(), job_id, str(all_tasks_sent)],
            args=task_ids, client=self.conn)
        if nb_tasks_sent != len(task_ids):
            self.logger.warn('%s tasks were sent several times',
                             len(task_ids) - nb_tasks_sent)
        status = debinarize(status)
        old_last_sent = debinarize(old_last_sent)
        return status, old_last_sent

    @handle_redis_exceptions
    def abort_tasks_sent(self, job_id, task_ids, old_last_sent):
        status = self.script_abort_tasks_sent(
            keys=[self._get_timestamp(), job_id, str(old_last_sent)],
            args=task_ids, client=self.conn)
        status = debinarize(status)
        return status

    @handle_redis_exceptions
    def update_tasks_processed(self, job_id, task_ids,
                               task_errors, task_results):
        counters = dict()
        if task_errors:
            total_errors = 0
            for key, value in task_errors.items():
                total_errors += value
                counters['errors.' + key] = value
            counters['errors.total'] = total_errors
        if task_results:
            for key, value in task_results.items():
                counters['results.' + key] = value
        finished = self.script_update_tasks_processed(
            keys=[self._get_timestamp(),
                  job_id] + self._dict_to_lua_array(counters),
            args=task_ids,
            client=self.conn)
        return finished

    @handle_redis_exceptions
    def incr_total_tasks(self, job_id, total_marker, tasks_incr):
        stop = self.script_incr_total(
            keys=[self._get_timestamp(), job_id, total_marker, tasks_incr])
        return stop

    @handle_redis_exceptions
    def total_tasks_done(self, job_id):
        total_tasks = self.script_total_tasks_done(
            keys=[self._get_timestamp(), job_id])
        return total_tasks

    @handle_redis_exceptions
    def delete(self, job_id):
        self.script_delete(keys=[job_id])

    @handle_redis_exceptions
    def get_job_info(self, job_id):
        job_info = self._get_job_info(job_id, client=self.conn)
        if not job_info:
            raise redis.exceptions.ResponseError('no_job')

        return self._unmarshal_job_info(job_info)

    def _get_job_info(self, job_id, client):
        job_id = debinarize(job_id)
        return client.hgetall(self.key_job_info % job_id)

    @handle_redis_exceptions
    def list_locks(self):
        locks = self.conn.hgetall(self.key_locks)
        locks = debinarize(locks)
        return [
            dict(lock=lock[0], job_id=lock[1])
            for lock in sorted(locks.items())
        ]

    @handle_redis_exceptions
    def get_lock_info(self, lock):
        job_id = self.conn.hget(self.key_locks, lock)
        job_id = debinarize(job_id)
        return dict(lock=lock, job_id=job_id)

    @staticmethod
    def _unmarshal_job_info(marshalled_job_info):
        job_info = dict(
            job=dict(),
            orchestrator=dict(),
            tasks=dict(),
            errors=dict(),
            results=dict(),
            config=dict())

        marshalled_job_info = debinarize(marshalled_job_info)
        for key, value in marshalled_job_info.items():
            split_key = key.split('.', 1)
            if len(split_key) == 1:
                job_info[split_key[0]] = value
            else:
                job_info[split_key[0]][split_key[1]] = value

        job_main_info = job_info['job']
        job_main_info['ctime'] = float(job_main_info['ctime'])
        job_main_info['mtime'] = float(job_main_info['mtime'])
        job_main_info['request_pause'] = true_value(
            job_main_info['request_pause'])

        job_tasks = job_info['tasks']
        job_tasks['sent'] = int(job_tasks['sent'])
        job_tasks.setdefault('last_sent')
        job_tasks['all_sent'] = true_value(job_tasks['all_sent'])
        job_tasks['processed'] = int(job_tasks['processed'])
        # To have a coherent total if the estimate was not correct
        if job_tasks['all_sent']:
            job_tasks['total'] = job_tasks['sent']
        else:
            job_tasks['total'] = max(job_tasks['sent'],
                                     int(job_tasks['total']))
        job_tasks['is_total_temp'] = true_value(
            job_tasks['is_total_temp'])
        job_tasks.setdefault('total_marker')

        job_errors = job_info['errors']
        for key, value in job_errors.items():
            job_errors[key] = int(value)

        job_results = job_info.get('results', dict())
        for key, value in job_results.items():
            job_results[key] = int(value)

        job_info['config'] = json.loads(job_info['config'])

        return job_info

    @staticmethod
    def _lua_array_to_dict(array):
        it = iter(array)
        return dict(zip(*([it] * 2)))

    @staticmethod
    def _dict_to_lua_array(dict_):
        array = list()
        for key, value in dict_.items():
            array.append(key)
            array.append(value)
        return array
