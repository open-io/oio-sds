# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

import redis
import random

from oio.common.easy_value import true_value
from oio.common.exceptions import Forbidden, NotFound
from oio.common.green import datetime
from oio.common.json import json
from oio.common.redis_conn import RedisConnection
from oio.common.timestamp import Timestamp


def handle_redis_exceptions(func):
    @wraps(func)
    def handle_redis_exceptions(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except redis.exceptions.ResponseError as exc:
            error = self._lua_errors.get(str(exc))
            if error is None:
                raise
            error_cls, error_msg = error
            raise error_cls(message=error_msg)
    return handle_redis_exceptions


class XcuteBackend(RedisConnection):

    DEFAULT_LIMIT = 1000

    _lua_errors = {
        'job_exists': (
            Forbidden,
            'The job already exists'),
        'no_job': (
            NotFound,
            'The job does\'nt exist'),
        'lock_exists': (
            Forbidden,
            'The lock already exists'),
        'must_be_running': (
            Forbidden,
            'The job must be running'),
        'must_be_paused': (
            Forbidden,
            'The job must be paused'),
        'must_be_waiting_paused_finished': (
            Forbidden,
            'The job must be waiting or paused or finished')
        }

    key_job_conf = 'xcute:job:config:%s'
    key_job_ids = 'xcute:job:ids'
    key_job_info = 'xcute:job:info:%s'
    key_waiting_jobs = 'xcute:waiting:jobs'
    key_tasks_running = 'xcute:tasks:running:%s'
    key_orchestrator_jobs = 'xcute:orchestrator:jobs:%s'

    _lua_update_mtime = """
        redis.call('HSET', 'xcute:job:info:' .. job_id, 'job.mtime', mtime);
    """

    lua_create = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local job_type = KEYS[3];
        local job_config = ARGV;

        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. job_id);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        redis.call('ZADD', 'xcute:job:ids', 0, job_id);
        redis.call(
            'HSET', 'xcute:job:info:' .. job_id,
            'job.type', job_type,
            'job.status', 'WAITING',
            'job.request_pause', 'False',
            'tasks.all_sent', 'False',
            'tasks.sent', '0',
            'tasks.processed', '0',
            'tasks.is_total_temp', 'True',
            'errors.total', '0');

        redis.call('HSET', 'xcute:job:config:' .. job_id, unpack(job_config));
        redis.call('RPUSH', 'xcute:waiting:jobs', job_id);
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

        redis.call('HSET', 'xcute:job:info:' .. job_id,
                   'job.status', 'RUNNING',
                   'orchestrator.id', orchestrator_id);
        redis.call('SADD', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                   job_id);
    """ + _lua_update_mtime + """
        local job_info = redis.call('HGETALL', 'xcute:job:info:' .. job_id);
        local job_config = redis.call(
            'HGETALL', 'xcute:job:config:' .. job_id);
        return {job_id, job_info, job_config};
    """

    lua_free = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
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

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status ~= 'RUNNING' then
            return redis.error_reply('job_must_be_running');
        end;

        redis.call('HSET', 'xcute:job:info:' .. job_id,
                   'job.status', 'FAILED');
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
                return redis.error_reply('job_running_all_tasks_sent');
            else
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'job.request_pause', 'True');
    """ + _lua_update_mtime + """
                return;
            end;
        end;

        if status == 'PAUSED' then
            return redis.error_reply('job_already_paused');
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

        if status == 'WAITING' then
            return redis.error_reply('job_already_waiting');
        end;

        if status == 'RUNNING' then
            local request_pause = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'job.request_pause');
            if request_pause == 'True' then
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'job.request_pause', 'False');
    """ + _lua_update_mtime + """
                return;
            else
                return redis.error_reply('job_already_running');
            end;
        end;

        if status == 'PAUSED' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'job.request_pause', 'False');
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'job.status', 'WAITING');
            redis.call('RPUSH', 'xcute:waiting:jobs', job_id);
    """ + _lua_update_mtime + """
            return;
        end;

        if status == 'RUNNING_LAST_TASKS' then
            return redis.error_reply('job_already_running');
        end;

        if status == 'FINISHED' then
            return redis.error_reply('job_finished');
        end;
    """

    lua_update_tasks_sent = """
        local mtime = KEYS[1];
        local job_id = KEYS[2];
        local all_tasks_sent = KEYS[3];
        local tasks_sent = ARGV;
        local tasks_sent_length = #tasks_sent;
        local info_key = 'xcute:job:info:' .. job_id;

        local status = redis.call('HGET', info_key,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local total_tasks_sent = redis.call(
            'HINCRBY', info_key,
            'tasks.sent', tasks_sent_length);
        for _, task_id in ipairs(tasks_sent) do
            redis.call('SADD', 'xcute:tasks:running:' .. job_id, task_id);
        end;
        if tasks_sent_length > 0 then
            redis.call('HSET', info_key,
                       'tasks.last_sent', tasks_sent[tasks_sent_length]);
        end;

        if all_tasks_sent == 'True' then
            -- replace the estimated total with the actual total
            redis.call('HSET', info_key,
                       'tasks.all_sent', 'True',
                       'tasks.total', total_tasks_sent,
                       'tasks.is_total_temp', 'False');
            -- remove the job of the orchestrator
            local orchestrator_id = redis.call(
                'HGET', info_key, 'orchestrator.id');
            redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                       job_id);

            if tonumber(total_tasks_sent) == 0 then
                -- if there is no task sent, finish job
                redis.call('HSET', info_key,
                           'job.status', 'FINISHED');
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
        return redis.call('HGET', info_key, 'job.status');
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
        local tasks_processed_length = #tasks_processed;

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local total_tasks_processed = redis.call(
            'HINCRBY', 'xcute:job:info:' .. job_id,
            'tasks.processed', tasks_processed_length);
        for _, task_id in ipairs(tasks_processed) do
            redis.call('SREM', 'xcute:tasks:running:' .. job_id, task_id);
        end;

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
            'job.status', 'tasks.is_total_temp');
        local status = info[1];
        local is_total_temp = info[2];

        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local stop = false;
        if is_total_temp == 'False' then
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

        redis.call('HSET', info_key, 'tasks.is_total_temp', 'False');
        local total_tasks = redis.call('HGET', info_key, 'tasks.total');

    """ + _lua_update_mtime + """
        return tonumber(total_tasks);
    """

    lua_delete = """
        local job_id = KEYS[1];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'job.status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'RUNNING' then
            return redis.error_reply('job_running');
        end;

        if status == 'WAITING' then
            redis.call('LREM', 'xcute:waiting:jobs', 1, job_id);
        end;

        redis.call('ZREM', 'xcute:job:ids', job_id);
        redis.call('DEL', 'xcute:job:info:' .. job_id);
        redis.call('DEL', 'xcute:job:config:' .. job_id);
        redis.call('DEL', 'xcute:tasks:running:' .. job_id);
        """

    def __init__(self, conf):
        self.conf = conf
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
        self.script_update_tasks_sent = self.register_script(
            self.lua_update_tasks_sent)
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

    def list_jobs(self, marker=None, limit=1000):
        limit = limit or self.DEFAULT_LIMIT

        jobs = list()
        while True:
            limit_ = limit - len(jobs)
            if limit_ <= 0:
                break

            range_min = '-'
            if marker:
                range_max = '(' + marker
            else:
                range_max = '+'

            job_ids = self.conn.zrevrangebylex(
                self.key_job_ids, range_max, range_min, 0, limit_)

            pipeline = self.conn.pipeline()
            for job_id in job_ids:
                self._get_job_conf(job_id, client=pipeline)
                self._get_job_info(job_id, client=pipeline)
            job_conf_infos = pipeline.execute()

            for job_id, job_conf, job_info in zip(
                    job_ids, *([iter(job_conf_infos)] * 2)):
                if not job_info:
                    continue

                job_conf = self._unmarshal_job_config(job_conf)
                job_info = self._unmarshal_job_info(job_info)

                jobs.append((job_id, job_conf, job_info))

            if len(job_ids) < limit_:
                break
            marker = job_id
        return jobs

    def _get_timestamp(self):
        return Timestamp().normal

    @handle_redis_exceptions
    def create(self, job_type, job_config):
        job_id = datetime.utcnow().strftime('%Y%m%d%H%M%S%f') \
            + '-%011x' % random.randrange(16**11)

        self.script_create(
            keys=[self._get_timestamp(), job_id, job_type],
            args=self._dict_to_lua_array(
                self._marshal_job_config(job_config)),
            client=self.conn)
        return job_id

    @handle_redis_exceptions
    def start_job(self, job_id, job_info):
        pipeline = self.conn.pipeline()

        self._update_job_info(job_id, job_info, client=pipeline)

        pipeline.execute()

    def list_orchestrator_jobs(self, orchestrator_id):
        orchestrator_jobs_key = self.key_orchestrator_jobs % orchestrator_id
        job_ids = self.conn.smembers(orchestrator_jobs_key)

        pipeline = self.conn.pipeline()
        for job_id in job_ids:
            self._get_job_conf(job_id, client=pipeline)
            self._get_job_info(job_id, client=pipeline)
        job_config_infos = pipeline.execute()

        return (
            (job_id, self._unmarshal_job_config(job_config),
             self._unmarshal_job_info(job_info))
            for job_config, job_info in zip(*([iter(job_config_infos)] * 2))
        )

    @handle_redis_exceptions
    def run_next(self, orchestrator_id):
        next_job = self.script_run_next(
            keys=[self._get_timestamp(), orchestrator_id],
            client=self.conn)
        if next_job is None:
            return None
        job_id, job_info, job_config = next_job
        job_info = self._unmarshal_job_info(
            self._lua_array_to_dict(job_info))
        job_config = self._unmarshal_job_config(
            self._lua_array_to_dict(job_config))
        return (job_id, job_config, job_info)

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
    def update_tasks_sent(self, job_id, task_ids, all_tasks_sent=False):
        return self.script_update_tasks_sent(
            keys=[self._get_timestamp(), job_id, str(all_tasks_sent)],
            args=task_ids, client=self.conn)

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
        return self.script_update_tasks_processed(
            keys=[self._get_timestamp(),
                  job_id] + self._dict_to_lua_array(counters),
            args=task_ids,
            client=self.conn)

    def incr_total_tasks(self, job_id, total_marker, tasks_incr):
        return self.script_incr_total(
            keys=[self._get_timestamp(), job_id, total_marker, tasks_incr])

    def total_tasks_done(self, job_id):
        return self.script_total_tasks_done(
            keys=[self._get_timestamp(), job_id])

    @handle_redis_exceptions
    def delete(self, job_id):
        self.script_delete(keys=[job_id])

    def get_job(self, job_id):
        pipeline = self.conn.pipeline()

        self._get_job_conf(job_id, client=pipeline)
        self._get_job_info(job_id, client=pipeline)

        job_conf, job_info = pipeline.execute()

        if job_info is None:
            raise NotFound('The job does\'nt exist')

        job_conf = self._unmarshal_job_config(job_conf)
        job_info = self._unmarshal_job_info(job_info)

        return job_conf, job_info

    def get_job_conf(self, job_id):
        job_config = self._get_job_conf(job_id, client=self.conn)
        return self._unmarshal_job_config(job_config)

    def get_job_info(self, job_id):
        job_info = self._get_job_info(job_id, client=self.conn)
        return self._unmarshal_job_info(job_info)

    def update_job_conf(self, job_id, updates):
        self._update_job_conf(job_id, updates, client=self.conn)

    def update_job_info(self, job_id, updates):
        self._update_job_info(job_id, updates, client=self.conn)

    def _get_job_conf(self, job_id, client):
        return client.hgetall(self.key_job_conf % job_id)

    def _get_job_info(self, job_id, client):
        return client.hgetall(self.key_job_info % job_id)

    def _update_job_info(self, job_id, updates, client):
        marshalled_updates = self._marshal_job_info(updates)
        return client.hmset(self.key_job_info % job_id, marshalled_updates)

    def _update_job_conf(self, job_id, job_config, client):
        marshalled_job_config = self._marshal_job_config(job_config)
        return client.hmset(self.key_job_conf % job_id, marshalled_job_config)

    @staticmethod
    def _marshal_job_info(job_info):
        marshalled_job_info = job_info.copy()

        if job_info.get('tasks.total') is None:
            marshalled_job_info.pop('tasks.total', None)

        return marshalled_job_info

    @staticmethod
    def _unmarshal_job_info(marshalled_job_info):
        job_info = marshalled_job_info.copy()

        job_info['tasks.total'] = int(job_info['tasks.total']) \
            if 'tasks.total' in job_info else None

        job_info['tasks.sent'] = int(job_info['tasks.sent'])
        job_info.setdefault('tasks.last_sent')
        job_info['tasks.all_sent'] = true_value(job_info['tasks.all_sent'])
        job_info['tasks.processed'] = int(job_info['tasks.processed'])
        job_info['tasks.is_total_temp'] = true_value(
            job_info['tasks.is_total_temp'])
        job_info.setdefault('tasks.total_marker')
        job_info['job.request_pause'] = true_value(
            job_info.get('job.request_pause'))

        for key, value in job_info.iteritems():
            if key.startswith('errors.') or key.startswith('results.'):
                job_info[key] = int(value)

        return job_info

    @staticmethod
    def _marshal_job_config(job_config):
        marshalled_job_config = job_config.copy()
        marshalled_job_config['params'] = json.dumps(job_config['params'])
        return marshalled_job_config

    @staticmethod
    def _unmarshal_job_config(marshalled_job_config):
        job_config = marshalled_job_config.copy()
        job_config['tasks_per_second'] = int(job_config['tasks_per_second'])
        job_config['tasks_batch_size'] = int(job_config['tasks_batch_size'])
        job_config['params'] = json.loads(job_config['params'])
        return job_config

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
