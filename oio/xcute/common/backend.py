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

from oio.common.exceptions import Forbidden, NotFound
from oio.common.green import time
from oio.common.json import json
from oio.common.redis_conn import RedisConnection


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
        'job_exists': (Forbidden,
                       'The job already exists'),
        'no_job': (NotFound,
                   'The job does\'nt exist'),
        'lock_exists': (Forbidden,
                        'The lock already exists'),
        'must_be_running': (Forbidden,
                            'The job must be running'),
        'must_be_paused': (Forbidden,
                           'The job must be paused'),
        'must_be_waiting_paused_finished': (Forbidden,
                                            'The job must be waiting or paused or finished')
        }

    key_job_conf = 'xcute:job:config:%s'
    key_job_ids = 'xcute:job:ids'
    key_job_info = 'xcute:job:info:%s'
    key_job_queue = 'xcute:job:queue'
    key_tasks_running = 'xcute:tasks:running:%s'
    key_orchestrator_jobs = 'xcute:orchestrator:jobs:%s'

    _lua_update_mtime = """
        local time = redis.call('TIME');
        redis.call('HSET', 'xcute:job:info:' .. job_id, 'mtime',
                   time[1] .. '.' .. time[2]);
    """

    lua_create_job = """
        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. KEYS[1]);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        redis.call('ZADD', 'xcute:job:ids', 0, KEYS[1]);
        redis.call('LPUSH', 'xcute:job:queue', KEYS[1]);
    """

    lua_take_job = """
        local job_id = redis.call('RPOP', 'xcute:job:queue');
        if job_id == false then
            return nil;
        end;

        local job_conf = redis.call('HGETALL', 'xcute:job:config:' .. job_id);
        local job_info = redis.call('HGETALL', 'xcute:job:info:' .. job_id);

        redis.call('SADD', 'xcute:orchestrator:jobs:' .. KEYS[1], job_id);
        redis.call('HSET', 'xcute:job:info:' .. job_id, 'orchestrator_id', KEYS[1]);

        return {job_id, job_conf, job_info};
    """

    lua_update_tasks_processed = """
        local function get_counters(tbl, first, last)
            local sliced = {}
            for i = first or 1, last or #tbl, 2 do
                sliced[tbl[i]] = tbl[i+1];
            end;
            return sliced;
        end;

        local job_id = KEYS[1];
        local counters = get_counters(KEYS, 2, nil);
        local tasks_processed = ARGV;
        local tasks_processed_length = #tasks_processed;

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local total_tasks_processed = redis.call(
            'HINCRBY', 'xcute:job:info:' .. job_id,
            'processed', tasks_processed_length);
        for _, task_id in ipairs(tasks_processed) do
            redis.call('SREM', 'xcute:tasks:running:' .. job_id, task_id);
        end;

        for key, value in pairs(counters) do
            redis.call('HINCRBY', 'xcute:job:info:' .. job_id,
                       key, value);
        end;

        local tasks_all_sent = redis.call(
            'HGET', 'xcute:job:info:' .. job_id, 'all_sent');
        if tasks_all_sent == '1' and status ~= 'FINISHED' then
            local total_tasks_sent = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'sent');
            if tonumber(total_tasks_processed) >= tonumber(total_tasks_sent) then
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'status', 'FINISHED');
            end;
        end;
    """ + _lua_update_mtime

    lua_delete_job = """
        local job_info = redis.call('HMGET', 'xcute:job:info:' .. KEYS[1],
                                    'status', 'orchestrator_id');
        local status = job_info[1];

        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status ~= 'WAITING' and status ~= 'PAUSED' and status ~= 'FINISHED' then
            return redis.error_reply('must_be_waiting_paused_finished');
        end;

        if status == 'WAITING' then
            redis.call('LREM', 'xcute:job:queue', 1, KEYS[1]);
        end;

        if status == 'PAUSED' then
            local orchestrator_id = job_info[2];

            redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id, KEYS[1]);
        end;

        redis.call('ZREM', 'xcute:job:ids', KEYS[1]);
        redis.call('DEL', 'xcute:job:info:' .. KEYS[1]);
        redis.call('DEL', 'xcute:job:config:' .. KEYS[1]);
        """

    def __init__(self, conf):
        self.conf = conf
        redis_conf = {k[6:]: v for k, v in self.conf.items()
                      if k.startswith('redis_')}
        super(XcuteBackend, self).__init__(**redis_conf)

        self.script_create_job = self.register_script(
            self.lua_create_job)
        self.script_take_job = self.register_script(
            self.lua_take_job)
        self.script_update_tasks_processed = self.register_script(
            self.lua_update_tasks_processed)
        self.script_delete_job = self.register_script(
            self.lua_delete_job)

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
                self._get_job_info(job_id, client=pipeline)
            job_infos = pipeline.execute()

            for job_id, job_info in zip(job_ids, job_infos):
                if not job_info:
                    continue

                job = dict(job_id=job_id, **self._unmarshal_job_info(job_info))
                jobs.append(job)

            if len(job_ids) < limit_:
                break
            marker = job_id
        return jobs

    @handle_redis_exceptions
    def create_job(self, job_id, job_conf, job_info):
        pipeline = self.conn.pipeline()

        self.script_create_job(keys=[job_id], client=pipeline)
        self._update_job_info(job_id, job_info, client=pipeline)
        self._update_job_conf(job_id, job_conf, client=pipeline)

        pipeline.execute()

    @handle_redis_exceptions
    def start_job(self, job_id, job_conf, job_info):
        pipeline = self.conn.pipeline()

        self._update_job_info(job_id, job_info, client=pipeline)
        self._update_job_conf(job_id, job_conf, client=pipeline)

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
            (job_id, self._unmarshal_job_conf(job_conf), self._unmarshal_job_info(job_info))
            for job_conf, job_info in zip(*([iter(job_config_infos)] * 2))
        )

    @handle_redis_exceptions
    def take_job(self, orchestrator_id):
        job = self.script_take_job(keys=[orchestrator_id])

        if job is None:
            return None

        job_id = job[0]
        job_conf = self._unmarshal_job_conf(self._lua_array_to_dict(job[1]))
        job_info = self._unmarshal_job_info(self._lua_array_to_dict(job[2]))

        return job_id, job_conf, job_info

    def incr_sent(self, job_id, task_id, updates):
        pipeline = self.conn.pipeline()

        pipeline.hincrby(self.key_job_info % job_id, 'sent', 1)
        pipeline.sadd(self.key_tasks_running % job_id, task_id)
        self._update_job_info(job_id, updates, client=pipeline)

        pipeline.execute()

    @handle_redis_exceptions
    def all_sent(self, orchestrator_id, job_id, updates, is_finished):
        pipeline = self.conn.pipeline()

        self._update_job_info(job_id, updates, client=pipeline)
        if is_finished:
            pipeline.srem(self.key_orchestrator_jobs % orchestrator_id, job_id)

        pipeline.execute()

    @handle_redis_exceptions
    def update_tasks_processed(self, job_id, task_ids,
                               task_errors, task_results):
        counters = dict()
        if task_errors:
            counters['errors.total'] = len(task_errors)
        if task_results:
            for key, value in task_results.items():
                counters['results.' + key] = value
        self.script_update_tasks_processed(
            keys=[job_id] + self._dict_to_lua_array(counters),
            args=task_ids,
            client=self.conn)

    @handle_redis_exceptions
    def fail_job(self, orchestrator_id, job_id, updates):
        pipeline = self.conn.pipeline()

        pipeline.srem(self.key_orchestrator_jobs % orchestrator_id, job_id)
        self._update_job_info(job_id, updates, client=pipeline)

        pipeline.execute()

    def get_job_conf(self, job_id):
        job_conf = self._get_job_conf(job_id, client=self.conn)

        return self._unmarshal_job_conf(job_conf)

    def get_job_info(self, job_id):
        job_info = self._get_job_info(job_id, client=self.conn)

        return self._unmarshal_job_info(job_info)

    def update_job_conf(self, job_id, updates):
        self._update_job_conf(job_id, updates, client=self.conn)

    def update_job_info(self, job_id, updates):
        self._update_job_info(job_id, updates, client=self.conn)

    @handle_redis_exceptions
    def delete_job(self, job_id):
        self.script_delete_job(keys=[job_id])

    def _get_job_conf(self, job_id, client):
        return client.hgetall(self.key_job_conf % job_id)

    def _get_job_info(self, job_id, client):
        return client.hgetall(self.key_job_info % job_id)

    def _update_job_info(self, job_id, updates, client):
        marshalled_updates = self._marshal_job_info(updates)
        return client.hmset(self.key_job_info % job_id, marshalled_updates)

    def _update_job_conf(self, job_id, updates, client):
        marshalled_updates = self._marshal_job_conf(updates)
        return client.hmset(self.key_job_conf % job_id, marshalled_updates)

    @staticmethod
    def _marshal_job_conf(job_conf):
        marshalled_job_conf = job_conf.copy()

        if 'params' in job_conf:
            marshalled_job_conf['params'] = json.dumps(job_conf['params'])

        return marshalled_job_conf

    @staticmethod
    def _unmarshal_job_conf(marshalled_job_conf):
        job_conf = marshalled_job_conf.copy()

        job_conf['params'] = json.loads(job_conf['params'])

        return job_conf

    @staticmethod
    def _marshal_job_info(job_info):
        marshalled_job_info = job_info.copy()

        if 'all_sent' in job_info:
            marshalled_job_info['all_sent'] = int(job_info['all_sent'])

        if job_info.get('total') is None:
            marshalled_job_info.pop('total', None)

        if 'result' in job_info:
            marshalled_job_info['result'] = json.dumps(job_info['result'])

        return marshalled_job_info

    @staticmethod
    def _unmarshal_job_info(marshalled_job_info):
        job_info = marshalled_job_info.copy()

        all_sent = True if job_info['all_sent'] == '1' else False
        total = int(job_info['total']) if 'total' in job_info else None

        job_info['sent'] = int(job_info['sent'])
        job_info['all_sent'] = all_sent
        job_info['processed'] = int(job_info['processed'])
        job_info['errors'] = int(job_info['errors'])
        job_info['total'] = total
        job_info['result'] = json.loads(job_info['result'])

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
