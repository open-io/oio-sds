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

import random
import redis

from oio.common.exceptions import Forbidden, NotFound
from oio.common.green import datetime
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
        'job_exists': (
            Forbidden,
            'Job already exists'),
        'no_job': (
            NotFound,
            'Job does\'nt exist'),
        'job_must_be_paused_finished': (
            Forbidden,
            'Job must be paused or finished'),
        'job_already_waiting_run': (
            Forbidden,
            'Job already waiting run'),
        'job_already_running': (
            Forbidden,
            'Job already running'),
        'job_already_wait_pause': (
            Forbidden,
            'Job already wait pause'),
        'job_already_paused': (
            Forbidden,
            'Job already paused'),
        'job_running_last_tasks': (
            Forbidden,
            'Job sent all tasks to the workers and waits the last results'),
        'job_finished': (
            Forbidden,
            'Job is finished')
        }

    key_job_conf = 'xcute:job:config:%s'
    key_job_ids = 'xcute:job:ids'
    key_job_info = 'xcute:job:info:%s'
    key_waiting_run_jobs = 'xcute:waiting_run:jobs'
    key_tasks_running = 'xcute:tasks:running:%s'
    key_orchestrator_jobs = 'xcute:orchestrator:jobs:%s'

    lua_create = """
        local job_id = KEYS[1];
        local job_type = KEYS[2];
        local job_config = ARGV;

        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. KEYS[1]);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        redis.call('ZADD', 'xcute:job:ids', 0, job_id);
        redis.call(
            'HSET', 'xcute:job:info:' .. job_id,
            'id', job_id,
            'type', job_type,
            'status', 'WAITING_RUN',
            'sent', '0',
            'processed', '0',
            'errors', '0');
        redis.call('HSET', 'xcute:job:config:' .. job_id, unpack(job_config));
        redis.call('RPUSH', 'xcute:waiting_run:jobs', job_id);
    """

    lua_run_next = """
        local orchestrator_id = KEYS[1];

        local job_id = redis.call('LPOP', 'xcute:waiting_run:jobs');
        if job_id == nil or job_id == false then
            return nil;
        end;

        redis.call('HSET', 'xcute:job:info:' .. job_id,
                   'status', 'RUNNING',
                   'orchestrator_id', orchestrator_id);
        redis.call('SADD', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                   job_id);

        local job_info = redis.call('HGETALL', 'xcute:job:info:' .. job_id);
        local job_config = redis.call('HGETALL', 'xcute:job:config:' .. job_id);
        return {job_id, job_info, job_config};
    """

    lua_request_pause = """
        local job_id = KEYS[1];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'WAITING_RUN' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'status', 'PAUSED');
            redis.call('LREM', 'xcute:waiting_run:jobs', 1, job_id);
            return;
        end;

        if status == 'RUNNING' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'status', 'WAITING_PAUSE');
            return;
        end;

        if status == 'WAITING_PAUSE' then
            return redis.error_reply('job_already_wait_pause');
        end;

        if status == 'PAUSED' then
            return redis.error_reply('job_already_paused');
        end;

        if status == 'RUNNING_LAST_TASKS' then
            return redis.error_reply('job_running_last_tasks');
        end;

        if status == 'FINISHED' then
            return redis.error_reply('job_finished');
        end;
    """

    lua_resume = """
        local job_id = KEYS[1];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status == 'WAITING_RUN' then
            return redis.error_reply('job_already_waiting_run');
        end;

        if status == 'RUNNING' then
            return redis.error_reply('job_already_running');
        end;

        if status == 'WAITING_PAUSE' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'status', 'RUNNING');
            return;
        end;

        if status == 'PAUSED' then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'status', 'WAITING_RUN');
            redis.call('RPUSH', 'xcute:waiting_run:jobs', job_id);
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
        local job_id = KEYS[1];
        local all_tasks_sent = KEYS[2];
        local tasks_sent = ARGV;
        local tasks_sent_length = #tasks_sent;

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        local total_tasks_sent = redis.call(
            'HINCRBY', 'xcute:job:info:' .. job_id,
            'sent', tasks_sent_length);
        for _, task_id in ipairs(tasks_sent) do
            redis.call('SADD', 'xcute:tasks:running:' .. job_id, task_id);
        end;
        if tasks_sent_length > 0 then
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'last_sent', tasks_sent[tasks_sent_length]);
        end;

        local stopped = false;
        if all_tasks_sent == 'True' then
            if tonumber(total_tasks_sent) == 0 then
                -- if there is no task sent, finish job
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'status', 'FINISHED');
            else
                -- else, wait the last tasks
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'status', 'RUNNING_LAST_TASKS');
            end;
            -- remove the job of the orchestrator
            local orchestrator_id = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'orchestrator_id');
            redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                       job_id);
            stopped = true;
        elseif status == 'WAITING_PAUSE' then
            -- if waiting pause, pause the job
            redis.call('HSET', 'xcute:job:info:' .. job_id,
                       'status', 'PAUSED');
            local orchestrator_id = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'orchestrator_id');
            redis.call('SREM', 'xcute:orchestrator:jobs:' .. orchestrator_id,
                       job_id);
            stopped = true;
        end;
        return stopped;
    """

    lua_update_tasks_processed = """
        local job_id = KEYS[1];
        local errors = KEYS[2];
        local results = KEYS[3];
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

        redis.call('HINCRBY', 'xcute:job:info:' .. job_id,
                   'errors', errors);
        redis.call('HINCRBY', 'xcute:job:info:' .. job_id,
                   'results', results);

        if status == 'RUNNING_LAST_TASKS' then
            local total_tasks_sent = redis.call(
                'HGET', 'xcute:job:info:' .. job_id, 'sent');
            if tonumber(total_tasks_processed) >= tonumber(total_tasks_sent) then
                redis.call('HSET', 'xcute:job:info:' .. job_id,
                           'status', 'FINISHED');
            end;
        end;
    """

    lua_delete = """
        local job_id = KEYS[1];

        local status = redis.call('HGET', 'xcute:job:info:' .. job_id,
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;

        if status ~= 'PAUSED' and status ~= 'FINISHED' then
            return redis.error_reply('job_must_be_paused_finished');
        end;

        redis.call('ZREM', 'xcute:job:ids', job_id);
        redis.call('DEL', 'xcute:job:info:' .. job_id);
        redis.call('DEL', 'xcute:job:config:' .. job_id);
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
        self.script_resquest_pause = self.register_script(
            self.lua_request_pause)
        self.script_resume = self.register_script(
            self.lua_resume)
        self.script_update_tasks_sent = self.register_script(
            self.lua_update_tasks_sent)
        self.script_update_tasks_processed = self.register_script(
            self.lua_update_tasks_processed)
        self.script_delete = self.register_script(
            self.lua_delete)

    def status(self):
        job_count = self.conn.zcard(self.key_job_ids)
        status = {'job_count': job_count}
        return status

    def list_jobs(self, marker=None, limit=None):
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

                job = dict(**self._unmarshal_job_info(job_info))
                job['id'] = job_id
                jobs.append(job)

            if len(job_ids) < limit_:
                break
            marker = job_id
        return jobs

    @handle_redis_exceptions
    def create(self, job_type, job_config):
        job_id = datetime.utcnow().strftime('%Y%m%d%H%M%S%f') \
            + '-%011x' % random.randrange(16**11)

        script_args = list()
        for key, value in self._marshal_job_conf(job_config).items():
            script_args.append(key)
            script_args.append(value)

        self.script_create(
            keys=[job_id, job_type], args=script_args, client=self.conn)
        return job_id

    @handle_redis_exceptions
    def run_next(self, orchestrator_id):
        next_job = self.script_run_next(
            keys=[orchestrator_id], client=self.conn)
        if next_job is None:
            return None
        job_id, job_info, job_config = next_job
        job_info_dict = dict()
        for key, value in zip(*([iter(job_info)] * 2)):
            job_info_dict[key] = value
        job_config_dict = dict()
        for key, value in zip(*([iter(job_config)] * 2)):
            job_config_dict[key] = value
        return (job_id, job_info_dict['type'], job_info_dict.get('last_sent'),
                self._unmarshal_job_conf(job_config_dict))

    @handle_redis_exceptions
    def get_running_jobs(self, orchestrator_id):
        job_ids = self.conn.smembers(
            self.key_orchestrator_jobs % orchestrator_id)

        pipeline = self.conn.pipeline()
        for job_id in job_ids:
            pipeline.hgetall(self.key_job_info % job_id)
            pipeline.hgetall(self.key_job_conf % job_id)
        job_config_infos = pipeline.execute()

        running_jobs = list()
        for job_id, job_info, job_config in zip(
                job_ids, *([iter(job_config_infos)] * 2)):
            running_jobs.append(
                job_id, job_info['type'], job_info.get('last_sent'),
                self._unmarshal_job_conf(job_config))
        return running_jobs

    @handle_redis_exceptions
    def request_pause(self, job_id):
        self.script_resquest_pause(keys=[job_id], client=self.conn)

    @handle_redis_exceptions
    def resume(self, job_id):
        self.script_resume(keys=[job_id], client=self.conn)

    @handle_redis_exceptions
    def update_tasks_sent(self, job_id, task_ids, all_tasks_sent=False):
        return self.script_update_tasks_sent(
            keys=[job_id, str(all_tasks_sent)],
            args=task_ids, client=self.conn)

    @handle_redis_exceptions
    def update_tasks_processed(self, job_id, task_ids,
                               task_errors, task_results):
        self.script_update_tasks_processed(
            keys=[job_id, task_errors, task_results],
            args=task_ids, client=self.conn)

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

    def get_job_type_and_result(self, job_id):
        job_info = self.get_job_info(job_id)

        return job_info['job_type'], job_info.get('result')

    def update_job_conf(self, job_id, updates):
        self._update_job_conf(job_id, updates, client=self.conn)

    def update_job_info(self, job_id, updates):
        self._update_job_info(job_id, updates, client=self.conn)

    @handle_redis_exceptions
    def delete_job(self, job_id):
        self.script_delete(keys=[job_id])

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

        job_info['sent'] = int(job_info['sent'])
        job_info['processed'] = int(job_info['processed'])
        job_info['errors'] = int(job_info['errors'])
        results = job_info.get('results')
        if results is not None:
            job_info['results'] = int(results)

        return job_info

    @staticmethod
    def _lua_array_to_dict(array):
        it = iter(array)
        return dict(zip(*([it] * 2)))
