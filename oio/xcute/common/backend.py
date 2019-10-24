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
        'must_be_paused_finished': (Forbidden,
                                    'The job must be paused or finished')
        }

    key_job_config = 'xcute:job:config:%s'
    key_job_ids = 'xcute:job:ids'
    key_job_info = 'xcute:job:info:%s'
    key_job_queue = 'xcute:job:queue'
    key_job_tasks = 'xcute:job:running:%s'
    key_orchestrator_jobs = 'xcute:orchestrator:jobs:%s'

    lua_create_job = """
        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. KEYS[1]);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        redis.call('ZADD', 'xcute:job:ids', 0, KEYS[1])
        redis.call('LPUSH', 'xcute:job:queue', KEYS[1])
    """

    lua_incr_processed = """
        local processed = redis.call('HINCRBY', 'xcute:job:info:' .. KEYS[2],
                                     'processed', 1);
        redis.call('HINCRBY', 'xcute:job:info:' .. KEYS[2], 'errors', ARGV[1]);

        local sent = redis.call('HMGET', 'xcute:job:info:' .. KEYS[2],
                                'all_sent', 'sent');

        if sent[1] == '1' and tonumber(sent[2]) == processed then
            redis.call('HSET', 'xcute:job:info:' .. KEYS[2],
                       'status', 'FINISHED');
            redis.call('SREM', 'xcute:orchestrator:jobs:' .. KEYS[1],
                       KEYS[2]);

            return 1;
        end;

        return 0;
    """

    lua_delete_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'PAUSED' and status ~= 'FINISHED' then
            return redis.error_reply('must_be_paused_finished');
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
        self.script_incr_processed = self.register_script(
            self.lua_incr_processed)
        self.script_delete_job = self.register_script(
            self.lua_delete_job)

    def list_jobs(self, marker='', limit=1000):
        jobs = list()

        while len(jobs) < limit:
            limit_ = limit - len(jobs)

            range_min = '-'
            if marker:
                range_max = '(' + marker
            else:
                range_max = '+'

            job_ids = self.conn.zrevrangebylex(
                self.key_job_ids, range_max, range_min, 0, limit_)

            if len(job_ids) == 0:
                break

            pipeline = self.conn.pipeline(True)
            for job_id in job_ids:
                pipeline.hgetall(self.key_job_info % job_id)
            job_infos = pipeline.execute()

            for job_id, job_info in zip(job_ids, job_infos):
                if not job_info:
                    continue

                job = dict(job_id=job_id, **self.sanitize_job_info(job_info))
                jobs.append(job)

            marker = jobs[-1]['job_id']

        return jobs

    @handle_redis_exceptions
    def create_job(self, job_id, job_conf, job_info):
        pipeline = self.conn.pipeline()

        self.script_create_job(keys=[job_id], client=pipeline)
        pipeline.hmset(self.key_job_info % job_id, job_info)

        if job_conf is not None and job_conf != {}:
            pipeline.hmset(self.key_job_config % job_id, job_conf)

        pipeline.execute()

    def start_job(self, job_id, job_conf, updates):
        pipeline = self.conn.pipeline()

        pipeline.hmset(self.key_job_config % job_id, job_conf)
        pipeline.hmset(self.key_job_info % job_id, updates)

        pipeline.execute()

    def list_orchestrator_jobs(self, orchestrator_id):
        orchestrator_jobs_key = self.key_orchestrator_jobs % orchestrator_id
        job_ids = self.conn.smembers(orchestrator_jobs_key)

        pipeline = self.conn.pipeline(True)
        for job_id in job_ids:
            pipeline.hgetall(self.key_job_config % job_id)
            pipeline.hgetall(self.key_job_info % job_id)
        job_config_infos = pipeline.execute()

        return (
            (job_id, job_conf or {}, self.sanitize_job_info(job_info))
            for job_conf, job_info in zip(*([iter(job_config_infos)] * 2))
        )

    @handle_redis_exceptions
    def pop_job(self, orchestrator_id):
        while True:
            job_id = self.conn.rpop(self.key_job_queue)

            if job_id is None:
                return None

            job_info = self.get_job_info(job_id)

            # the job has already been deleted, ignore
            if job_info is None:
                continue

            job_conf = self.get_job_config(job_id)

            self.conn.sadd(
                self.key_orchestrator_jobs % orchestrator_id, job_id)

            return job_id, job_conf, job_info

    def incr_sent(self, job_id, task_id, updates):
        pipeline = self.conn.pipeline()

        pipeline.hincrby(self.key_job_info % job_id, 'sent', 1)
        pipeline.hmset(self.key_job_info % job_id, updates)
        pipeline.sadd(self.key_job_tasks % job_id, task_id)

        pipeline.execute()

    @handle_redis_exceptions
    def incr_processed(self, orchestrator_id, job_id, task_id, error, updates):
        pipeline = self.conn.pipeline()

        done = self.script_incr_processed(
            keys=[orchestrator_id, job_id],
            args=[int(error)])
        pipeline.hmset(self.key_job_info % job_id, updates)
        pipeline.srem(self.key_job_tasks % job_id, task_id)

        pipeline.execute()

        return True if done == 1 else False

    def get_job_config(self, job_id):
        return self.conn.hgetall(self.key_job_config % job_id) or {}

    def get_job_info(self, job_id):
        info = self.conn.hgetall(self.key_job_info % job_id)
        if not info:
            raise NotFound(message='Job %s does\'nt exist' % job_id)
        return self.sanitize_job_info(info)

    def update_job_info(self, job_id, updates):
        self.conn.hmset(self.key_job_info % job_id, updates)

    @handle_redis_exceptions
    def delete_job(self, job_id):
        self.script_delete_job(keys=[job_id])

    @staticmethod
    def sanitize_job_info(job_info):
        all_sent = True if job_info['all_sent'] == '1' else False
        total = int(job_info['total']) if 'total' in job_info else None

        job_info['sent'] = int(job_info['sent'])
        job_info['all_sent'] = all_sent
        job_info['processed'] = int(job_info['processed'])
        job_info['errors'] = int(job_info['errors'])
        job_info['total'] = total

        return job_info
