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

import redis
from functools import wraps

from oio.common.exceptions import BadRequest, Forbidden, NotFound
from oio.common.redis_conn import RedisConnection
from oio.common.timestamp import Timestamp


def handle_missing_job_id(func):
    @wraps(func)
    def handle_missing_job_id(self, job_id, **info):
        if not job_id:
            raise BadRequest(message='Missing job ID')
        return func(self, job_id, **info)
    return handle_missing_job_id


def handle_missing_mtime(func):
    @wraps(func)
    def handle_missing_mtime(self, job_id, **info):
        mtime = info.get('mtime')
        if mtime is None:
            raise BadRequest(message='Missing mtime')
        info['mtime'] = Timestamp(mtime).normal
        return func(self, job_id, **info)
    return handle_missing_mtime


def handle_missing_update_info(func):
    @wraps(func)
    def handle_missing_update_info(self, job_id, **info):
        if info.get('last_item_sent') is None:
            raise BadRequest(message='Missing last item sent')
        if info.get('processed_items') is None:
            raise BadRequest(message='Missing number of processed items')
        if info.get('errors') is None:
            raise BadRequest(message='Missing number of errors')
        return func(self, job_id, **info)
    return handle_missing_update_info


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

    _lua_update_info = """
        redis.call('HMSET', 'xcute:job:info:' .. KEYS[1], unpack(ARGV));
        """

    lua_start_job = """
        local job_exists = redis.call('EXISTS', 'xcute:job:info:' .. KEYS[1]);
        if job_exists == 1 then
            return redis.error_reply('job_exists');
        end;

        for i, v in ipairs(ARGV) do
            if math.mod(i,2) == 1 and v == 'lock' then
                local lock = ARGV[i+1];
                local lock_exists = redis.call('HSETNX', 'xcute:locks',
                                               lock, KEYS[1]);
                if lock_exists ~= 1 then
                    return redis.error_reply('lock_exists');
                end;
                break;
            end;
        end;

        redis.call('HSET', 'xcute:job:info:' .. KEYS[1],
                   'status', 'RUN');
        redis.call('ZADD', 'xcute:job:ids', 0, KEYS[1]);
        """ + _lua_update_info

    lua_update_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;
        """ + _lua_update_info

    lua_pause_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;

        redis.call('HSET', 'xcute:job:info:' .. KEYS[1], 'status', 'PAUSE');
        """ + _lua_update_info

    lua_resume_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'PAUSE' then
            return redis.error_reply('must_be_paused');
        end;

        redis.call('HSET', 'xcute:job:info:' .. KEYS[1], 'status', 'RUN');
        """

    lua_finish_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;

        local lock = redis.call('HGET', 'xcute:job:info:' .. KEYS[1], 'lock');
        if lock ~= nil and lock ~= false then
            redis.call('HDEL', 'xcute:locks', lock);
        end;

        redis.call('HSET', 'xcute:job:info:' .. KEYS[1], 'status', 'FINISHED');
        """ + _lua_update_info

    lua_delete_job = """
        local status = redis.call('HGET', 'xcute:job:info:' .. KEYS[1],
                                  'status');
        if status == nil or status == false then
            return redis.error_reply('no_job');
        end;
        if status ~= 'PAUSE' and status ~= 'FINISHED' then
            return redis.error_reply('must_be_paused_finished');
        end;

        local lock = redis.call('HGET', 'xcute:job:info:' .. KEYS[1], 'lock');
        if lock ~= nil and lock ~= false then
            redis.call('HDEL', 'xcute:locks', lock);
        end;

        redis.call('ZREM', 'xcute:job:ids', KEYS[1]);
        redis.call('DEL', 'xcute:job:info:' .. KEYS[1]);
        redis.call('DEL', 'xcute:job:config:' .. KEYS[1]);
        """

    lua_set_config = """
        redis.call('HMSET', 'xcute:job:config:' .. KEYS[1], unpack(ARGV));
        """

    lua_get_config = """
    """

    def __init__(self, conf):
        self.conf = conf
        redis_conf = {k[6:]: v for k, v in self.conf.items()
                      if k.startswith("redis_")}
        super(XcuteBackend, self).__init__(**redis_conf)

        self.script_start_job = self.register_script(
            self.lua_start_job)
        self.script_update_job = self.register_script(
            self.lua_update_job)
        self.script_pause_job = self.register_script(
            self.lua_pause_job)
        self.script_resume_job = self.register_script(
            self.lua_resume_job)
        self.script_finish_job = self.register_script(
            self.lua_finish_job)
        self.script_delete_job = self.register_script(
            self.lua_delete_job)
        self.script_set_config = self.register_script(
            self.lua_set_config)

    def list_jobs(self, marker=None, limit=1000):
        jobs = list()
        while True:
            limit_ = limit - len(jobs)
            if limit_ <= 0:
                break
            min = '-'
            if marker:
                max = '(' + marker
            else:
                max = '+'

            job_ids = self.conn.zrevrangebylex(
                'xcute:job:ids', max, min, 0, limit - len(jobs))

            pipeline = self.conn.pipeline(True)
            for job_id in job_ids:
                pipeline.hgetall('xcute:job:info:%s' % job_id)
            res = pipeline.execute()
            i = 0
            for job_id in job_ids:
                if not res[i]:
                    continue
                info = dict()
                info['job_id'] = job_id
                info.update(res[i])
                jobs.append(info)
                i += 1

            if len(job_ids) < limit_:
                break
        return jobs

    @handle_missing_job_id
    def get_job_info(self, job_id):
        info = self.conn.hgetall('xcute:job:info:%s' % job_id)
        if not info:
            raise NotFound(message='Job %s doest\'nt exist' % job_id)
        info['job_id'] = job_id
        info['expected_items'] = info.get('expected_items')
        info['last_item_sent'] = info.get('last_item_sent')
        return info

    @handle_missing_job_id
    def get_job_config(self, job_id):
        conf = self.conn.hgetall('xcute:job:config:%s' % job_id)
        if not conf:
            raise NotFound(message='Job %s doest\'nt exist' % job_id)
        return conf

    def get_locks(self):
        return self.conn.hgetall('xcute:locks')

    def _run_script(self, job_id, script, client=None, **info):
        client = client or self.conn

        script_args = list()
        for key, value in info.items():
            if value is None:
                continue
            script_args.append(key)
            script_args.append(value)

        try:
            return script(keys=[job_id], args=script_args, client=client)
        except redis.exceptions.ResponseError as exc:
            error = self._lua_errors.get(str(exc))
            if error is None:
                raise
            error_cls, error_msg = error
            raise error_cls(message=error_msg)

    @handle_missing_job_id
    @handle_missing_mtime
    def start_job(self, job_id, conf=None, **info):
        if conf is None:
            raise BadRequest(message='Missing configuration')
        if info.get('job_type') is None:
            raise BadRequest(message='Missing job type')

        info['ctime'] = info.get('mtime')
        info['processed_items'] = 0
        info['errors'] = 0

        script_args_conf = list()
        for key, value in conf.items():
            if value is None:
                continue
            script_args_conf.append(key)
            script_args_conf.append(value)

        pipeline = self.conn.pipeline()
        self._run_script(
            job_id, self.script_start_job, client=pipeline, **info)
        self.script_set_config(
            keys=[job_id], args=script_args_conf, client=pipeline)
        pipeline.execute()

    @handle_missing_job_id
    @handle_missing_mtime
    @handle_missing_update_info
    def update_job(self, job_id, **info):
        self._run_script(job_id, self.script_update_job, **info)

    @handle_missing_job_id
    @handle_missing_mtime
    @handle_missing_update_info
    def pause_job(self, job_id, **info):
        self._run_script(job_id, self.script_pause_job, **info)

    @handle_missing_job_id
    @handle_missing_mtime
    def resume_job(self, job_id, **info):
        self._run_script(job_id, self.script_resume_job, **info)

    @handle_missing_job_id
    @handle_missing_mtime
    @handle_missing_update_info
    def finish_job(self, job_id, **info):
        self._run_script(job_id, self.script_finish_job, **info)

    @handle_missing_job_id
    def delete_job(self, job_id, **info):
        self._run_script(job_id, self.script_delete_job)
