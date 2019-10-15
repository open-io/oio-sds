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


def handle_missing_task_id(func):
    @wraps(func)
    def handle_missing_task_id(self, task_id, **info):
        if not task_id:
            raise BadRequest(message='Missing task ID')
        return func(self, task_id, **info)
    return handle_missing_task_id


def handle_missing_mtime(func):
    @wraps(func)
    def handle_missing_mtime(self, task_id, **info):
        mtime = info.get('mtime')
        if mtime is None:
            raise BadRequest(message='Missing mtime')
        info['mtime'] = Timestamp(mtime).normal
        return func(self, task_id, **info)
    return handle_missing_mtime


def handle_missing_update_info(func):
    @wraps(func)
    def handle_missing_update_info(self, task_id, **info):
        if info.get('last_item_sent') is None:
            raise BadRequest(message='Missing last item sent')
        if info.get('processed_items') is None:
            raise BadRequest(message='Missing number of processed items')
        if info.get('errors') is None:
            raise BadRequest(message='Missing number of errors')
        return func(self, task_id, **info)
    return handle_missing_update_info


class XcuteBackend(RedisConnection):

    NONE_VALUE = 'n/a'

    _lua_update_info = """
        redis.call('HMSET', 'xcute:info:' .. KEYS[1], unpack(ARGV));
        """

    lua_start_task = """
        local exists = redis.call('EXISTS', 'xcute:info:' .. KEYS[1]);
        if exists == 1 then
            return redis.error_reply('task_exists');
        end;

        redis.call('HMSET', 'xcute:info:' .. KEYS[1], 'status', 'RUN');
        redis.call('ZADD', 'xcute:all:ids', 0, KEYS[1]);
        """ + _lua_update_info

    lua_update_task = """
        local status = redis.call('HMGET', 'xcute:info:' .. KEYS[1], 'status');
        if status == nil then
            return redis.error_reply('no_task');
        end;
        if status[1] ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;
        """ + _lua_update_info

    lua_pause_task = """
        local status = redis.call('HMGET', 'xcute:info:' .. KEYS[1], 'status');
        if status == nil then
            return redis.error_reply('no_task');
        end;
        if status[1] ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;

        redis.call('HMSET', 'xcute:info:' .. KEYS[1], 'status', 'PAUSE');
        """ + _lua_update_info

    lua_resume_task = """
        local status = redis.call('HMGET', 'xcute:info:' .. KEYS[1], 'status');
        if status == nil then
            return redis.error_reply('no_task');
        end;
        if status[1] ~= 'PAUSE' then
            return redis.error_reply('must_be_paused');
        end;

        redis.call('HMSET', 'xcute:info:' .. KEYS[1], 'status', 'RUN');
        """

    lua_finish_task = """
        local status = redis.call('HMGET', 'xcute:info:' .. KEYS[1], 'status');
        if status == nil then
            return redis.error_reply('no_task');
        end;
        if status[1] ~= 'RUN' then
            return redis.error_reply('must_be_running');
        end;

        redis.call('HMSET', 'xcute:info:' .. KEYS[1], 'status', 'FINISHED');
        """ + _lua_update_info

    lua_delete_task = """
        local status = redis.call('HMGET', 'xcute:info:' .. KEYS[1], 'status');
        if status == nil then
            return redis.error_reply('no_task');
        end;
        if status[1] ~= 'PAUSE' and status[1] ~= 'FINISHED' then
            return redis.error_reply('must_be_paused_finished');
        end;

        redis.call('ZREM', 'xcute:all:ids', KEYS[1])
        redis.call('DEL', 'xcute:info:' .. KEYS[1])
        """

    def __init__(self, conf):
        self.conf = conf
        redis_conf = {k[6:]: v for k, v in self.conf.items()
                      if k.startswith("redis_")}
        super(XcuteBackend, self).__init__(**redis_conf)

        self.script_start_task = self.register_script(
            self.lua_start_task)
        self.script_update_task = self.register_script(
            self.lua_update_task)
        self.script_pause_task = self.register_script(
            self.lua_pause_task)
        self.script_resume_task = self.register_script(
            self.lua_resume_task)
        self.script_finish_task = self.register_script(
            self.lua_finish_task)
        self.script_delete_task = self.register_script(
            self.lua_delete_task)

    def list_tasks(self):
        task_ids = self.conn.zrangebylex('xcute:all:ids', '-', '+')
        pipeline = self.conn.pipeline(True)
        for task_id in task_ids:
            pipeline.hgetall('xcute:info:%s' % task_id)
        res = pipeline.execute()

        tasks = list()
        i = 0
        for task_id in task_ids:
            if not res[i]:
                continue
            info = dict()
            info['task_id'] = task_id
            info.update(res[i])
            tasks.append(info)
            i += 1
        return tasks

    @handle_missing_task_id
    def get_task_info(self, task_id):
        info = self.conn.hgetall('xcute:info:%s' % task_id)
        if not info:
            raise NotFound(message='Task %s doest\'nt exist' % task_id)
        info['task_id'] = task_id
        return info

    def _run_script(self, task_id, script, **info):
        script_args = list()
        for k, v in info.items():
            script_args.append(k)
            script_args.append(v)
        try:
            return script(keys=[task_id], args=script_args, client=self.conn)
        except redis.exceptions.ResponseError as exc:
            if str(exc) == 'task_exists':
                raise Forbidden(
                    message='The task %s already exists' % task_id)
            elif str(exc) == 'no_task':
                raise NotFound(
                    message='Task %s doest\'nt exist' % task_id)
            elif str(exc) == 'must_be_running':
                raise Forbidden(
                    message='The task %s must be running' % task_id)
            elif str(exc) == 'must_be_paused':
                raise Forbidden(
                    message='The task %s must be paused' % task_id)
            elif str(exc) == 'must_be_paused':
                raise Forbidden(
                    message='The task %s must be paused' % task_id)
            elif str(exc) == 'must_be_paused_finished':
                raise Forbidden(
                    message='The task %s must be paused or finished' % task_id)
            else:
                raise

    @handle_missing_task_id
    @handle_missing_mtime
    def start_task(self, task_id, **info):
        if info.get('task_type') is None:
            raise BadRequest(message='Missing task type')

        info['ctime'] = info.get('mtime')
        info['expected_items'] = self.NONE_VALUE
        info['last_item_sent'] = self.NONE_VALUE
        info['processed_items'] = 0
        info['errors'] = 0
        self._run_script(task_id, self.script_start_task, **info)

    @handle_missing_task_id
    @handle_missing_mtime
    @handle_missing_update_info
    def update_task(self, task_id, **info):
        self._run_script(task_id, self.script_update_task, **info)

    @handle_missing_task_id
    @handle_missing_mtime
    @handle_missing_update_info
    def pause_task(self, task_id, **info):
        self._run_script(task_id, self.script_pause_task, **info)

    @handle_missing_task_id
    @handle_missing_mtime
    def resume_task(self, task_id, **info):
        self._run_script(task_id, self.script_resume_task, **info)

    @handle_missing_task_id
    @handle_missing_mtime
    @handle_missing_update_info
    def finish_task(self, task_id, **info):
        self._run_script(task_id, self.script_finish_task, **info)

    @handle_missing_task_id
    def delete_task(self, task_id, **info):
        self._run_script(task_id, self.script_delete_task)
