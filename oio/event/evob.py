# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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


from functools import partial


def is_success(status):
    return 200 <= status <= 299


def is_error(status):
    return 500 <= status <= 599


def _event_env_property(field):
    def getter(self):
        return self.env.get(field, None)

    def setter(self, value):
        self.env[field] = value

    return property(getter, setter)


class Event(object):
    job_id = _event_env_property('job_id')
    event_type = _event_env_property('event')
    data = _event_env_property('data')
    when = _event_env_property('when')

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return "Event [%s](%s)" % (self.job_id, self.event_type)


class Response(object):
    def __init__(self, body=None, status=200, event=None, **kwargs):
        self.status = status
        self.event = event
        if event:
            self.env = event.env
        else:
            self.env = {}
        self.body = body

    def __call__(self, env, cb):
        if not self.event:
            self.event = Event(env)
        if not self.body:
            self.body = ''
        cb(self.status, self.body)


class EventException(Response, Exception):
    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class StatusMap(object):
    def __getitem__(self, key):
        return partial(EventException, status=key)


status_map = StatusMap()
EventOk = status_map[200]
EventError = status_map[500]
