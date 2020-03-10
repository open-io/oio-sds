# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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
    reqid = _event_env_property('request_id')
    url = _event_env_property('url')
    when = _event_env_property('when')

    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return "Event [%s,%s](%s)" % (self.job_id, self.reqid, self.event_type)


class Response(object):
    def __init__(self, body=None, status=200, event=None, **kwargs):
        self.status = status
        self.event = event
        if event:
            self.env = event.env
        else:
            self.env = {}
        self.body = body

    def __call__(self, env, beanstalkd, cb):
        if not self.event:
            self.event = Event(env)
        if not self.body:
            self.body = ''
        cb(self.status, self.body)


class EventException(Response, Exception):
    def __init__(self, *args, **kwargs):
        Response.__init__(self, *args, **kwargs)
        Exception.__init__(self, self.status)


class EventTypes(object):
    """Enum class for event type names."""

    ACCOUNT_SERVICES = 'account.services'
    CHUNK_DELETED = 'storage.chunk.deleted'
    CHUNK_NEW = 'storage.chunk.new'
    CONTAINER_DELETED = 'storage.container.deleted'
    CONTAINER_NEW = 'storage.container.new'
    CONTAINER_STATE = 'storage.container.state'
    CONTAINER_UPDATE = 'storage.container.update'
    CONTENT_APPEND = 'storage.content.append'
    CONTENT_BROKEN = 'storage.content.broken'
    CONTENT_DELETED = 'storage.content.deleted'
    CONTENT_UPDATE = 'storage.content.update'
    CONTENT_NEW = 'storage.content.new'
    CONTENT_PERFECTIBLE = 'storage.content.perfectible'
    CONTENT_REBUILT = 'storage.content.rebuilt'
    META2_DELETED = 'storage.meta2.deleted'
    XCUTE_TASKS = 'xcute.tasks'

    CONTAINER_EVENTS = (
        CONTAINER_DELETED,
        CONTAINER_NEW,
        CONTAINER_STATE,
        CONTAINER_UPDATE
    )
    CONTENT_EVENTS = (
        CONTENT_APPEND,
        CONTENT_BROKEN,
        CONTENT_DELETED,
        CONTENT_NEW,
        CONTENT_PERFECTIBLE,
        CONTENT_REBUILT,
        CONTENT_UPDATE
    )


class StatusMap(object):
    def __getitem__(self, key):
        return partial(EventException, status=key)


status_map = StatusMap()
EventOk = status_map[200]
EventError = status_map[500]
