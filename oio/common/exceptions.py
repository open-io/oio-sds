# Copyright (C) 2016 OpenIO SAS

# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from eventlet import Timeout


class OioException(Exception):
    pass


class ConfigurationException(OioException):
    pass


class MissingAttribute(OioException):
    def __init__(self, attribute):
        self.attribute = attribute

    def __str__(self):
        return '%s' % self.attribute


class ChunkException(OioException):
    pass


class CorruptedChunk(ChunkException):
    pass


class FaultyChunk(ChunkException):
    pass


class OrphanChunk(ChunkException):
    pass


class ServerException(OioException):
    pass


class Meta2Exception(OioException):
    pass


class SpareChunkException(Meta2Exception):
    pass


class ContentException(OioException):
    pass


class InconsistentContent(ContentException):
    pass


class ContentNotFound(ContentException):
    pass


class UnrecoverableContent(ContentException):
    pass


class ServiceUnavailable(OioException):
    pass


class CommandError(Exception):
    pass


class ECError(Exception):
    pass


class UnsatisfiableRange(Exception):
    pass


class EmptyByteRange(Exception):
    pass


class InvalidStorageMethod(OioException):
    pass


class PreconditionFailed(OioException):
    pass


class EtagMismatch(OioException):
    pass


class MissingContentLength(OioException):
    pass


class MissingData(OioException):
    pass


class MissingName(OioException):
    pass


class FileNotFound(OioException):
    pass


class ContainerNotEmpty(OioException):
    pass


class NoSuchContainer(OioException):
    pass


class NoSuchObject(OioException):
    pass


class NoSuchReference(OioException):
    pass


class SourceReadError(OioException):
    pass


# Timeouts

class ClientReadTimeout(Timeout):
    pass


class OioTimeout(OioException):
    pass


class ConnectionTimeout(Timeout):
    pass


class SourceReadTimeout(Timeout):
    pass


class ChunkWriteTimeout(Timeout):
    pass


class ChunkReadTimeout(Timeout):
    pass


class ClientException(OioException):
    def __init__(self, http_status, status=None, message=None):
        self.http_status = http_status
        self.message = message or 'n/a'
        self.status = status

    def __str__(self):
        s = "%s (HTTP %s)" % (self.message, self.http_status)
        if self.status:
            s += ' (STATUS %s)' % self.status
        return s


class NotFound(ClientException):
    pass


class Conflict(ClientException):
    pass


_http_status_map = {404: NotFound, 409: Conflict}


def from_response(resp, body=None):
    http_status = resp.status_code
    cls = _http_status_map.get(http_status, ClientException)
    if body:
        message = "n/a"
        status = None
        if isinstance(body, dict):
            message = body.get('message')
            status = body.get('status')
        else:
            message = body
        return cls(http_status, status, message)
    else:
        return cls(http_status, resp.reason)
