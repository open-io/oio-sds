# Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
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

from sys import exc_info


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


class ExplicitBury(OioException):
    pass


class ECError(Exception):
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


class NoSuchAccount(OioException):
    pass


class NoSuchContainer(OioException):
    pass


class NoSuchObject(OioException):
    pass


class NoSuchReference(OioException):
    pass


class SourceReadError(OioException):
    pass


class OioNetworkException(OioException):
    """Network related exception (connection, timeout...)."""
    pass


class OioTimeout(OioNetworkException):
    pass


class VolumeException(OioException):
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


class TooLarge(ClientException):
    pass


class UnsatisfiableRange(ClientException):
    def __init__(self, http_status=416, status=None, message=None):
        super(UnsatisfiableRange, self).__init__(http_status, status, message)


class ServiceBusy(ClientException):
    def __init__(self, http_status=503, status=None, message=None):
        super(ServiceBusy, self).__init__(http_status, status, message)


_http_status_map = {404: NotFound,
                    409: Conflict,
                    413: TooLarge,
                    416: UnsatisfiableRange,
                    503: ServiceBusy}


def from_status(status, reason="n/a"):
    cls = _http_status_map.get(status, ClientException)
    return cls(status, None, reason)


def from_response(resp, body=None):
    try:
        http_status = resp.status
    except AttributeError:
        http_status = resp.status_code
    cls = _http_status_map.get(http_status, ClientException)
    if body:
        message = "n/a"
        status = None
        try:
            message = body.get('message')
            status = body.get('status')
        except Exception:
            message = body
        return cls(http_status, status, message)
    else:
        return cls(http_status, resp.reason)


def reraise(exc_type, exc_value, extra_message=None):
    """
    Raise an exception of type `exc_type` with arguments of `exc_value`
    plus maybe `extra_message` at the beginning.
    """
    args = exc_value.args
    if extra_message:
        args = (extra_message, ) + args
    raise exc_type(args), None, exc_info()[2]
