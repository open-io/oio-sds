# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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

from six import binary_type, reraise as six_reraise


class OioException(Exception):
    pass


class ConfigurationException(OioException):
    pass


class MissingAttribute(OioException):
    def __init__(self, attribute):
        self.attribute = attribute

    def __str__(self):
        return '%s' % self.attribute

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.attribute)


class ChunkException(OioException):
    pass


class CorruptedChunk(ChunkException):
    pass


class FaultyChunk(ChunkException):
    """
    Raised when a chunk misses some extended attributes,
    or they have invalid values.
    """

    def __repr__(self):
        if len(self.args) > 1:
            return "%s%r" % (self.__class__.__name__, self.args)
        else:
            return super(FaultyChunk, self).__repr__()


class OrphanChunk(ChunkException):
    pass


class ServerException(OioException):
    pass


class Meta2Exception(OioException):
    pass


class SpareChunkException(Meta2Exception):
    """
    Exception raised when no spare chunk has been found,
    or some may have been found but they don't match all criteria.
    """
    pass


class ContentException(OioException):
    pass


class ContentNotFound(ContentException):
    pass


class UnrecoverableContent(ContentException):
    pass


class ServiceUnavailable(OioException):
    """
    Exception raised when some services are temporarily
    not available. This does not mean data is lost.
    """
    pass


class CommandError(Exception):
    pass


class ExplicitBury(OioException):
    pass


class RetryLater(OioException):
    """
    Exception raised by workers that want a task to be
    rescheduled later.
    """
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


class LifecycleNotFound(OioException):
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


class SourceReadTimeout(OioTimeout):
    """
    Specialization of OioTimeout for the case when a timeout occurs
    while reading data from a client application.
    """
    pass


class DeadlineReached(OioException):
    """
    Special exception to be raised when a deadline is reached.
    This differs from the `OioTimeout` in that we are sure
    the operation won't succeed silently in the background.
    """

    def __str__(self):
        if not self.args:
            return 'Deadline reached'
        return super(DeadlineReached, self).__str__()


class VolumeException(OioException):
    """
    Exception raised when someone is trying to contact a rdir service,
    but there is none assigned to the specified rawx.
    """
    pass


class StatusMessageException(OioException):
    """
    Error carrying an HTTP status, an OIO status and a message.
    """
    def __init__(self, http_status, status=None, message=None):
        self.http_status = http_status
        self.message = message or 'n/a'
        self.status = status
        super(StatusMessageException, self).__init__(self.message)

    def __str__(self):
        out = "%s (HTTP %s)" % (self.message, self.http_status)
        if self.status:
            out += ' (STATUS %s)' % self.status
        return out


class UnfinishedUploadException(OioException):
    """
    Exception raised when a number of chunks are not uploaded.
    """
    def __init__(self, exception, chunks_already_uploaded):
        self.exception = exception
        self.chunks_already_uploaded = chunks_already_uploaded
        super(UnfinishedUploadException, self).__init__()

    def reraise(self):
        """
        Re-raise the wrapped exception. This is intended to be called
        after some sort of cleanup has been done.
        """
        six_reraise(type(self.exception), self.exception, exc_info()[2])


class ClientException(StatusMessageException):
    pass


class BadRequest(ClientException):
    """
    Request is not correct.
    """
    def __init__(self, http_status=400, status=None, message=None):
        super(BadRequest, self).__init__(http_status, status, message)


class Forbidden(ClientException):
    """
    Operation is forbidden.
    """
    def __init__(self, http_status=403, status=None, message=None):
        super(Forbidden, self).__init__(http_status, status, message)


class NotFound(ClientException):
    """Resource was not found."""
    def __init__(self, http_status=404, status=None, message=None):
        super(NotFound, self).__init__(http_status, status, message)


class MethodNotAllowed(ClientException):
    """
    Request method is not allowed.
    May be raised when the namespace is in WORM mode and user tries to delete.
    """
    def __init__(self, http_status=405, status=None, message=None):
        super(MethodNotAllowed, self).__init__(http_status, status, message)

    # TODO(FVE): parse 'Allow' header


class Conflict(ClientException):
    def __init__(self, http_status=409, status=None, message=None):
        super(Conflict, self).__init__(http_status, status, message)


class ClientPreconditionFailed(ClientException):
    def __init__(self, http_status=412, status=None, message=None):
        super(ClientPreconditionFailed, self).__init__(
            http_status, status, message)


class TooLarge(ClientException):
    def __init__(self, http_status=413, status=None, message=None):
        super(TooLarge, self).__init__(http_status, status, message)


class UnsatisfiableRange(ClientException):
    def __init__(self, http_status=416, status=None, message=None):
        super(UnsatisfiableRange, self).__init__(http_status, status, message)


# FIXME(FVE): ServiceBusy is not a client exception
class ServiceBusy(ClientException):
    """
    This kind of exceptions tell that the system was "busy" and could not
    handle the request at the moment. The user is invited to retry after a
    few seconds.
    """
    def __init__(self, http_status=503, status=None, message=None):
        super(ServiceBusy, self).__init__(http_status, status, message)


_http_status_map = {
    400: BadRequest,
    403: Forbidden,
    404: NotFound,
    405: MethodNotAllowed,
    409: Conflict,
    412: ClientPreconditionFailed,
    413: TooLarge,
    416: UnsatisfiableRange,
    503: ServiceBusy,
}


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
            if isinstance(body, binary_type):
                message = body.decode('utf-8')
            else:
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
    if isinstance(exc_value, StatusMessageException):
        args = (exc_value.message, ) + args
    if extra_message:
        args = (extra_message, ) + args
    six_reraise(exc_type, exc_type(*args), exc_info()[2])
