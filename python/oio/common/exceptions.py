class OioException(Exception):
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


_http_status_map = {404: NotFound}


def from_response(resp, body):
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
        return cls(http_status)
