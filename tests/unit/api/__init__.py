# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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


from io import BytesIO

from oio.api.object_storage import ObjectStorageApi
from oio.common.green import sleep
from oio.common.http import HeadersDict
from oio.common.http_urllib3 import urllib3
from oio.directory.client import DirectoryClient

CHUNK_SIZE = 1048576
EMPTY_BLAKE3 = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class FakeAPI(object):
    def __init__(self, *args, **kwargs):
        pass


class FakeApiResponse(urllib3.HTTPResponse):
    pass


class FakeStorageApi(ObjectStorageApi):
    pass


class FakeDirectoryClient(DirectoryClient):
    pass


class FakeResponse(object):
    def __init__(self, status, body=b"", headers=None, slow=0):
        self.status = status
        self.body = body
        self.headers = HeadersDict(headers)
        self.stream = BytesIO(body)
        self.slow = slow

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def getheaders(self):
        if "Content-Length" not in self.headers:
            self.headers["Content-Length"] = len(self.body)
        return self.headers.items()

    def _slow(self):
        sleep(self.slow)

    def read(self, amt=0):
        if self.slow:
            self._slow()
        return self.stream.read(amt)

    def __repr__(self):
        return "FakeResponse(status=%s)" % self.status

    def reason(self):
        return str(self.status)


def decode_chunked_body(raw_body):
    body = b""
    remaining = raw_body
    trailers = {}
    reading_trailers = False
    while remaining:
        if reading_trailers:
            header, remaining = remaining.split(b"\r\n", 1)
            if header:
                header_key, header_value = header.split(b": ", 1)
                trailers[header_key.decode("utf-8")] = header_value.decode("utf-8")
        else:
            # get the hexa_length
            hexa_length, remaining = remaining.split(b"\r\n", 1)
            length = int(hexa_length, 16)
            if length == 0:
                # reached the end
                reading_trailers = True
            else:
                # get the body
                body += remaining[:length]
                # discard the \r\n
                remaining = remaining[length + 2 :]
    return body, trailers


def empty_stream():
    return BytesIO(b"")
