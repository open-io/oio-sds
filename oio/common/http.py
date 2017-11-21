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

import re
try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus
from six import iteritems, text_type

from oio.common.constants import CHUNK_HEADERS, OIO_VERSION
from oio.common.http_eventlet import CustomHttpConnection \
    as NewCustomHttpConnection


_TOKEN = r'[^()<>@,;:\"/\[\]?={}\x00-\x20\x7f]+'
_EXT_PATTERN = re.compile(
    r'(?:\s*;\s*(' + _TOKEN + r')\s*(?:=\s*(' + _TOKEN +
    r'|"(?:[^"\\]|\\.)*"))?)')


def parse_content_type(raw_content_type):
    param_list = []
    if raw_content_type:
        if ';' in raw_content_type:
            content_type, params = raw_content_type.split(';', 1)
            params = ';' + params
            for p in _EXT_PATTERN.findall(params):
                k = p[0].strip()
                v = p[1].strip()
                param_list.append((k, v))
    return raw_content_type, param_list


_content_range_pattern = re.compile(r'^bytes (\d+)-(\d+)/(\d+)$')


def parse_content_range(raw_content_range):
    found = re.search(_content_range_pattern, raw_content_range)
    if not found:
        raise ValueError('invalid content-range %r' % (raw_content_range,))
    return tuple(int(x) for x in found.groups())


def http_header_from_ranges(ranges):
    s = 'bytes='
    for i, (start, end) in enumerate(ranges):
        if end:
            if end < 0:
                raise ValueError("Invalid range (%s, %s)" % (start, end))
            elif start is not None and end < start:
                raise ValueError("Invalid range (%s, %s)" % (start, end))
        else:
            if start is None:
                raise ValueError("Invalid range (%s, %s)" % (start, end))

        if start is not None:
            s += str(start)
        s += '-'

        if end is not None:
            s += str(end)
        if i < len(ranges) - 1:
            s += ','
    return s


def ranges_from_http_header(val):
    if not val.startswith('bytes='):
        raise ValueError('Invalid Range value: %s' % val)
    ranges = []
    for r in val[6:].split(','):
        start, end = r.split('-', 1)
        if start:
            start = int(start)
        else:
            start = None
        if end:
            end = int(end)
            if end < 0:
                raise ValueError('Invalid byterange value: %s' % val)
            elif start is not None and end < start:
                raise ValueError('Invalid byterange value: %s' % val)
        else:
            end = None
            if start is None:
                raise ValueError('Invalid byterange value: %s' % val)
        ranges.append((start, end))
    return ranges


def headers_from_object_metadata(metadata):
    """
    Generate chunk PUT request headers from object metadata.
    """
    out = dict()
    out["transfer-encoding"] = "chunked"
    # FIXME: remove key incoherencies
    out[CHUNK_HEADERS["content_id"]] = metadata['id']
    out[CHUNK_HEADERS["content_version"]] = metadata['version']
    out[CHUNK_HEADERS["content_path"]] = metadata['content_path']
    out[CHUNK_HEADERS["content_chunkmethod"]] = metadata['chunk_method']
    out[CHUNK_HEADERS["content_policy"]] = metadata['policy']
    out[CHUNK_HEADERS["container_id"]] = metadata['container_id']
    out[CHUNK_HEADERS["oio_version"]] = metadata.get('oio_version',
                                                     OIO_VERSION)

    for key in ['metachunk_hash', 'metachunk_size', 'chunk_hash']:
        val = metadata.get(key)
        if val is not None:
            out[CHUNK_HEADERS[key]] = metadata[key]

    header = {}
    for k, v in iteritems(out):
        if isinstance(v, text_type):
            header[k] = quote_plus(v.encode('utf-8'))
        elif isinstance(v, int):
            header[k] = quote_plus('%d' % v)
        else:
            header[k] = quote_plus(v)

    header[CHUNK_HEADERS["full_path"]] = ','.join(metadata['full_path'])
    return header


def get_addr(host, port):
    """
    Generate the address for host (IPv4 or IPv6) and port
    """
    if ':' in host:  # IPv6
        return '[%s]:%s' % (host, port)
    else:  # IPv4
        return '%s:%s' % (host, port)


class HeadersDict(dict):
    def __init__(self, headers, **kwargs):
        if headers:
            self.update(headers)
        self.update(kwargs)

    def update(self, data):
        if hasattr(data, 'keys'):
            for key in data.keys():
                self[key.title()] = data[key]
        else:
            for k, v in data:
                self[k.title()] = v

    def __setitem__(self, k, v):
        if v is None:
            self.pop(k.title(), None)
        return dict.__setitem__(self, k.title(), v)

    def get(self, k, default=None):
        return dict.get(self, k.title(), default)

    def pop(self, k, default=None):
        return dict.pop(self, k.title(), default)


class CustomHttpConnection(NewCustomHttpConnection):
    def __init__(self, *args, **kwargs):
        import warnings
        warnings.simplefilter('once')
        warnings.warn(
            "oio.common.http.CustomHttpConnection is deprecated, "
            "use oio.common.http_eventlet.CustomHttpConnection",
            DeprecationWarning, stacklevel=2)
        NewCustomHttpConnection.__init__(self, *args, **kwargs)
