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

from urllib import quote_plus
from oio.common.constants import chunk_headers
from oio.common.http_eventlet import CustomHttpConnection \
    as NewCustomHttpConnection


_token = r'[^()<>@,;:\"/\[\]?={}\x00-\x20\x7f]+'
_ext_pattern = re.compile(
    r'(?:\s*;\s*(' + _token + r')\s*(?:=\s*(' + _token +
    r'|"(?:[^"\\]|\\.)*"))?)')


def parse_content_type(raw_content_type):
    param_list = []
    if raw_content_type:
        if ';' in raw_content_type:
            content_type, params = raw_content_type.split(';', 1)
            params = ';' + params
            for p in _ext_pattern.findall(params):
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
    out[chunk_headers["content_id"]] = metadata['id']
    out[chunk_headers["content_version"]] = metadata['version']
    out[chunk_headers["content_path"]] = metadata['content_path']
    out[chunk_headers["content_chunkmethod"]] = metadata['chunk_method']
    out[chunk_headers["content_policy"]] = metadata['policy']
    out[chunk_headers["container_id"]] = metadata['container_id']
    out[chunk_headers["oio_version"]] = metadata["oio_version"]

    for key in ['metachunk_hash', 'metachunk_size', 'chunk_hash']:
        val = metadata.get(key)
        if val is not None:
            out[chunk_headers[key]] = metadata[key]

    header = {k: quote_plus(str(v)) for (k, v) in out.iteritems()}
    header[chunk_headers["full_path"]] = ','.join(metadata['full_path'])
    return header


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
