# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023 OVH SAS
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

from urllib.parse import quote, unquote


def encode_fullpath(account, container, path, version, content_id):
    for k, v in locals().items():
        if not v:
            raise ValueError("Can't encode fullpath: missing %s" % k)
    if isinstance(account, str):
        account = account.encode("utf-8")
    if isinstance(container, str):
        container = container.encode("utf-8")
    if isinstance(path, str):
        path = path.encode("utf-8")
    return "{0}/{1}/{2}/{3}/{4}".format(
        quote(account, ""),
        quote(container, ""),
        quote(path, ""),
        quote(str(version), ""),
        quote(content_id, ""),
    )


def decode_fullpath(fullpath):
    """
    Decode a "fullpath" string, extract its 5 parts.

    :raises: ValueError if the string has invalid format.
    :returns: account, container, path, version and content ID.
    """
    fp = fullpath.split("/")
    if len(fp) != 5:
        raise ValueError("fullpath: invalid format")
    decoded = []
    for part in fp:
        decoded.append(unquote(part))
    return tuple(decoded)
