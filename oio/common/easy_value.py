# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2020-2024 OVH SAS
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

HEX_PATTERN = re.compile(r"^[0-9A-Fa-f]+$")


def int_value(value, default):
    """
    Cast an object to an integer.

    Return the default if the object is None or the empty string.
    """
    if value in (None, "None", ""):
        return default
    return int(value)


def float_value(value, default):
    """
    Cast an object to a float.

    Return the default if the object is None or the empty string.
    """
    if value in (None, "None", ""):
        return default
    return float(value)


TRUE_VALUES = set(("true", "1", "yes", "on", "t", "y"))
FALSE_VALUES = set(("false", "0", "no", "off", "f", "n"))


def true_value(value):
    return value is True or (isinstance(value, str) and value.lower() in TRUE_VALUES)


def boolean_value(value, default=False):
    """
    Make a boolean value from an object.

    If the object is None or an empty string, return the default value.
    If the object does not look like something "boolean", raise ValueError.
    """
    if value in (None, "None", ""):
        return default
    value = str(value).lower()
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    raise ValueError("Boolean value expected")


METRIC_SYMBOLS = ("", "K", "M", "G", "T", "P", "E", "Z", "Y")


def convert_size(size, unit=""):
    if abs(size) < 1000.0:
        return f"{size:.0f}{METRIC_SYMBOLS[0]}{unit}"
    for metric_symbol in METRIC_SYMBOLS[1:]:
        size /= 1000.0
        if abs(size) < 1000.0:
            return f"{size:.3f}{metric_symbol}{unit}"
    return f"{size:.3f}{METRIC_SYMBOLS[-1]}{unit}"


def is_hexa(hexa, size=None):
    if not isinstance(hexa, str):
        return False
    if size and len(hexa) != size:
        return False
    return HEX_PATTERN.match(hexa)


def debinarize(something):
    """
    Convert binary data to string.

    For bytes arrays, return a string.
    For lists, call debinarize all items.
    For dicts, debinarize keys and values.
    For other types, return the item as is.

    :type something: bytes, list, dict, or anything else.
    """
    if isinstance(something, bytes):
        return something.decode("utf-8")
    if isinstance(something, list):
        return [debinarize(o) for o in something]
    if isinstance(something, dict):
        return {debinarize(k): debinarize(v) for k, v in something.items()}
    return something
