# Copyright (C) 2017-2019 OpenIO SAS, as part of OpenIO SDS
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

import math
import string
from six import binary_type, string_types


def int_value(value, default):
    if value in (None, 'None'):
        return default
    try:
        value = int(value)
    except (TypeError, ValueError):
        raise
    return value


def float_value(value, default):
    if value in (None, 'None'):
        return default
    try:
        value = float(value)
    except (TypeError, ValueError):
        raise
    return value


TRUE_VALUES = set(('true', '1', 'yes', 'on', 't', 'y'))
FALSE_VALUES = set(('false', '0', 'no', 'off', 'f', 'n'))


def true_value(value):
    return value is True or \
        (isinstance(value, string_types) and value.lower() in TRUE_VALUES)


def boolean_value(value, default=False):
    if value in (None, 'None'):
        return default
    try:
        value = str(value).lower()
        if value in TRUE_VALUES:
            return True
        elif value in FALSE_VALUES:
            return False
        else:
            raise ValueError('Boolean value expected')
    except (TypeError, ValueError):
        raise


METRIC_SYMBOLS = ("", "K", "M", "G", "T", "P", "E", "Z", "Y")


def convert_size(size, unit=""):
    if size == 0:
        return "0%s" % unit
    i = int(math.log(size, 1000))
    if i != 0:
        p = math.pow(1000, i)
        size = round(size / p, 3)
    return "%s%s%s" % (size, METRIC_SYMBOLS[i], unit)


def is_hexa(hexa, size=None):
    if not isinstance(hexa, string_types):
        return False
    if size and len(hexa) != size:
        return False
    return all(c in string.hexdigits for c in hexa)


def debinarize(something):
    """
    Convert binary data to string.

    For bytes arrays, return a string.
    For lists, call debinarize all items.
    For dicts, debinarize keys and values.
    For other types, return the item as is.

    :type something: bytes, list, dict, or anything else.
    """
    if isinstance(something, binary_type):
        return something.decode('utf-8')
    elif isinstance(something, list):
        return [debinarize(o) for o in something]
    elif isinstance(something, dict):
        return {debinarize(k): debinarize(v)
                for k, v in something.items()}
    return something
