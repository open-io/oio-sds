# Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS
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

import string


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
        (isinstance(value, basestring) and value.lower() in TRUE_VALUES)


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


def convert_size(size, unit=''):
    if abs(size) < 1000.0:
        return '%.0f%s%s' % (size, METRIC_SYMBOLS[0], unit)
    for metric_symbol in METRIC_SYMBOLS[1:-1]:
        size /= 1000.0
        if abs(size) < 1000.0:
            return '%.3f%s%s' % (size, metric_symbol, unit)
    return '%.3f%s%s' % (size, METRIC_SYMBOLS[-1], unit)


def is_hexa(hexa, size=None):
    if not isinstance(hexa, basestring):
        return False
    if size and len(hexa) != size:
        return False
    return all(c in string.hexdigits for c in hexa)
