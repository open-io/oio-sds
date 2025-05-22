# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2023-2025 OVH SAS
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

from argparse import Action


class KeyValueAction(Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is None:
            setattr(namespace, self.dest, {})

        if "=" in values:
            getattr(namespace, self.dest, {}).update([values.split("=", 1)])
        else:
            getattr(namespace, self.dest, {}).pop(values, None)


class ValueFormatStoreTrueAction(Action):
    """Same as 'store_true', but also set 'formatter' field to 'value'"""

    def __init__(self, option_strings, dest, nargs=0, **kwargs):
        super(ValueFormatStoreTrueAction, self).__init__(
            option_strings, dest, nargs=nargs, **kwargs
        )

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, True)
        setattr(namespace, "formatter", "value")


class ValueCheckStoreTrueAction(Action):
    """Same as 'store_true', but also set 'aggregated' field to 'true'"""

    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values)
        setattr(namespace, "check", True)


def format_detailed_scores(srv):
    return " ".join(
        [
            f"{k[len('scores') :]}={v}"
            for k, v in srv.get("scores", {}).items()
            if k.startswith("score.")
        ]
    )
