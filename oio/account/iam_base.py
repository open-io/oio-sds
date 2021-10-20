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

import re

from oio.common.easy_value import true_value
from oio.common.logger import get_logger
from oio.common.json import json


class IamDbBase(object):
    """
    Base class for IAM
    """

    def __init__(self, logger=None, key_prefix='IAM:', subkey_separator='/',
                 allow_empty_policy_name=True):
        self.logger = logger or get_logger(None, 'IAM')
        self.allow_empty_policy_name = true_value(allow_empty_policy_name)
        self.key_prefix = key_prefix
        self.subkey_sep = subkey_separator
        self.name_regex = re.compile(r'[\w+=,.@-]+')

    def append_policy_statements(self, account, user, policy_name, policy,
                                 all_statements):
        """
        Decode the provide policy (JSON bytes) and append all of its
        statements to the list. Does nothing but logging if the policy
        cannot be decoded.
        """
        try:
            policy_obj = json.loads(policy.decode('utf-8'))
            statements = policy_obj.get('Statement')
            if not statements:
                self.logger.warning(
                    'policy %r for %s/%s has no Statement',
                    policy_name, account, user)
            else:
                all_statements.extend(statements)
        except ValueError as err:
            self.logger.warning(
                'policy %r for %s/%s is not JSON-formatted: %s',
                policy_name, account, user, err)
