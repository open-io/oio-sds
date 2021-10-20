# Copyright (C) 2020-2021 OVH SAS
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

import time

from oio.common.json import json
from oio.common.redis_conn import RedisConnection, catch_service_errors
from oio.account.iam_base import IamDbBase


class RedisIamDb(IamDbBase):
    """
    High-level API to save IAM rules in a Redis database.
    """

    def __init__(self, key_prefix='IAM:', subkey_separator='/', logger=None,
                 allow_empty_policy_name=True, **redis_kwargs):
        super(RedisIamDb, self).__init__(
            key_prefix=key_prefix,
            subkey_separator=subkey_separator,
            allow_empty_policy_name=allow_empty_policy_name,
            logger=logger)

        self.redis = RedisConnection(**redis_kwargs)

    def key_for_account(self, account):
        """
        Get the Redis key to the hash holding IAM policies
        for all users of the specified account.
        """
        return self.key_prefix + 'account:' + account

    def subkey_for_policy(self, user, policy_name=''):
        """
        Get the key to the specified policy (or default one) of the
        specified user.
        """
        # It would be wise to set a trailing separator in the key to the
        # default policy (which has no name). But for compatibility with the
        # previous database format, we chose to keep only the user name.
        return (user if not policy_name
                else self.subkey_sep.join((user, policy_name)))

    @catch_service_errors
    def delete_user_policy(self, account, user, policy_name=''):
        """
        Delete an IAM user policy.

        :rtype: bool
        :returns: True if the policy has been deleted, False if it was
            already deleted.
        """
        acct_key = self.key_for_account(account)
        policy_key = self.subkey_for_policy(user, policy_name)
        deleted = self.redis.conn.hdel(acct_key, policy_key)
        return bool(deleted)

    @catch_service_errors
    def list_users(self, account):
        """
        Get the names of all IAM users of the specified account.
        """
        acct_key = self.key_for_account(account)
        users = {name.decode('utf-8').rsplit(self.subkey_sep, 1)[0]
                 for name in self.redis.conn_slave.hkeys(acct_key)}
        users = list(users)
        users.sort()
        return users

    @catch_service_errors
    def list_user_policies(self, account, user):
        """
        Get the names of all the configured policies for the specified user.
        """
        acct_key = self.key_for_account(account)
        # We consider it is faster to load all keys of the account (with hkeys)
        # and filter them client-side rather than filtering keys server-side
        # and load keys and values (with hscan).
        prefix = user + self.subkey_sep
        prefix_len = len(prefix)
        prefix = prefix.encode('utf-8')
        user_b = user.encode('utf-8')
        policies = [name.decode('utf-8')[prefix_len:]
                    for name in self.redis.conn_slave.hkeys(acct_key)
                    if name.startswith(prefix) or name == user_b]
        policies.sort()
        return policies

    @catch_service_errors
    def load_merged_user_policies(self, account, user):
        """
        Merge all policies of the specified user into a single policy
        document.

        :rtype: dict
        :returns: a dictionary with one 'Statement' key with the list
            of all statements (not JSON)
        """
        acct_key = self.key_for_account(account)
        sub_key = self.subkey_for_policy(user, policy_name='*')
        all_statements = list()
        # Loop on the named policies
        for name, val in self.redis.conn_slave.hscan_iter(acct_key,
                                                          match=sub_key):
            self.append_policy_statements(account, user, name, val,
                                          all_statements)
        # Look for the empty name policy
        if self.allow_empty_policy_name:
            sub_key = self.subkey_for_policy(user, policy_name='')
            val = self.redis.conn_slave.hget(acct_key, sub_key)
            if val:
                self.append_policy_statements(account, user, '', val,
                                              all_statements)
        if all_statements:
            return {'Statement': all_statements}
        return None

    @catch_service_errors
    def get_user_policy(self, account, user, policy_name=''):
        """
        Load an IAM policy for the specified user.

        :rtype: str
        """
        acct_key = self.key_for_account(account)
        policy_key = self.subkey_for_policy(user, policy_name)
        policy = self.redis.conn_slave.hget(acct_key, policy_key)
        return policy.decode('utf-8') if policy else None

    def load_rules_str_for_user(self, account, user):
        """
        Backward compatibility wrapper.
        """
        return self.get_user_policy(account, user)

    @catch_service_errors
    def put_user_policy(self, account, user, policy, policy_name=''):
        """
        Save an IAM policy for the specified user.

        :param policy: JSON-formatted string
        :type policy: str
        :param policy_name: name of the policy (empty string if not set)
        """
        if not isinstance(policy, str):
            raise TypeError("policy parameter must be a string")
        if not policy_name and not self.allow_empty_policy_name:
            raise ValueError('policy name cannot be empty')
        if policy_name and not self.name_regex.fullmatch(policy_name):
            raise ValueError('policy name does not match %s' % (
                self.name_regex.pattern))
        # XXX: we should also match user name, but unfortunately, when using
        # tempauth, user names have the ':' character between the project name
        # and the actual user name.
        try:
            policy_obj = json.loads(policy)
            policy_obj['UpdateDate'] = time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                                     time.gmtime())
            # Strip spaces and new lines
            policy = json.dumps(policy_obj, separators=(',', ':'))
        except ValueError as err:
            raise ValueError('policy is not JSON-formatted: %s' % err)
        acct_key = self.key_for_account(account)
        policy_key = self.subkey_for_policy(user, policy_name)
        self.redis.conn.hset(acct_key, policy_key, policy.encode('utf-8'))

    def save_rules_str_for_user(self, account, user, rules):
        """
        Backward compatibility wrapper.
        """
        return self.put_user_policy(account, user, policy=rules)
