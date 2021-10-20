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

import json

from cliff import lister, show

from oio.common.utils import parse_conn_str


class IamCommandMixinBase(object):
    """
    Add IAM-related arguments to a cliff command.
    """

    default_connection = 'fdb://127.0.0.1:6379'

    def patch_parser(self, parser):
        parser.add_argument('--connection',
                            help=("Tell how to connect to the IAM database. "
                                  "This overrides the 'iam.connection' "
                                  "parameter defined in the namespace "
                                  "configuration file. Defaults to '%s' if "
                                  "neither parameter is set." %
                                  self.default_connection))
        parser.add_argument('account',
                            help=("The account the user belongs to. "
                                  "Usually 'AUTH_' followed by either the "
                                  "Keystone project ID, or the clear account "
                                  "name when using tempauth."))

    def get_db(self, parsed_args):
        if parsed_args.connection is None:
            parsed_args.connection = self.app.client_manager.sds_conf.get(
                'iam.connection', self.default_connection)
        if parsed_args.connection == self.default_connection:
            self.logger.warn('Using the default connection (%s) is probably '
                             'not what you want to do.',
                             self.default_connection)
        scheme, netloc, kwargs = parse_conn_str(parsed_args.connection)
        if scheme == 'redis+sentinel':
            from oio.account.iam import RedisIamDb
            kwargs['sentinel_hosts'] = netloc
            iam = RedisIamDb(**kwargs)
        elif scheme == 'fdb':
            from oio.account.iam_fdb import FdbIamDb
            # TODO pass default fdb file location as parameter
            parsed_args.fdb_file = self.app.client_manager.sds_conf.get(
                'fdb_file', '/etc/foundationdb/fdb.cluster')
            conf = {}
            conf['fdb_file'] = parsed_args.fdb_file
            iam = FdbIamDb(conf=conf, **kwargs)
            iam.init_db()
        else:
            from oio.account.iam import RedisIamDb
            kwargs['host'] = netloc
            iam = RedisIamDb(**kwargs)
        return iam

    @property
    def logger(self):
        return self.app.client_manager.logger


class IamCommandMixin(IamCommandMixinBase):
    """
    Add IAM-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        super(IamCommandMixin, self).patch_parser(parser)
        parser.add_argument('user',
                            help=("The ID of the user, as seen by the swift "
                                  "gateway. Usually in the form "
                                  "'project_name:user_name'."))
        parser.add_argument('--policy-name',
                            default='',
                            help=("The name of the policy document. "
                                  "If not provided, get/set the default one, "
                                  "but it recommended to always set a name."))

    def pretty_print_policy(self, policy):
        """
        :param policy: JSON-formatted string
        :returns: the pretty-printed version of the policy
        """
        return json.dumps(json.loads(policy), sort_keys=True, indent=4)


class IamDeleteUserPolicy(IamCommandMixin, show.ShowOne):
    """
    Delete an IAM policy.
    """

    columns = ('account', 'user', 'policy_name', 'deleted')

    def get_parser(self, prog_name):
        parser = super(IamDeleteUserPolicy, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        iamdb = self.get_db(parsed_args)
        deleted = iamdb.delete_user_policy(parsed_args.account,
                                           parsed_args.user,
                                           parsed_args.policy_name)
        return self.columns, [parsed_args.account,
                              parsed_args.user,
                              parsed_args.policy_name,
                              deleted]


class IamGetUserPolicy(IamCommandMixin, show.ShowOne):
    """
    Get the IAM policy for the specified user.
    """

    columns = ('account', 'user', 'policy_name', 'policy')

    def get_parser(self, prog_name):
        parser = super(IamGetUserPolicy, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        iamdb = self.get_db(parsed_args)
        policy = iamdb.get_user_policy(parsed_args.account,
                                       parsed_args.user,
                                       parsed_args.policy_name)
        if not policy:
            policy = 'null'
        elif parsed_args.formatter == 'table':
            policy = self.pretty_print_policy(policy)
        return self.columns, [parsed_args.account,
                              parsed_args.user,
                              parsed_args.policy_name,
                              policy]


class IamListUsers(IamCommandMixinBase, lister.Lister):
    """
    Get the list of IAM users for the specified account.
    """

    columns = ('account', 'user')

    def get_parser(self, prog_name):
        parser = super(IamListUsers, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        iamdb = self.get_db(parsed_args)
        users = iamdb.list_users(parsed_args.account)
        if not users:
            self.logger.warning("No IAM users for this account")
            res = users
        else:
            res = ((parsed_args.account, x) for x in users)
        return self.columns, res


class IamListUserPolicies(IamCommandMixin, lister.Lister):
    """
    Get the list of IAM policies for the specified user.

    The default policy has no name, you may get an empty string
    among the results.
    """

    columns = ('account', 'user', 'policy_name')

    def get_parser(self, prog_name):
        parser = super(IamListUserPolicies, self).get_parser(prog_name)
        self.patch_parser(parser)
        return parser

    def take_action(self, parsed_args):
        iamdb = self.get_db(parsed_args)
        policies = iamdb.list_user_policies(parsed_args.account,
                                            parsed_args.user)
        if not policies:
            self.logger.warning("No policy for this user")
            res = policies
        elif parsed_args.policy_name:
            res = ((parsed_args.account, parsed_args.user, x)
                   for x in policies
                   if x.startswith(parsed_args.policy_name))
        else:
            res = ((parsed_args.account, parsed_args.user, x)
                   for x in policies)
        return self.columns, res


class IamPutUserPolicy(IamCommandMixin, show.ShowOne):
    """
    Set an IAM policy for the specified user.
    """

    columns = ('account', 'user', 'policy_name', 'policy')

    def get_parser(self, prog_name):
        parser = super(IamPutUserPolicy, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument('policy',
                            help=("User policy string (JSON), or path to a "
                                  "file containing the policy "
                                  "(use the --from-file option)."))
        parser.add_argument('--from-file',
                            action='store_true',
                            help=("Consider 'policy' as the path to a JSON "
                                  "file. Use '-' to read from stdin."))
        return parser

    def take_action(self, parsed_args):
        if parsed_args.from_file:
            if parsed_args.policy == '-':
                from sys import stdin
                policy = stdin.read()
            else:
                with open(parsed_args.policy, 'r') as rules_f:
                    policy = rules_f.read()
        else:
            policy = parsed_args.policy
        iamdb = self.get_db(parsed_args)
        iamdb.put_user_policy(parsed_args.account,
                              parsed_args.user,
                              policy,
                              parsed_args.policy_name)
        if parsed_args.formatter == 'table':
            policy = self.pretty_print_policy(policy)
        return self.columns, [parsed_args.account,
                              parsed_args.user,
                              parsed_args.policy_name,
                              policy]
