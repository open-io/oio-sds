# Copyright (C) 2020-2022 OVH SAS
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


class IamCommandMixinBase(object):
    """
    Add IAM-related arguments to a cliff command.
    """

    def patch_parser(self, parser):
        parser.add_argument('account',
                            help=("The account the user belongs to. "
                                  "Usually 'AUTH_' followed by either the "
                                  "Keystone project ID, or the clear account "
                                  "name when using tempauth."))

    def get_iam_client(self, parsed_args):
        return self.app.client_manager.storage.iam

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
        iam_client = self.get_iam_client(parsed_args)
        deleted = iam_client.delete_user_policy(parsed_args.account,
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
        iam_client = self.get_iam_client(parsed_args)
        policy = iam_client.get_user_policy(parsed_args.account,
                                            parsed_args.user,
                                            parsed_args.policy_name)
        policy = json.dumps(policy)
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
        iam_client = self.get_iam_client(parsed_args)
        users = iam_client.list_users(parsed_args.account)
        if not users['Users']:
            self.logger.warning("No IAM users for this account")
            res = users['Users']
        else:
            res = ((parsed_args.account, x) for x in users['Users'])
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
        iam_client = self.get_iam_client(parsed_args)
        policies = iam_client.list_user_policies(parsed_args.account,
                                                 parsed_args.user)
        policies = policies['PolicyNames']

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
        iam_client = self.get_iam_client(parsed_args)
        iam_client.put_user_policy(parsed_args.account,
                                   parsed_args.user,
                                   policy,
                                   parsed_args.policy_name)
        if parsed_args.formatter == 'table':
            policy = self.pretty_print_policy(policy)
        return self.columns, [parsed_args.account,
                              parsed_args.user,
                              parsed_args.policy_name,
                              policy]
