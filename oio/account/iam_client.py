# Copyright (C) 2021-2022 OVH SAS
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

from oio.common.service_client import ServiceClient


class IamClient(ServiceClient):
    """Simple client API for the Iam service."""

    def __init__(self, conf, **kwargs):
        super(IamClient, self).__init__(
            "account",
            conf,
            service_name="iam-service",
            request_prefix="v1.0/iam",
            **kwargs
        )

    def iam_request(self, account, *args, **kwargs):
        params = kwargs.setdefault("params", {})
        if account:
            params["account"] = account
        return self.service_request(*args, **kwargs)

    def delete_user_policy(self, account, user, policy_name=None, **kwargs):
        params = {"user": user}
        if policy_name:
            params["policy-name"] = policy_name
        _resp, body = self.iam_request(
            account, "DELETE", "delete-user-policy", params=params, **kwargs
        )
        return body

    def get_user_policy(self, account, user, policy_name=None, **kwargs):
        params = {"user": user}
        if policy_name:
            params["policy-name"] = policy_name
        _resp, body = self.iam_request(
            account, "GET", "get-user-policy", params=params, **kwargs
        )
        return body

    def list_users(self, account, **kwargs):
        _resp, body = self.iam_request(account, "GET", "list-users", **kwargs)
        return body

    def list_user_policies(self, account, user, **kwargs):
        params = {"user": user}
        _resp, body = self.iam_request(
            account, "GET", "list-user-policies", params=params, **kwargs
        )
        return body

    def load_merged_user_policies(self, account, user, **kwargs):
        """
        load merged policies for given couple account/user

        :param account: name of the account
        :type account: `str`
        :param user: user of account
        :type user: `str`
        """
        params = {"user": user}
        _resp, body = self.iam_request(
            account, "GET", "load-merged-user-policies", params=params, **kwargs
        )
        return body

    def put_user_policy(self, account, user, policy, policy_name=None, **kwargs):
        params = {"user": user}
        if policy_name:
            params["policy-name"] = policy_name
        _resp, body = self.iam_request(
            account, "PUT", "put-user-policy", params=params, data=policy, **kwargs
        )
        return body
