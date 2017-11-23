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

from eventlet import sleep
from oio.check_service.common import CheckService, random_buffer
from oio.account.client import AccountClient
from oio.container.client import ContainerClient
from oio.directory.client import DirectoryClient
from oio.common.configuration import load_namespace_conf


def cmp(x, y): return(x > y) - (x < y)


class CheckMeta2(CheckService):

    account_name = "_meta2_probe"

    def __init__(self, namespace, **kwargs):
        ep_parts = ["http:/",
                    load_namespace_conf(namespace).get('proxy'),
                    "v3.0",
                    namespace,
                    "content"]

        super(CheckMeta2, self).__init__(namespace, "meta2",
                                         endpoint="/".join(ep_parts), **kwargs)

        self.account = AccountClient({"namespace": self.ns})
        self.container = ContainerClient({"namespace": self.ns})
        self.directory = DirectoryClient({"namespace": self.ns})
        self.reference = random_buffer('0123456789ABCDEF', 64)

    def _get_params(self):
        path = random_buffer('0123456789ABCDEF', 64)
        return {'acct': self.account_name, 'ref': self.reference, 'path': path}

    def _compare_chunks(self, chunks1, chunks2):
        def light_chunks(chunks):
            new_chunks = []
            for chunk in chunks:
                new_chunk = dict()
                new_chunk["url"] = chunk["url"]
                new_chunk["hash"] = chunk["hash"]
                new_chunks.append(new_chunk)
            return new_chunks
        try:
            chunks1 = light_chunks(chunks1)
            chunks1.sort()
            chunks2 = light_chunks(chunks2)
            chunks2.sort()
            return cmp(chunks1, chunks2) == 0
        except TypeError:
            return False

    def _cycle(self, meta2_host):
        self.directory.unlink(
            account=self.account_name, reference=self.reference,
            service_type=self.service_type)
        service = {"host": meta2_host, "type": self.service_type, "args": "",
                   "seq": 1}
        self.directory.force(
            account=self.account_name, reference=self.reference,
            service_type=self.service_type, services=service)

        params = self._get_params()
        global_success = True

        _, body, success = self._request(
            "GET", "/locate", params=params, expected_status=404)
        global_success &= success
        headers = {'X-oio-action-mode': 'autocreate'}
        _, body, success = self._request(
            "POST", "/prepare", params=params, headers=headers,
            json={"size": "1024"}, expected_status=200)
        global_success &= success
        chunks = body
        _, body, success = self._request(
            "GET", "/locate", params=params, expected_status=404)
        global_success &= success
        headers = {"x-oio-content-meta-length": "1024"}
        _, _, success = self._request(
            "POST", "/create", params=params, headers=headers, json=chunks,
            expected_status=204)
        global_success &= success
        _, body, success = self._request(
            "GET", "/locate", params=params, expected_status=200)
        global_success &= success
        success = self._compare_chunks(chunks, body)
        global_success &= success
        _, _, success = self._request(
            "POST", "/delete", params=params, expected_status=204)
        global_success &= success
        _, body, success = self._request(
            "GET", "/locate", params=params, expected_status=404)
        global_success &= success

        return global_success

    def run(self):
        try:
            self.container.container_create(account=self.account_name,
                                            reference=self.reference)
            super(CheckMeta2, self).run()
            self.container.container_delete(account=self.account_name,
                                            reference=self.reference)
            sleep(1)
            self.account.account_delete(self.account_name)
        except Exception as exc:
            print("Exception - " + str(exc))
