# Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2023 OVH SAS
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

from oio.common.exceptions import ContentNotFound
from oio.common.exceptions import NotFound
from oio.common.logger import get_logger
from oio.container.client import ContainerClient
from oio.blob.client import BlobClient
from oio.content.plain import PlainContent
from oio.content.ec import ECContent
from oio.common.storage_method import STORAGE_METHODS


class ContentFactory(object):
    DEFAULT_DATASEC = "plain", {"nb_copy": "1", "distance": "0"}

    def __init__(
        self, conf, container_client=None, blob_client=None, logger=None, **kwargs
    ):
        self.conf = conf
        self.logger = logger or get_logger(conf)
        self.container_client = container_client or ContainerClient(
            conf, logger=self.logger, **kwargs
        )
        self.blob_client = blob_client or BlobClient(conf, logger=self.logger, **kwargs)

    def _get(
        self, container_id, meta, chunks, account=None, container_name=None, **kwargs
    ):
        # Some objects may not have cca and oca attributes, which have been
        # introduced at the same time as the blake3 algorithm. Which means
        # objects without these attributes use the old default algorithm: md5.
        storage_method = STORAGE_METHODS.load(meta["chunk_method"])
        storage_method.fix_missing_checksum_algo(chunk_checksum_algo="md5")
        meta["chunk_method"] = storage_method.to_chunk_method()
        if not account or not container_name:
            container_info = self.container_client.container_get_properties(
                cid=container_id, **kwargs
            )["system"]
            if not account:
                account = container_info["sys.account"]
            if not container_name:
                container_name = container_info["sys.user.name"]
        cls = ECContent if storage_method.ec else PlainContent
        return cls(
            self.conf,
            container_id,
            meta,
            chunks,
            storage_method,
            account,
            container_name,
            container_client=self.container_client,
            blob_client=self.blob_client,
            logger=self.logger,
        )

    def get(
        self, container_id, content_id, account=None, container_name=None, **kwargs
    ):
        # Deprecated, prefer using get_by_path_and_version.
        # Using path and versions allows to resolve objects in sharded containers.
        try:
            meta, chunks = self.container_client.content_locate(
                cid=container_id, content=content_id, **kwargs
            )
        except NotFound:
            raise ContentNotFound(f"Content {container_id}/{content_id} not found")

        return self._get(
            container_id,
            meta,
            chunks,
            account=account,
            container_name=container_name,
            **kwargs,
        )

    def get_by_path_and_version(
        self,
        container_id,
        content_id,
        path,
        version,
        account=None,
        container_name=None,
        **kwargs,
    ):
        try:
            meta, chunks = self.container_client.content_locate(
                cid=container_id,
                content=content_id,
                path=path,
                version=version,
                **kwargs,
            )
        except NotFound:
            raise ContentNotFound(
                f"Content {container_id}/{path}/{version}/{content_id} not found"
            )

        return self._get(
            container_id,
            meta,
            chunks,
            account=account,
            container_name=container_name,
            **kwargs,
        )

    def new(
        self,
        container_id,
        path,
        size,
        policy,
        account=None,
        container_name=None,
        **kwargs,
    ):
        meta, chunks = self.container_client.content_prepare(
            cid=container_id, path=path, size=size, stgpol=policy, **kwargs
        )

        storage_method = STORAGE_METHODS.load(meta["chunk_method"])
        storage_method.fix_missing_checksum_algo()
        meta["chunk_method"] = storage_method.to_chunk_method()
        if not account or not container_name:
            container_info = self.container_client.container_get_properties(
                cid=container_id
            )["system"]
            if not account:
                account = container_info["sys.account"]
            if not container_name:
                container_name = container_info["sys.user.name"]
        cls = ECContent if storage_method.ec else PlainContent
        return cls(
            self.conf,
            container_id,
            meta,
            chunks,
            storage_method,
            account,
            container_name,
            container_client=self.container_client,
            blob_client=self.blob_client,
            logger=self.logger,
        )

    def copy(self, origin, policy=None):
        if not policy:
            policy = origin.policy
        metadata = origin.metadata.copy()
        new_metadata, chunks = self.container_client.content_prepare(
            cid=origin.container_id,
            path=metadata["name"],
            size=metadata["length"],
            stgpol=policy,
        )

        metadata["chunk_method"] = new_metadata["chunk_method"]
        metadata["chunk_size"] = new_metadata["chunk_size"]
        # We must use a new content_id since we change the data
        metadata["id"] = new_metadata["id"]
        # We may want to keep the same version, but it is denied by meta2
        metadata["version"] = int(metadata["version"]) + 1
        metadata["policy"] = new_metadata["policy"]
        # FIXME: meta2 does not allow us to set ctime
        # and thus the object will appear as new.
        storage_method = STORAGE_METHODS.load(metadata["chunk_method"])

        cls = ECContent if storage_method.ec else PlainContent
        return cls(
            self.conf,
            origin.container_id,
            metadata,
            chunks,
            storage_method,
            origin.account,
            origin.container_name,
            container_client=self.container_client,
            blob_client=self.blob_client,
            logger=self.logger,
        )
