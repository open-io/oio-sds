# Copyright (C) 2026 OVH SAS
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


import warnings
from urllib.parse import unquote

from oio.common import exceptions
from oio.common.cache import (
    del_cached_object_metadata,
    get_cached_object_metadata,
    set_cached_object_metadata,
)
from oio.common.client import ProxyClient
from oio.common.constants import (
    DELETEMARKER_HEADER,
    HEADER_PREFIX,
    SHARD_HEXID_HEADER,
    VERSIONID_HEADER,
)
from oio.common.decorators import ensure_headers
from oio.common.easy_value import boolean_value
from oio.common.json import json
from oio.conscience.client import ConscienceClient
from oio.content.helpers import RawxScoreMixin

CONTENT_HEADER_PREFIX = "x-oio-content-meta-"
SYSMETA_KEYS = (
    "chunk-method",
    "ctime",
    "mtime",
    "deleted",
    "hash",
    "hash-method",
    "id",
    "length",
    "mime-type",
    "name",
    "policy",
    "target-policy",
    "size",
    "version",
)


def _extract_content_headers_meta(headers):
    resp_headers = {"properties": {}}
    for key in headers:
        if key.lower().startswith(CONTENT_HEADER_PREFIX):
            short_key = key[len(CONTENT_HEADER_PREFIX) :]
            # FIXME(FVE): this will fail when someone creates a property with
            # same name as one of our system metadata.
            # content_prepare() and content_get_properties() are safe but
            # content_locate() protocol has to send properties in the body
            # instead of the response headers.
            if short_key.startswith("x-") or short_key not in SYSMETA_KEYS:
                resp_headers["properties"][short_key] = unquote(headers[key])
            else:
                short_key = short_key.replace("-", "_")
                resp_headers[short_key] = unquote(headers[key])
        # Extract other headers which are not content metadata
        # but deserve to be propagated.
        if key.lower() == SHARD_HEXID_HEADER.lower():
            short_key = key[len(HEADER_PREFIX) :].lower().replace("-", "_")
            resp_headers[short_key] = unquote(headers[key])
    chunk_size = headers.get("x-oio-ns-chunk-size")
    if chunk_size:
        resp_headers["chunk_size"] = int(chunk_size)
    return resp_headers


class ContentClient(RawxScoreMixin, ProxyClient):
    def __init__(
        self,
        conf,
        logger=None,
        pool_manager=None,
        refresh_rawx_scores_delay=2.0,
        conscience_client=None,
        **kwargs,
    ):
        super().__init__(
            conf,
            request_prefix="/content",
            logger=logger,
            pool_manager=pool_manager,
            **kwargs,
        )

        _ = kwargs.pop("pool_manager", None)
        self.conscience_client = conscience_client or ConscienceClient(
            self.conf, pool_manager=self.pool_manager, **kwargs
        )
        self.refresh_rawx_scores_delay = refresh_rawx_scores_delay

    def _add_replication_info(self, data, **kwargs):
        """Add replication destinations field to data structure."""
        if data is None:
            data = {}
        dests = kwargs.get("replication_destinations")
        if dests:
            data["replication_destinations"] = dests
        replication_replicator_id = kwargs.get("replication_replicator_id")
        if replication_replicator_id:
            data["replication_replicator_id"] = replication_replicator_id
        replication_role_project_id = kwargs.get("replication_role_project_id")
        if replication_role_project_id:
            data["replication_role_project_id"] = replication_role_project_id
        return data

    def _make_params(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        content=None,
        version=None,
        bypass_governance=None,
        dryrun=None,
        slo_manifest=None,
        params=None,
    ):
        params = {**params} if params else {}
        if cid:
            params["cid"] = cid
        else:
            params["acct"] = account
            params["ref"] = reference
        if path:
            params["path"] = path
        if content:
            params["content"] = content
        if version:
            params["version"] = version
        if bypass_governance:
            params["bypass_governance"] = bypass_governance
        if dryrun:
            params["dryrun"] = dryrun
        if slo_manifest:
            params["slo_manifest"] = slo_manifest
        return params

    @ensure_headers
    def content_create(
        self,
        account=None,
        reference=None,
        path=None,
        size=None,
        checksum=None,
        data=None,
        cid=None,
        content_id=None,
        stgpol=None,
        version=None,
        mime_type=None,
        chunk_method=None,
        headers=None,
        append=False,
        change_policy=False,
        restore_drained=False,
        meta_pos=None,
        force=False,
        params=None,
        **kwargs,
    ):
        """
        Create a new object. This method does not upload any data, it just
        registers object metadata in the database.

        :param size: size of the object
        :type size: `int`
        :param checksum: checksum of the object (may be None when appending)
        :type checksum: hexadecimal `str`
        :param data: metadata of the object (list of chunks and
        dict of properties)
        :type data: `dict`
        :param cid: container id that can be used in place of `account`
            and `reference`
        :type cid: hexadecimal `str`
        :param content_id: the ID to set on the object, or the ID of the
        existing object when appending
        :param stgpol: name of the storage policy for the object
        :param version: version of the object
        :type version: `int`
        :param mime_type: MIME type to set on the object
        :param chunk_method:
        :param headers: extra headers to send to the proxy
        :param append: append to an existing object instead of creating it
        :type append: `bool`
        :param change_policy: change policy of an existing object
        :type change_policy: `bool`
        :param restore_drained: restore a drained object (keeping its metadata)
        :type restore_drained: `bool`
        """
        action = "create"
        params = self._make_params(
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            params=params,
        )
        if append:
            params["append"] = "1"
        if change_policy:
            params["change_policy"] = "1"
        if restore_drained:
            params["restore_drained"] = "1"
        # TODO(FVE): implement 'force' parameter
        if not isinstance(data, dict):
            warnings.simplefilter("once")
            warnings.warn(
                "'data' parameter should be a dict, not a list",
                DeprecationWarning,
                stacklevel=3,
            )
        if meta_pos is not None:
            data = data["chunks"]
            # TODO(FVE): change "id" into "content", and other occurrences
            params["id"] = content_id
            action = "update"

        data = self._add_replication_info(data, **kwargs)
        data = json.dumps(data)

        hdrs = {"x-oio-content-meta-length": str(size)}
        hdrs.update(headers)
        if checksum:
            hdrs["x-oio-content-meta-hash"] = checksum
        if content_id is not None:
            hdrs["x-oio-content-meta-id"] = content_id
        if stgpol is not None:
            hdrs["x-oio-content-meta-policy"] = stgpol
        if version is not None:
            hdrs["x-oio-content-meta-version"] = str(version)
        if mime_type is not None:
            hdrs["x-oio-content-meta-mime-type"] = mime_type
        if chunk_method is not None:
            hdrs["x-oio-content-meta-chunk-method"] = chunk_method

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        resp, body = self._request(
            "POST", action, data=data, params=params, headers=hdrs, **kwargs
        )
        return resp, body

    def content_drain(
        self, account=None, reference=None, path=None, cid=None, version=None, **kwargs
    ):
        params = self._make_params(account, reference, path, cid=cid, version=version)

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        resp, _ = self._request("POST", "drain", params=params, **kwargs)
        return resp.status == 204

    def content_delete(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        version=None,
        bypass_governance=None,
        create_delete_marker=False,
        dryrun=None,
        slo_manifest=None,
        **kwargs,
    ):
        """
        Delete one object.

        :returns: True if a delete marker has been created, False otherwise,
            and the version id which has been deleted or the version id of the
            delete marker which has been created
        :rtype: tuple
        """
        params = self._make_params(
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            version=version,
            bypass_governance=bypass_governance,
            dryrun=dryrun,
            slo_manifest=slo_manifest,
        )
        if create_delete_marker:
            params["delete_marker"] = create_delete_marker
        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        data = self._add_replication_info({}, **kwargs)
        data = json.dumps(data)
        resp, _ = self._request("POST", "delete", params=params, data=data, **kwargs)
        delete_marker = boolean_value(resp.headers.get(DELETEMARKER_HEADER))
        version_id = resp.headers.get(VERSIONID_HEADER)
        return delete_marker, version_id

    def content_delete_many(
        self,
        account=None,
        reference=None,
        paths=None,
        cid=None,
        params=None,
        **kwargs,
    ):
        """
        Delete several objects.

        :param paths: an iterable of object paths (should not be a generator)
        :returns: a list of tuples with the path of the content and
            a boolean telling if the content has been deleted
        :rtype: `list` of `tuple`
        """
        params = self._make_params(
            account=account, reference=reference, cid=cid, params=params
        )
        unformatted_data = []
        for obj in paths:
            if isinstance(obj, tuple):
                unformatted_data.append({"name": obj[0], "version": obj[1]})
            else:
                unformatted_data.append({"name": obj})
        data = json.dumps({"contents": unformatted_data})
        results = []

        for path in paths:
            del_cached_object_metadata(
                account=account, reference=reference, path=path, cid=cid, **kwargs
            )

        try:
            _, resp_body = self._request(
                "POST", "delete_many", data=data, params=params, **kwargs
            )
            for obj in resp_body["contents"]:
                results.append((obj["name"], obj["status"] == 204))
            return results
        except exceptions.TooLarge:
            pivot = len(paths) // 2
            head = paths[:pivot]
            tail = paths[pivot:]
            if head:
                results += self.content_delete_many(
                    account, reference, head, cid=cid, **kwargs
                )
            if tail:
                results += self.content_delete_many(
                    account, reference, tail, cid=cid, **kwargs
                )
            return results

    def content_locate(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        content=None,
        version=None,
        properties=True,
        params=None,
        **kwargs,
    ):
        """
        Get a description of the content along with the list of its chunks.

        :param cid: container id that can be used in place of `account`
            and `reference`
        :type cid: hexadecimal `str`
        :param content: content id that can be used in place of `path`
        :type content: hexadecimal `str`
        :param properties: should the request return object properties
            along with content description
        :type properties: `bool`
        :returns: a tuple with content metadata `dict` as first element
            and chunk `list` as second element
        """
        content_meta, chunks = get_cached_object_metadata(
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            version=version,
            properties=properties,
            params=params,
            **kwargs,
        )
        if content_meta is not None and chunks is not None:
            rawx_scores = self.maybe_refresh_rawx_scores(
                self.conscience_client, **kwargs
            )
            for chunk in chunks:
                # If the rawx is not in the dict, consider it down
                chunk["score"] = rawx_scores.get(chunk["url"].split("/")[2], -1)
            return content_meta, chunks

        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            content=content,
            params=params,
        )
        params["properties"] = properties
        try:
            resp, chunks = self._request(
                "GET", "locate", params=params, retriable=True, **kwargs
            )
            content_meta = _extract_content_headers_meta(resp.headers)
        except exceptions.OioNetworkException as exc:
            # TODO(FVE): this special behavior can be removed when
            # the 'content/locate' protocol is changed to include
            # object properties in the response body instead of headers.
            if properties and "got more than " in str(exc):
                params["properties"] = False
                _resp, chunks = self._request(
                    "GET", "locate", params=params, retriable=True, **kwargs
                )
                content_meta = self.content_get_properties(
                    account,
                    reference,
                    path,
                    cid=cid,
                    content=content,
                    version=version,
                    **kwargs,
                )
            else:
                raise

        set_cached_object_metadata(
            content_meta,
            chunks,
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            version=version,
            properties=properties,
            **kwargs,
        )

        return content_meta, chunks

    def content_prepare(
        self,
        account=None,
        reference=None,
        path=None,
        position=0,
        size=None,
        cid=None,
        stgpol=None,
        content_id=None,
        version=None,
        params=None,
        **kwargs,
    ):
        """
        Prepare an upload: get URLs of chunks on available rawx.

        :param position: position a the metachunk that must be prepared
        :param stgpol: name of the storage policy of the object being uploaded
        :param version: version of the object being uploaded. This is required
            only on the second and later calls to this method to get coherent
            results.
        :keyword autocreate: create container if it doesn't exist
        """
        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            content=content_id,
            params=params,
        )
        data = {"size": size, "position": position}
        if stgpol:
            data["policy"] = stgpol
        data = json.dumps(data)
        try:
            resp, body = self._request(
                "POST", "prepare2", data=data, params=params, **kwargs
            )
            chunks = body["chunks"]
            obj_meta = _extract_content_headers_meta(resp.headers)
            obj_meta["properties"] = body.get("properties", {})
        except exceptions.NotFound:
            # Proxy does not support v2 request (oio < 4.3)
            resp, chunks = self._request(
                "POST", "prepare", data=data, params=params, **kwargs
            )
            obj_meta = _extract_content_headers_meta(resp.headers)
        return obj_meta, chunks

    def content_get_properties(
        self,
        account=None,
        reference=None,
        path=None,
        properties=None,
        cid=None,
        content=None,
        version=None,
        params=None,
        **kwargs,
    ):
        """
        Get a description of the content along with its user properties.
        """
        obj_meta, _ = get_cached_object_metadata(
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            version=version,
            properties=True,
            **kwargs,
        )
        if obj_meta is not None:
            return obj_meta

        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            content=content,
            version=version,
            params=params,
        )
        data = json.dumps(properties) if properties else None
        resp, body = self._request(
            "POST", "get_properties", data=data, params=params, retriable=True, **kwargs
        )
        obj_meta = _extract_content_headers_meta(resp.headers)
        obj_meta.update(body)

        set_cached_object_metadata(
            obj_meta,
            None,
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            version=version,
            properties=True,
            **kwargs,
        )

        return obj_meta

    def content_set_properties(
        self,
        account=None,
        reference=None,
        path=None,
        properties=None,
        cid=None,
        version=None,
        clear=False,
        params=None,
        **kwargs,
    ):
        """
        Set properties on an object.

        :param properties: dictionary of properties
        """
        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            params=params,
        )
        if clear:
            params["flush"] = 1

        if properties is None:
            properties = {}
        data = self._add_replication_info(properties, **kwargs)
        data = json.dumps(data)

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        _resp, _body = self._request(
            "POST", "set_properties", data=data, params=params, **kwargs
        )

    def content_del_properties(
        self,
        account=None,
        reference=None,
        path=None,
        properties=None,
        cid=None,
        version=None,
        params=None,
        **kwargs,
    ):
        """
        Delete some properties from an object.

        :param properties: list of property keys to delete
        :type properties: `list`
        :returns: True is the property has been deleted
        """
        if properties is None:
            properties = []

        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            params=params,
        )
        # Build a list in case the parameter is a view (not serializable).

        data = self._add_replication_info({}, **kwargs)
        if data:
            data["properties"] = [x for x in properties]
        else:
            # legacy proxy call
            data = [x for x in properties]

        data = json.dumps(data)

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        resp, _body = self._request(
            "POST", "del_properties", data=data, params=params, **kwargs
        )
        return resp.status == 204

    def content_touch(
        self, account=None, reference=None, path=None, cid=None, version=None, **kwargs
    ):
        """
        Send an event to update object and object size on container.

        :param account: account
        :param reference: container
        :param cid: container id
        :param path: content path
        :param version: content version
        """
        params = self._make_params(
            account=account, reference=reference, path=path, cid=cid, version=version
        )
        self._request("POST", "touch", params=params, **kwargs)

    def content_spare(
        self,
        account=None,
        reference=None,
        path=None,
        version=None,
        data=None,
        cid=None,
        stgpol=None,
        position=None,
        params=None,
        **kwargs,
    ):
        """
        Get list of spare for content

        :param account: account
        :param reference: container
        :param cid: container id
        :param path: content path
        :param version: content version
        :param stgpol: storage policy
        :param position: content position
        :param data: spare selection hints
        :param params: request params
        """
        if None in (stgpol, position):
            raise ValueError("stgpol and position cannot be None")
        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            params=params,
        )
        params["stgpol"] = stgpol
        params["position"] = position
        data = json.dumps(data)
        _resp, body = self._request(
            "POST", "spare", data=data, params=params, retriable=True, **kwargs
        )
        return body

    def content_truncate(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        version=None,
        size=0,
        params=None,
        **kwargs,
    ):
        """
        Truncate content

        :param account: account
        :param reference: container
        :param cid: container id
        :param path: content path
        :param version: content version
        :param size: Size to truncate
        :param params: request params
        """
        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            version=version,
            params=params,
        )
        params["size"] = size

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        _resp, body = self._request("POST", "truncate", params=params, **kwargs)
        return body

    def content_purge(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        maxvers=None,
        params=None,
        **kwargs,
    ):
        """
        Purge content.

        :param account: account
        :param reference: container
        :param cid: container id
        :param path: content path
        :param maxvers: maximum number of version
        :param params: request params
        """
        params = self._make_params(
            account=account,
            reference=reference,
            cid=cid,
            path=path,
            params=params,
        )
        if maxvers is not None:
            params["maxvers"] = maxvers

        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )

        self._request("POST", "purge", params=params, **kwargs)

    def content_request_transition(
        self,
        account=None,
        reference=None,
        path=None,
        cid=None,
        version=None,
        policy=None,
        **kwargs,
    ):
        """
        Trigger a policy transition for content.

        :param account: account
        :param reference: container
        :param cid: container id
        :param path: content path
        :param version: content version
        :param policy: policy to transition
        """
        params = self._make_params(
            account=account, reference=reference, path=path, cid=cid, version=version
        )
        del_cached_object_metadata(
            account=account, reference=reference, path=path, cid=cid, **kwargs
        )
        self._request(
            "POST",
            "transition",
            params=params,
            json={
                "policy": policy,
                "skip_data_move": kwargs.pop("skip_data_move", False),
                "internal_transition": kwargs.pop("internal_transition", False),
            },
            **kwargs,
        )
