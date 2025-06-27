# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2026 OVH SAS
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

from functools import wraps
import warnings

from oio.common import exceptions
from oio.common.cache import (
    del_cached_container_metadata,
    get_cached_container_metadata,
    set_cached_container_metadata,
)
from oio.common.client import ProxyClient
from oio.content.client import ContentClient
from oio.common.easy_value import boolean_value
from oio.common.json import json


def extract_reference_params(func):
    @wraps(func)
    def _reference_params(
        self, account=None, reference=None, path=None, cid=None, **kwargs
    ):
        params = kwargs.pop("params", dict())
        if cid:
            params["cid"] = cid
        else:
            params["acct"] = account
            params["ref"] = reference
        if path:
            params["path"] = path

        if "content" in kwargs:
            params["content"] = kwargs["content"]
        elif "content_id" in kwargs:
            params["content"] = kwargs["content_id"]

        if "version" in kwargs:
            params["version"] = kwargs["version"]

        return func(
            self,
            account=account,
            reference=reference,
            path=path,
            cid=cid,
            params=params,
            **kwargs,
        )

    return _reference_params


class ContainerClient(ProxyClient):
    """
    Intermediate level class to manage containers.
    """

    def __init__(self, conf, content_client=None, **kwargs):
        super(ContainerClient, self).__init__(
            conf, request_prefix="/container", **kwargs
        )
        self._content_client = content_client

    @property
    def _content(self):
        if not self._content_client:
            self._content_client = ContentClient(
                self.conf, logger=self.logger, pool_manager=self.pool_manager
            )
        return self._content_client

    def _make_uri(self, target):
        """
        Build URIs for request that don't use the same prefix as the one
        set in this class' constructor.
        """
        uri = "%s://%s/v3.0/%s/%s" % (
            self.proxy_scheme,
            self.proxy_netloc,
            self.ns,
            target,
        )
        return uri

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
        **_kwargs,
    ):
        params = {**params} if params else {}
        if cid:
            params["cid"] = cid
        else:
            params["acct"] = account
            params["ref"] = reference
        if path:
            params.update({"path": path})
        if content:
            params.update({"content": content})
        if version:
            params.update({"version": version})
        if bypass_governance:
            params.update({"bypass_governance": bypass_governance})
        if dryrun:
            params.update({"dryrun": dryrun})
        if slo_manifest:
            params.update({"slo_manifest": slo_manifest})
        return params

    def container_create(
        self, account, reference, properties=None, system=None, region=None, **kwargs
    ):
        """
        Create a container.

        :param account: account in which to create the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param properties: properties to set on the container
        :type properties: `dict`
        :param region: ensure the container is created in this region
        :type region: str
        :param system: system properties to set on the container
        :type system: `dict`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: True if the container has been created,
                  False if it already exists
        """
        params = self._make_params(account=account, reference=reference)
        data = json.dumps({"properties": properties or {}, "system": system or {}})
        resp, body = self._request(
            "POST", "/create", params=params, data=data, region=region, **kwargs
        )
        if resp.status not in (204, 201):
            raise exceptions.from_response(resp, body)
        return resp.status == 201

    def container_create_many(
        self, account, containers, properties=None, region=None, **kwargs
    ):
        """
        Create several containers.

        :param account: account in which to create the containers
        :type account: `str`
        :param containers: names of the containers
        :type containers: iterable of `str`
        :param properties: properties to set on the containers
        :type properties: `dict`
        :param region: ensure the containers are created in this region
        :type region: str
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a list of tuples with the name of the container and
            a boolean telling if the container has been created
        :rtype: `list` of `tuple`
        """
        results = list()
        try:
            params = self._make_params(account=account)
            unformatted_data = list()
            for container in containers:
                unformatted_data.append(
                    {
                        "name": container,
                        "properties": properties or {},
                        "system": kwargs.get("system", {}),
                    }
                )
            data = json.dumps({"containers": unformatted_data})
            resp, body = self._request(
                "POST",
                "/create_many",
                params=params,
                data=data,
                region=region,
                **kwargs,
            )
            if resp.status not in (204, 200):
                raise exceptions.from_response(resp, body)
            for container in body["containers"]:
                results.append((container["name"], container["status"] == 201))
            return results
        except exceptions.TooLarge:
            # Batch too large for the proxy
            pivot = len(containers) // 2
            head = containers[:pivot]
            tail = containers[pivot:]
            if head:
                results += self.container_create_many(
                    account, head, properties=properties, region=region, **kwargs
                )
            if tail:
                results += self.container_create_many(
                    account, tail, properties=properties, region=region, **kwargs
                )
            return results

    def container_delete(
        self, account=None, reference=None, cid=None, force=False, **kwargs
    ):
        """
        Delete a container.

        :param account: account from which to delete the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :param force: Force the deletion of the container,
            even if it is not empty
            (only the metadata of the objects will be deleted)
        :type force: `bool`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        params = self._make_params(account=account, reference=reference, cid=cid)
        if force:
            params["force"] = True

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        try:
            self._request("POST", "/destroy", params=params, **kwargs)
        except exceptions.Conflict as exc:
            raise exceptions.ContainerNotEmpty(exc)

    def container_drain(
        self, account=None, reference=None, cid=None, limit=None, **kwargs
    ):
        """
        Drain a container.

        :param account: account from which to drain the container
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :param limit: drain limit for each call from the crawler to the meta2.
        :type limit: `int`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        """
        params = self._make_params(account=account, reference=reference, cid=cid)
        if limit:
            params.update({"limit": limit})

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        resp, body = self._request("POST", "/drain", params=params, **kwargs)

        if resp.status != 204:
            raise exceptions.from_response(resp, body)

        return resp.headers, body

    def container_show(self, account=None, reference=None, cid=None, **kwargs):
        """
        Get information about a container (like user properties).

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" containing a `dict` of
            user properties.
        :deprecated: use `container_get_properties` instead
        """
        params = self._make_params(account=account, reference=reference, cid=cid)
        _resp, body = self._request("GET", "/show", params=params, **kwargs)
        return body

    def container_snapshot(
        self,
        account=None,
        reference=None,
        dst_account=None,
        dst_reference=None,
        cid=None,
        **kwargs,
    ):
        """
        Create a snapshot of a the container.

        This function duplicates only the database. It doesn't duplicate the
        chunks of the contents.

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :param dst_account: account in which the snapshot will be created
        :type dst_account: `str`
        :param dst_reference: name of the snapshot
        :type dst_reference: `str`
        """
        params = self._make_params(account=account, reference=reference, cid=cid)
        data = json.dumps({"account": dst_account, "container": dst_reference})
        resp, _ = self._request("POST", "/snapshot", params=params, data=data, **kwargs)
        return resp

    def container_enable(self, account=None, reference=None, cid=None, **kwargs):
        """
        Change the status of a container database to enable

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        """
        uri = self._make_uri("admin/enable")
        params = self._make_params(account=account, reference=reference, cid=cid)
        params.update({"type": "meta2"})

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        resp, _ = self._direct_request("POST", uri, params=params, **kwargs)
        return resp

    def container_freeze(self, account=None, reference=None, cid=None, **kwargs):
        """
        Freeze the database of a container

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: name of the container
        :param cid: container id that can be used instead of account
            and reference
        """
        uri = self._make_uri("admin/freeze")
        params = self._make_params(account=account, reference=reference, cid=cid)
        params.update({"type": "meta2"})

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        resp, _ = self._direct_request("POST", uri, params=params, **kwargs)
        return resp

    @extract_reference_params
    def container_get_properties(
        self,
        account=None,
        reference=None,
        properties=None,
        cid=None,
        params=None,
        extra_counters=False,
        **kwargs,
    ):
        """
        Get information about a container (user and system properties).

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`
        :keyword headers: extra headers to send to the proxy
        :type headers: `dict`
        :returns: a `dict` with "properties" and "system" entries,
            containing respectively a `dict` of user properties and
            a `dict` of system properties.
        """
        if extra_counters:
            params["extra_counters"] = 1

        container_meta = get_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )
        if container_meta is not None:
            return container_meta

        if not properties:
            properties = list()
        data = json.dumps(properties)
        _resp, container_meta = self._request(
            "POST", "/get_properties", data=data, params=params, **kwargs
        )

        set_cached_container_metadata(
            container_meta, account=account, reference=reference, cid=cid, **kwargs
        )

        return container_meta

    def container_set_properties(
        self,
        account=None,
        reference=None,
        properties=None,
        clear=False,
        cid=None,
        system=None,
        propagate_to_shards=False,
        **kwargs,
    ):
        params = self._make_params(account=account, reference=reference, cid=cid)
        if clear:
            params["flush"] = 1
        if propagate_to_shards:
            params["propagate_to_shards"] = 1
        data = json.dumps({"properties": properties or {}, "system": system or {}})

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        _resp, body = self._request(
            "POST", "/set_properties", data=data, params=params, **kwargs
        )
        return body

    def container_del_properties(
        self, account=None, reference=None, properties=None, cid=None, **kwargs
    ):
        if properties is None:
            properties = []
        params = self._make_params(account=account, reference=reference, cid=cid)
        data = json.dumps(properties)

        del_cached_container_metadata(
            account=account, reference=reference, cid=cid, **kwargs
        )

        _resp, body = self._request(
            "POST", "/del_properties", data=data, params=params, **kwargs
        )
        return body

    def container_touch(
        self, account=None, reference=None, cid=None, recompute=False, **kwargs
    ):
        params = self._make_params(account=account, reference=reference, cid=cid)
        if recompute:
            params["recompute"] = True
        self._request("POST", "/touch", params=params, **kwargs)

    def container_dedup(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account=account, reference=reference, cid=cid)
        self._request("POST", "/dedup", params=params, **kwargs)

    def container_purge(
        self, account=None, reference=None, cid=None, maxvers=None, **kwargs
    ):
        params = self._make_params(account=account, reference=reference, cid=cid)
        if maxvers is not None:
            params["maxvers"] = maxvers
        self._request("POST", "/purge", params=params, **kwargs)

    def container_raw_insert(
        self, bean, account=None, reference=None, cid=None, **kwargs
    ):
        params = self._make_params(
            account=account, reference=reference, cid=cid, **kwargs
        )
        if not isinstance(bean, list):
            bean = (bean,)
        data = json.dumps(bean)
        if kwargs.pop("frozen", None):
            params["frozen"] = 1
        if kwargs.pop("force", None):
            params["force"] = 1
        self._request("POST", "/raw_insert", data=data, params=params, **kwargs)

    def container_raw_update(
        self, old, new, account=None, reference=None, cid=None, **kwargs
    ):
        params = self._make_params(
            account=account, reference=reference, cid=cid, **kwargs
        )
        data = json.dumps({"old": old, "new": new})
        if kwargs.pop("frozen", None):
            params["frozen"] = 1
        self._request("POST", "/raw_update", data=data, params=params, **kwargs)

    def container_raw_delete(
        self, account=None, reference=None, data=None, cid=None, **kwargs
    ):
        """
        Delete raw 'beans' from a container.

        :param data: dictionaries representing the beans to delete. They must
            have a key for each column of the meta2 database, plus a 'type'
            telling which type of bean it is.
        :type data: `list` of `dict` items
        """
        params = self._make_params(
            account=account, reference=reference, cid=cid, **kwargs
        )
        data = json.dumps(data)
        self._request("POST", "/raw_delete", data=data, params=params, **kwargs)

    def container_flush(self, account=None, reference=None, cid=None, **kwargs):
        params = self._make_params(account=account, reference=reference, cid=cid)
        resp, _ = self._request("POST", "/flush", params=params, **kwargs)
        return {"truncated": boolean_value(resp.headers.get("x-oio-truncated"), False)}

    def container_checkpoint(
        self, account=None, reference=None, cid=None, suffix=None, **kwargs
    ):
        """
        Create a checkpoint of a container. This checkpoint can be used for later
        processing.

        This function copies the database and creates a symlink pointing to this copy
        in the checkpoints directory.

        :param account: account in which the container is
        :type account: `str`
        :param reference: name of the container
        :type reference: `str`
        :param cid: container id that can be used instead of account
            and reference
        :type cid: `str`

        """
        params = self._make_params(account=account, reference=reference, cid=cid)
        data = {}
        if suffix:
            data["suffix"] = suffix
        data = json.dumps(data)
        resp, _ = self._request(
            "POST", "/checkpoint", params=params, data=data, **kwargs
        )

        return resp

    def content_list(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Container.container_list_content
        """
        self._deprecated_warning(
            "Container.content_list", "Content.container_list_content"
        )
        return self.container_list_content(*args, **kwargs)

    @extract_reference_params
    def container_list_content(
        self,
        account=None,
        reference=None,
        limit=None,
        marker=None,
        version_marker=None,
        end_marker=None,
        prefix=None,
        delimiter=None,
        properties=False,
        cid=None,
        versions=False,
        deleted=False,
        params=None,
        chunks=False,
        mpu_marker_only=False,
        version=None,
        **kwargs,
    ):
        """
        Get the list of contents of a container.

        :returns: a tuple with container metadata `dict` as first element
            and a `dict` with "object" and "prefixes" as second element
        """
        p_up = {
            "max": limit,
            "marker": marker,
            "end_marker": end_marker,
            "prefix": prefix,
            "delimiter": delimiter,
            "properties": properties,
            "chunks": chunks,
            "version": version,
        }
        params.update(p_up)
        # As of 4.0.0.a3, to make it false, the 'all' parameter must be absent
        if versions:
            params["all"] = "1"
            if marker and version_marker:
                params["version_marker"] = version_marker
        if deleted:
            params["deleted"] = 1
        if kwargs.get("local"):
            params["local"] = 1
        if mpu_marker_only:
            params["mpu_marker_only"] = 1
        resp, body = self._request("GET", "/list", params=params, **kwargs)
        return resp.headers, body

    def _deprecated_warning(self, old_func, new_func):
        warnings.simplefilter("once")
        warnings.warn(
            f"'{old_func}' function is deprecated. Prefer '{new_func}'",
            DeprecationWarning,
            stacklevel=3,
        )

    def content_create(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_create
        """
        self._deprecated_warning("Container.content_create", "Content.content_create")
        return self._content.content_create(*args, **kwargs)

    def content_drain(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_drain
        """
        self._deprecated_warning("Container.content_drain", "Content.content_drain")
        return self._content.content_drain(*args, **kwargs)

    def content_delete(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_delete
        """
        self._deprecated_warning("Container.content_delete", "Content.content_delete")
        return self._content.content_delete(*args, **kwargs)

    def content_delete_many(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_delete_many
        """
        self._deprecated_warning(
            "Container.content_delete_many", "Content.content_delete_many"
        )
        return self._content.content_delete_many(*args, **kwargs)

    def content_locate(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_locate
        """
        self._deprecated_warning("Container.content_locate", "Content.content_locate")
        return self._content.content_locate(*args, **kwargs)

    def content_prepare(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_prepare
        """
        self._deprecated_warning("Container.content_prepare", "Content.content_prepare")
        return self._content.content_prepare(*args, **kwargs)

    def content_get_properties(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_get_properties
        """
        self._deprecated_warning(
            "Container.content_get_properties", "Content.content_get_properties"
        )
        return self._content.content_get_properties(*args, **kwargs)

    def content_set_properties(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_set_properties
        """
        self._deprecated_warning(
            "Container.content_set_properties", "Content.content_set_properties"
        )
        return self._content.content_set_properties(*args, **kwargs)

    def content_del_properties(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_del_properties
        """
        self._deprecated_warning(
            "Container.content_del_properties", "Content.content_del_properties"
        )
        return self._content.content_del_properties(*args, **kwargs)

    def content_touch(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_touch
        """
        self._deprecated_warning("Container.content_touch", "Content.content_touch")
        return self._content.content_touch(*args, **kwargs)

    def content_spare(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_spare
        """
        self._deprecated_warning("Container.content_spare", "Content.content_spare")
        return self._content.content_spare(*args, **kwargs)

    def content_truncate(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_truncate
        """
        self._deprecated_warning(
            "Container.content_truncate", "Content.content_truncate"
        )
        return self._content.content_truncate(*args, **kwargs)

    def content_purge(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_purge
        """
        self._deprecated_warning("Container.content_purge", "Content.content_purge")
        return self._content.content_purge(*args, **kwargs)

    def content_request_transition(self, *args, **kwargs):
        """
        This method is depecrated. Prefer Content.content_request_transition
        """
        self._deprecated_warning(
            "Container.content_request_transition", "Content.content_request_transition"
        )
        return self._content.content_request_transition(*args, **kwargs)
