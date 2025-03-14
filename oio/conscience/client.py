# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2024 OVH SAS
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


from urllib.parse import urlparse, urlunparse

from oio.common.client import ProxyClient
from oio.common.exceptions import OioException
from oio.common.green import time
from oio.common.json import json
from oio.content.quality import get_distance


class LbClient(ProxyClient):
    """Simple load balancer client"""

    def __init__(self, conf, **kwargs):
        super().__init__(conf, request_prefix="/lb", **kwargs)

    def next_instances(self, pool, size=None, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        """
        params = {"type": pool}
        if size is not None:
            params["size"] = size
        resp, body = self._request("GET", "/choose", params=params, **kwargs)
        if resp.status == 200:
            return body
        raise OioException(f"ERROR while getting next instances from pool {pool}")

    def next_instance(self, pool, **kwargs):
        """Get the next service instance from the specified pool"""
        kwargs.pop("size", None)
        return self.next_instances(pool, size=1, **kwargs)[0]

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        params = {"pool": pool}
        resp, obody = self._request(
            "POST", "/poll", params=params, data=json.dumps(kwargs)
        )
        if resp.status == 200:
            return obody
        raise OioException(f"Failed to poll {pool}: {resp.text}")

    def create_pool(self, pool, targets, force=False, options=None, **kwargs):
        """
        Create a service pool on the local proxy.

        :param pool: a name for the pool
        :type pool: `str`
        :param targets: a list of tuples like (1, "rawx-usa", "rawx", ...)
        :param force: if the pool already exists, overwrite it
        :param options: options for the pool
        :type options: `dict`
        :exception Conflict: if a pool with same name already exists
        """
        stargets = ";".join(",".join(str(y) for y in x) for x in targets)
        ibody = {"targets": stargets, "options": options}
        _, _ = self._request(
            "POST",
            "/create_pool",
            params={"name": pool, "force": str(force)},
            data=json.dumps(ibody),
            **kwargs,
        )


class ConscienceClient(ProxyClient):
    """Conscience client. Some calls are actually redirected to LbClient."""

    def __init__(self, conf, service_id_max_age=60, **kwargs):
        super().__init__(conf, request_prefix="/conscience", **kwargs)
        self._lb_kwargs = dict(kwargs)
        self._lb_kwargs.pop("pool_manager", None)
        self._lb = None
        self._service_id_max_age = service_id_max_age
        self._service_ids = {}

    def _request(self, method, url, **kwargs):
        params = kwargs.setdefault("params", {})
        # Forward the request to this particular Conscience, do not use cache
        cs_addr = kwargs.get("cs")
        if cs_addr:
            params["cs"] = cs_addr
        return super()._request(method, url, **kwargs)

    @property
    def lb(self):
        """Get an instance of LbClient."""
        if self._lb is None:
            self._lb = LbClient(
                self.conf, pool_manager=self.pool_manager, **self._lb_kwargs
            )
        return self._lb

    def next_instances(self, pool, **kwargs):
        """
        Get the next service instances from the specified pool.

        :keyword size: number of services to get
        :type size: `int`
        :keyword slot: comma-separated list of slots to poll
        :type slot: `str`
        """
        return self.lb.next_instance(pool, **kwargs)

    def next_instance(self, pool, **kwargs):
        """Get the next service instance from the specified pool"""
        return self.lb.next_instance(pool, **kwargs)

    def poll(self, pool, **kwargs):
        """
        Get a set of services from a predefined pool.

        :keyword avoid: service IDs that must be avoided
        :type avoid: `list`
        :keyword known: service IDs that are already known
        :type known: `list`
        """
        return self.lb.poll(pool, **kwargs)

    def all_services(
        self, service_type, full=False, cs=None, requester_location=None, **kwargs
    ):
        """
        Get the list of all services of a specific type.

        :param service_type: the type of services to get (ex: 'rawx')
        :type service_type: `str`
        :param full: whether to get all metrics for each service
        :param cs: conscience address to request
        :param requester_location: location string used to compute a distance
            to each listed service. If None, do not compute distance.
        :returns: the list of all services of the specified type.
        :rtype: `list` of `dict` objects, each containing at least
            - 'addr' (`str`),
            - 'id' (`str`),
            - 'score' (`int`),
            - 'tags' (`dict`).
        """
        params = {"type": service_type}
        if full:
            params["full"] = "1"
        if cs:
            params["cs"] = cs
        resp, body = self._request("GET", "/list", params=params, **kwargs)
        if resp.status != 200:
            raise OioException(
                f"failed to get list of {service_type} services: {resp.text}"
            )
        # TODO(FVE): do that in the proxy
        for srv in body:
            if "id" not in srv:
                srv_id = srv["tags"].get("tag.service_id", srv["addr"])
                srv["id"] = srv_id
        if requester_location:
            for srv in body:
                srv_loc = srv["tags"].get("tag.loc", "nowhere.1.2.3")
                srv["distance"] = get_distance(requester_location, srv_loc)
        return body

    def all_services_by_id(self, service_type, **kwargs):
        """
        Same as all_services, but the output is a dictionary with service IDs as keys.
        """
        all_services = self.all_services(service_type=service_type, **kwargs)
        return {s["id"]: s for s in all_services}

    def local_services(self):
        url = self.endpoint.replace("conscience", "local/list")
        resp, body = self._direct_request("GET", url)
        if resp.status == 200:
            return body
        raise OioException(f"failed to get list of local services: {resp.text}")

    def service_types(self, **kwargs):
        """
        Get the list of service types known by Conscience.
        """
        params = {"what": "types"}
        resp, body = self._request("GET", "/info", params=params, **kwargs)
        if resp.status == 200:
            return body
        raise OioException(f"ERROR while getting services types: {resp.text}")

    def get_service_definition(
        self, srv_type, srv_id, score=None, scores=None, tags=None
    ):
        service_definition = {
            "ns": self.ns,
            "type": srv_type,
            "addr": srv_id,
        }
        if score is not None:
            service_definition["score"] = score
        if scores is not None:
            service_definition["scores"] = scores
        if tags is not None:
            service_definition["tags"] = tags
        return service_definition

    def register(self, service_definitions, **kwargs):
        data = json.dumps(service_definitions)
        resp, body = self._request("POST", "/register", data=data, **kwargs)

    def deregister(self, service_definitions, **kwargs):
        data = json.dumps(service_definitions)
        resp, body = self._request("POST", "/deregister", data=data, **kwargs)

    def info(self):
        resp, body = self._request("GET", "/info")
        return body

    def lock_score(self, srv_or_list, **kwargs):
        """
        Lock the score of a service.

        :param srv_or_list: dictionary containing:
            - 'addr': the service address,
            - 'type': the service type,
            - 'score': optional, the score to set the service to.
        :type srv_or_list: `dict` or list of `dict`.
        """
        _, body = self._request("POST", "/lock", data=json.dumps(srv_or_list), **kwargs)
        return body

    def unlock_score(self, srv_or_list, **kwargs):
        """
        Unlock the score of a service, let the Conscience compute it.

        :param srv_or_list: dictionary containing:
            - 'addr': the service address,
            - 'type': the service type,
        :type srv_or_list: `dict` or list of `dict`.
        """
        self._request("POST", "/unlock", data=json.dumps(srv_or_list), **kwargs)

    def flush(self, srv_type):
        resp, body = self._request("POST", "/flush", params={"type": srv_type})

    def resolve(self, srv_type, service_id, **kwargs):
        resp, body = self._request(
            "GET",
            "/resolve",
            params={"type": srv_type, "service_id": service_id},
            **kwargs,
        )
        if resp.status == 200:
            return body
        raise OioException(f"failed to resolve service id {service_id}: {resp.text}")

    def resolve_service_id(
        self,
        service_type,
        service_id,
        check_format=True,
        end_user_request=False,
        **kwargs,
    ):
        """
        :returns: Service address corresponding to the service ID
        """
        if check_format:
            url = "http://" + service_id
            parsed = urlparse(url)
            if parsed.port is not None:
                return service_id

        cached_service_id = self._service_ids.get(service_id)
        if cached_service_id and (
            time.time() - cached_service_id["mtime"] < self._service_id_max_age
        ):
            if end_user_request:
                return cached_service_id["addr"]
            # Prefer internal service and fallback to main service.
            # The internal service won't be discovered until the cache expiration. This
            # should prevent any extra pressure on conscience service if internal
            # service is missing.
            return cached_service_id.get("internal_addr", cached_service_id["addr"])

        kwargs["end_user_request"] = end_user_request
        result = self.resolve(
            srv_type=service_type,
            service_id=service_id,
            **kwargs,
        )
        service_addr = result["addr"]
        self._service_ids[service_id] = {"addr": service_addr, "mtime": time.time()}
        # If there is an internal address (in case of rawx)
        if "internal_addr" in result:
            # Cache also the internal service address
            self._service_ids[service_id].update(
                {"internal_addr": result["internal_addr"]}
            )
            if not end_user_request:
                service_addr = result["internal_addr"]
        return service_addr

    def resolve_url(self, service_type, url, **kwargs):
        """
        :returns: Resolved URL of a service using a service ID
        """
        # FIXME(mb): some tests don't put scheme, should fix tests
        if not url.startswith("http://"):
            url = "http://" + url

        parsed = urlparse(url)
        if parsed.port is not None:
            return url

        service_addr = self.resolve_service_id(
            service_type, parsed.hostname, check_format=False, **kwargs
        )
        return urlunparse(
            (
                parsed.scheme,
                service_addr,
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
