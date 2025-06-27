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

import time
from collections import Counter, namedtuple
from os.path import join
from urllib.parse import urlparse

from oio.common import exceptions as exc
from oio.common.easy_value import int_value
from oio.common.logger import get_logger
from oio.common.utils import get_nb_chunks, is_chunk_id_valid, service_pool_to_dict
from oio.content.content import ChunksHelper
from oio.content.factory import ContentFactory
from oio.content.quality import NB_LOCATION_LEVELS, count_local_items, format_location

RawxService = namedtuple("RawxService", ("status", "last_time"))

ORPHANS_DIR = "orphans"


class Filter(object):
    NAME: str | None = None

    def __init__(self, app, conf, logger=None):
        self.app = app
        self.app_env = app.app_env
        self.conf = conf
        self.logger = logger or self.app_env.get("logger") or get_logger(conf)
        self.stop_requested = self.app_env.get("stop_requested")
        self.init()

    def init(self):
        pass

    def process(self, env, cb):
        return self.app(env, cb)

    def __call__(self, env, cb):
        return self.process(env, cb)

    def _get_filter_stats(self):
        return {}

    def _reset_filter_stats(self):
        return

    def get_stats(self):
        stats = self.app.get_stats()
        filter_stats = self._get_filter_stats()
        if filter_stats:
            stats[self.NAME] = filter_stats
        return stats

    def reset_stats(self):
        self.app.reset_stats()
        self._reset_filter_stats()

    def _open_resources(self):
        return

    def open_resources(self):
        self.app.open_resources()
        self._open_resources()

    def _close_resources(self):
        return

    def close_resources(self):
        self.app.close_resources()
        self._close_resources()


class ChunkSymlinkFilter(Filter):
    NEW_ATTEMPT_DELAY = 900
    SERVICE_UPDATE_INTERVAL = 3600
    NON_OPTIMAL_DIR = "non_optimal_placement"

    def __init__(self, app, conf, logger=None):
        super().__init__(app, conf, logger)
        self.new_attempt_delay = int_value(
            self.conf.get("new_attempt_delay"), self.NEW_ATTEMPT_DELAY
        )

        # Interval of time in sec after which the services are updated
        self.service_update_interval = int_value(
            self.conf.get("service_update_interval"), self.SERVICE_UPDATE_INTERVAL
        )
        self.last_services_update = 0.0
        # Path of the volume in which the chunk is located
        self.volume_path = self.app_env["volume_path"]
        self.volume_id = self.app_env["volume_id"]
        self.working_dir = self.app_env["working_dir"]
        self.api = self.app_env["api"]
        self.conscience_client = self.api.conscience
        # Get content object
        self.content_factory = ContentFactory(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"]
        )
        self.rawx_srv_data = None
        self.rawx_srv_locations = {}
        self.policy_data = {}

    def _check_chunk_location(self, chunk, reqid, force_master=False):
        """
        Verify if chunk exists and returns all the chunks belonging
        to the same object.

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        :param reqid: request id
        :type reqid: str
        :param force_master: force the request to the master if True
        :type force_master: bool
        :raises exc.OrphanChunk: raised in case a orphan chunk is found
        """
        # Get all object chunks location
        _, chunks = self.api.content.content_locate(
            content=chunk.meta["content_id"],
            cid=chunk.meta["container_id"],
            path=chunk.meta["content_path"],
            version=chunk.meta["content_version"],
            reqid=reqid,
            force_master=force_master,
        )
        chunkshelper = ChunksHelper(chunks).filter(
            id=chunk.chunk_id, host=self.volume_id
        )
        # Check if object chunks exist
        if len(chunkshelper.chunks) == 0:
            raise exc.OrphanChunk("Chunk not found in content")
        if "." in chunks[0]["pos"]:
            return sorted(
                chunks,
                key=lambda d: (
                    int(d["pos"].split(".")[0]),
                    int(d["pos"].split(".")[1]),
                ),
            )
        return sorted(chunks, key=lambda d: int(d["pos"]))

    def _get_misplaced_chunks(self, chunks, policy, content_id):
        """
        Return the misplaced chunks ids among the list of chunks passed in
        the parameters.

        :param chunks: list of object chunks
        :type chunks: list
        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        :return: list of misplaced chunks ids
        :rtype: list
        """
        misplaced_chunks_ids = []
        counters = {}
        try:
            # Constraint defined for all the chunks object
            fair_location_constraint = self.policy_data[policy][2]
        except KeyError:
            self.logger.warning(
                "Policy %s has no fair location constraint defined, \
                    cannot get misplaced chunks for the content %s",
                policy,
                content_id,
            )
            return misplaced_chunks_ids
        for chunk_data in chunks:
            rawx_srv_id = urlparse(chunk_data["url"]).netloc
            chunk_id = chunk_data["url"].split("/", 3)[3]
            # Location of the chunk selected rawx
            location = format_location(self.rawx_srv_locations[rawx_srv_id])
            for depth in range(NB_LOCATION_LEVELS):
                # Create a counter for each depth
                depth_counter = counters.setdefault(depth, Counter())
                subloc = location[: depth + 1]
                depth_counter[subloc] += 1
                if depth_counter[subloc] > fair_location_constraint[depth]:
                    misplaced_chunks_ids.append(chunk_id)
        return misplaced_chunks_ids

    def _get_new_symlink_path(self, chunk_id, path, is_symlink_new_format, now):
        """
        Return new symlink file path after changing in the file name the number of
        attempt and the timestamp representing the next time we will try to
        apply filter.

        :param chunk_id: id of the chunk
        :type chunk_id: str
        :param path: path of the symlink path
        :type path: str
        :param is_symlink_new_format: True if symlink name has new
            format and False if not
        :type is_symlink_new_format: bool
        :param now: now time
        :type now: timestamp
        :return: new symlink file path
        :rtype: str
        """
        # Check if the symlink name file is in
        # chunkid.nb_attempt.timestamp format
        # TODO (FIR) remove this verification as of now the symlink
        # created will always be on this format. This verification
        # was set up to be compatible with symlinks created prior
        # this change.
        if is_symlink_new_format:
            attempt_counter = int(path.rsplit(".", 2)[1]) + 1
            next_attempt_time = int(path.rsplit(".", 2)[2])
        else:
            attempt_counter = 1
        # Define the next time we will be allowed to apply filter on the chunk
        seconds = self.get_timedelta(attempt_counter, delay=self.new_attempt_delay)
        next_attempt_time = str(int(now + seconds))
        new_symlink_name = ".".join(
            [
                chunk_id,
                str(attempt_counter),
                next_attempt_time,
            ]
        )
        new_symlink_path = join(path.rsplit("/", 1)[0], new_symlink_name)
        return new_symlink_path

    def _get_current_items(self, chunk, chunks, reqid):
        """Calculate current items on the host of the chunk having symlink

        :param chunk: chunk representation.
        :type chunk: ChunkWrapper
        :param chunks: list of chunks of an object
        :type chunks: list of dict
        :param reqid: request id
        :type reqid: str
        :return: the current items on the host, e.g: 12.12.4.1
        :rtype: str
        """
        now = time.time()
        if self.rawx_srv_data is None or (
            (now - self.last_services_update) >= self.service_update_interval
        ):
            self.rawx_srv_data = self.conscience_client.all_services(
                service_type="rawx",
                reqid=reqid,
            )
            for data in self.rawx_srv_data:
                # Fetch location of each rawx service
                loc = tuple(data["tags"]["tag.loc"].split("."))
                # Here data["id"] represents the rawx service id
                self.rawx_srv_locations[data["id"]] = loc
            cluster_info = self.conscience_client.info()
            for policy in cluster_info["storage_policy"]:
                # Fetch constraints of each rawx service
                service_pool, data_security = cluster_info["storage_policy"][
                    policy
                ].split(":")
                if service_pool not in cluster_info["service_pools"]:
                    continue
                pool = cluster_info["service_pools"][service_pool]
                pool_dict = service_pool_to_dict(pool)
                if "fair_location_constraint" not in pool_dict:
                    continue
                try:
                    # pool = 9,rawx;fair_location_constraint=9.9.2.1;
                    # strict_location_constraint=9.9.2.1;
                    # min_dist=1;warn_dist=0
                    service_pool_constraints = pool_dict[
                        "fair_location_constraint"
                    ].split(".")
                    data_security = cluster_info["data_security"][data_security]
                    # Fetch expected chunks for a policy with a specific data security
                    expected_nb_chunks = get_nb_chunks(data_security)
                    storage_constraints = [int(x) for x in service_pool_constraints]
                    self.policy_data[policy] = (
                        expected_nb_chunks,
                        data_security,
                        storage_constraints,
                    )
                except Exception:
                    self.logger.exception("Failed to fetch %s policy data", policy)
                    continue
            self.last_services_update = now
        return count_local_items(
            chunk, None, chunks, self.rawx_srv_locations, self.logger
        )

    @staticmethod
    def get_timedelta(nb_attempt, delay=NEW_ATTEMPT_DELAY):
        """
        Return time to wait before another apply filter attempt

        :param nb_attempt: number of attempt
        :type nb_attempt: int
        :return: time in second
        :rtype: int
        """
        # first attempt -> 15 min
        # second attempt -> 30 min
        # third attempt -> 1h
        # fourth attempt -> 2h
        # fifth attempt -> 2h
        # sixth attempt -> 2h ...
        res = 2 ** (nb_attempt - 1)
        times = min(res, 8)
        return delay * times

    @staticmethod
    def has_new_format(path):
        """
        Verify if the symlink path has the new format
        chunk_id.nb_attempt.timestamp

        :param path: symlink
        :type path: str
        :return: True if it has the new format and False if not
        :rtype: boolean
        """
        res = path.rsplit("/", 1)[1].split(".")
        chunk_id = res[0]
        return len(res) == 3 and is_chunk_id_valid(chunk_id)


class RawxUpMixin:
    """Mixin class providing _check_rawx_up"""

    def _check_rawx_up(self):
        now = time.time()
        status, last_time = self._rawx_service
        # If the conscience has been requested in the last X seconds, return
        if now < last_time + self.conscience_cache:
            return status

        status = True
        try:
            data = self.conscience_client.all_services("rawx")
            # Check that all rawx are UP
            # If one is down, the chunk may be still rebuildable in the future
            for srv in data:
                tags = srv["tags"]
                addr = srv["addr"]
                up = tags.pop("tag.up", "n/a")
                if not up:
                    self.logger.debug(
                        "service %s is down, rebuild may not be possible", addr
                    )
                    status = False
                    break
        except exc.OioException:
            status = False

        self._rawx_service = RawxService(status, now)
        return status
