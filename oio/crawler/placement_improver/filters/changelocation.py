# Copyright (C) 2022-2023 OVH SAS
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
from os import unlink, rename
from os.path import join
import re
import time
from urllib.parse import urlparse
from collections import Counter
from oio.common.constants import CHUNK_HEADERS
from oio.common.easy_value import int_value
from oio.common.green import get_watchdog
from oio.content.content import ChunksHelper
from oio.content.factory import ContentFactory
from oio.content.quality import NB_LOCATION_LEVELS, format_location, get_current_items
from oio.crawler.common.base import Filter
from oio.common.utils import get_nb_chunks, is_chunk_id_valid, request_id
from oio.crawler.rawx.chunk_wrapper import (
    ChunkWrapper,
    PlacementImproverCrawlerError,
    PlacementImproverCrawlerChunkNotFound,
)
from oio.common import exceptions as exc


class Changelocation(Filter):
    """
    Initialize the filter used to relocate misplaced chunks
    """

    NAME = "Changelocation"
    NEW_ATTEMPT_DELAY = 900
    SERVICE_UPDATE_INTERVAL = 3600

    def init(self):
        """
        Initialize Changelocation filter
        """
        # Count of the number of chunks relocated to respect placement constraints
        self.successes = 0
        # Count of the number of chunks relocated to respect placement constraints
        self.relocated_chunks = 0
        # Count the error encountered during chunk relocation
        self.errors = 0
        # Count of the number non optimal placement symlinks created
        self.created_symlinks = 0
        # Count the number of failed post to create non optimal placement symlinks
        self.failed_post = 0
        # Count of the number of irrelevant non optimal placement symlinks removed
        self.removed_symlinks = 0
        # Count orphans chunks found
        self.orphan_chunks_found = 0
        self.waiting_new_attempt = 0
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
        watchdog = get_watchdog(called_from_main_application=True)
        # Getting Content object
        self.content_factory = ContentFactory(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        self.rawx_srv_data = None
        self.rawx_srv_locations = {}
        self.policy_data = {}

    def _check_chunk_location(self, chunk, reqid):
        """
        Verify if the misplaced chunk exists

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        :param reqid: request id
        :type reqid: str
        :raises exc.OrphanChunk: raised in case a orphan chunk is found
        """
        # Getting all the chunks location of the object
        _, chunks = self.api.container.content_locate(
            content=chunk.meta["content_id"],
            cid=chunk.meta["container_id"],
            path=chunk.meta["content_path"],
            version=chunk.meta["content_version"],
            reqid=reqid,
        )
        chunkshelper = ChunksHelper(chunks).filter(
            id=chunk.chunk_id, host=self.volume_id
        )
        # Checking if the chunk object exists
        if len(chunkshelper.chunks) == 0:
            raise exc.OrphanChunk("Chunk not found in content")
        return chunks

    def _move_chunk(self, chunkwrapper, content, reqid, cur_items=None):
        """
        Move the misplaced chunk to a better placement

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        :param content: content object
        :type content: Content
        :param reqid: request id
        :type reqid: str
        :return: dict with metadata of the new chunk created
        :rtype: dict
        """
        chunk_id = chunkwrapper.chunk_id
        rawx_dict = content.move_chunk(
            chunk_id=chunk_id,
            service_id=self.volume_id,
            check_quality=True,
            reqid=reqid,
            cur_items=cur_items,
        )
        self.logger.debug("Chunk %s moved to %s", chunk_id, rawx_dict["url"])
        # Incrementing the counter of chunks relocated
        self.relocated_chunks += 1

    def _get_current_items(self, chunk, chunks, reqid):
        """Calculate current items on the host of the chunk tagged as misplaced

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
                if "fair_location_constraint" not in pool:
                    continue
                try:
                    # pool = 9,rawx;fair_location_constraint=9.9.2.1;
                    # strict_location_constraint=9.9.2.1;
                    # min_dist=1;warn_dist=0
                    constraint_service_pool = (
                        re.findall(
                            r"fair_location_constraint=\d+\.\d+\.\d+\.\d+",
                            pool,
                        )[0]
                        .split("=")[1]
                        .split(".")
                    )
                    data_security = cluster_info["data_security"][data_security]
                    # Fetch expected chunks for a policy with a specific data security
                    expected_nb_chunks = get_nb_chunks(data_security)
                    storage_constraints = list(map(int, constraint_service_pool))
                    self.policy_data[policy] = (
                        expected_nb_chunks,
                        data_security,
                        storage_constraints,
                    )
                except Exception:
                    self.logger.exception("Failed to fetch data %s policy", policy)
                    continue
            self.last_services_update = now
        return get_current_items(
            chunk, None, chunks, self.rawx_srv_locations, self.logger
        )

    def _get_misplaced_chunks(self, chunks, policy, content_id):
        """
        Return the misplaced chunks ids among the list of chunks passed in
        the parameters.

        :param chunks: list of object chunks
        :type chunks: list
        :param account: accout name
        :type account: str
        :param container: container name
        :type container: str
        :return: list of misplaced chunks ids
        :rtype: list
        """
        misplaced_chunks_ids = list()
        counters = {}
        try:
            # Constraint defined for all the chunks object
            fair_location_constraint = self.policy_data[policy][2]
        except KeyError:
            #
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
            # Location of the rawx of the chunk selected
            location = format_location(self.rawx_srv_locations[rawx_srv_id])
            for depth in range(NB_LOCATION_LEVELS):
                # Create a counter for each depth
                depth_counter = counters.setdefault(depth, Counter())
                subloc = location[: depth + 1]
                depth_counter[subloc] += 1
                if depth_counter[subloc] > fair_location_constraint[depth]:
                    misplaced_chunks_ids.append(chunk_id)
        return misplaced_chunks_ids

    def _tag_misplaced_chunk(self, url, headers):
        """
        Tag misplaced chunk by adding a header to the chunk

        :param url: url of the misplaced chunk
        :type url: str
        :param headers: headers to add to the chunk
        :type headers: dict
        """
        try:
            self.api.blob_client.chunk_post(url=url, headers=headers)
            self.created_symlinks += 1
        except exc.Conflict as err:
            # Misplaced tag already on the chunk
            # and the symlink already created
            self.logger.debug(
                "Header misplaced chunk already added on %s: %s",
                url,
                str(err),
            )
        except Exception as err:
            self.logger.debug(
                "Tag chunk %s as misplaced failed due to: %s",
                url,
                str(err),
            )
            self.failed_post += 1

    def _post_process(self, chunkwrapper):
        """
        Launch post process event: delete symbolic link

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        """
        try:
            # unlinking the symbolic link
            symb_link_path = chunkwrapper.chunk_symlink_path
            unlink(symb_link_path)
            # Incrementing the counter of process which succeeded
            self.successes += 1
        except Exception as chunk_exc:
            self.logger.warning(
                "Delete the symbolic link %s failed due to: %s",
                symb_link_path,
                str(chunk_exc),
            )

    def process(self, env, cb):
        """
        Change location of a misplaced chunk

        :param env: used to create chunk representation
        :type env: dict
        :param cb: callback function
        :type cb: function
        """
        chunkwrapper = ChunkWrapper(env)
        # Getting a request id for chunk placement improvement
        reqid = request_id("placementImprover-")
        chunk_id = chunkwrapper.chunk_id
        try:
            now = time.time()
            path = chunkwrapper.chunk_symlink_path
            is_symlink_new_format = self.has_new_format(path)
            # Check if the symlink name file is in chunkid.nb_attempt.timestamp format
            if is_symlink_new_format:
                next_try_time = int(chunkwrapper.chunk_symlink_path.rsplit(".", 1)[1])
                if next_try_time > now:
                    # An attempt has already failed
                    # a timeout has been set until the next attempt to move the chunk
                    self.waiting_new_attempt += 1
                    return self.app(env, cb)
            chunks = self._check_chunk_location(chunkwrapper, reqid)
            cur_items = self._get_current_items(chunkwrapper, chunks, reqid)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, (exc.OrphanChunk, exc.NotFound)):
                self.logger.warning("Orphan chunk %s: %s", chunk_id, str(chunk_exc))
                self.orphan_chunks_found += 1
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
                # Define the next time we will be allowed to move the misplaced chunk
                seconds = self.get_timedelta(
                    attempt_counter, delay=self.new_attempt_delay
                )
                next_attempt_time = str(int(now + seconds))
                new_symlink_name = ".".join(
                    [
                        chunk_id,
                        str(attempt_counter),
                        next_attempt_time,
                    ]
                )
                new_symlink_path = join(path.rsplit("/", 1)[0], new_symlink_name)
                rename(chunkwrapper.chunk_symlink_path, new_symlink_path)
            else:
                self.errors += 1
            resp = PlacementImproverCrawlerChunkNotFound(
                chunk=chunkwrapper,
                body=(
                    f"Error while looking for chunks location: {chunk_exc} "
                    f"reqid={reqid}, chunk_id={chunk_id}"
                ),
            )
            return resp(env, cb)
        try:
            # Getting Content object
            content = self.content_factory.get_by_path_and_version(
                container_id=chunkwrapper.meta["container_id"],
                content_id=chunkwrapper.meta["content_id"],
                path=chunkwrapper.meta["content_path"],
                version=chunkwrapper.meta["content_version"],
                reqid=reqid,
            )
            self._move_chunk(chunkwrapper, content, reqid, cur_items=cur_items)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, exc.SpareChunkException):
                # Check if symlink found is actually a misplaced chunk
                misplaced_chunks_ids = self._get_misplaced_chunks(
                    chunks, policy=content.policy, content_id=content.content_id
                )
                if chunk_id not in misplaced_chunks_ids:
                    # Remove symlink
                    symb_link_path = chunkwrapper.chunk_symlink_path
                    unlink(symb_link_path)
                    self.removed_symlinks += 1
                    self.logger.warning(
                        "Chunk %s is well placed, its symlink has been deleted",
                        chunk_id,
                    )
                headers = {CHUNK_HEADERS["non_optimal_placement"]: True}
                chunks_url = {
                    chunk["url"].split("/", 3)[3]: chunk["url"] for chunk in chunks
                }
                for c_id in misplaced_chunks_ids:
                    # Tag the chunks as misplaced
                    self._tag_misplaced_chunk(chunks_url[c_id], headers)
                return self.app(env, cb)
            self.errors += 1
            resp = PlacementImproverCrawlerError(
                chunk=chunkwrapper,
                body="Error while moving the chunk {0}: {1}".format(
                    chunk_id, str(chunk_exc)
                ),
            )
            return resp(env, cb)
        # Deleting the symbolic link refering the chunk as misplaced
        # This action is called only when the chunks has been moved
        self._post_process(chunkwrapper)
        return self.app(env, cb)

    @staticmethod
    def get_timedelta(nb_attempt, delay=NEW_ATTEMPT_DELAY):
        """
        Return time to wait before another improver attempt

        :param nb_attempt: number of attempt by placement Improver
        :type nb_attempt: int
        :return: time in second
        :rtype: int
        """
        # first attemp -> 15 min
        # second attemp -> 30 min
        # third attemp -> 1h
        # fourth attemp -> 2h
        # fifth attemp -> 2h
        # sixth attemp -> 2h ...
        res = 2 ** (nb_attempt - 1)
        times = res if res < 8 else 8
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

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "relocated_chunks": self.relocated_chunks,
            "errors": self.errors,
            "orphan_chunks_found": self.orphan_chunks_found,
            "waiting_new_attempt": self.waiting_new_attempt,
            "removed_symlinks": self.removed_symlinks,
            "created_symlinks": self.created_symlinks,
            "failed_post": self.failed_post,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.relocated_chunks = 0
        self.errors = 0
        self.orphan_chunks_found = 0
        self.waiting_new_attempt = 0
        self.removed_symlinks = 0
        self.created_symlinks = 0
        self.failed_post = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def Changelocation_filter(app):
        return Changelocation(app, conf)

    return Changelocation_filter
