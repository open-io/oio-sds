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
import time
from os import lstat, makedirs, unlink, rename
from os.path import join, isdir
from shutil import move
from urllib.parse import urlparse
from collections import Counter
from oio.common.easy_value import int_value
from oio.common.green import get_watchdog
from oio.content.content import ChunksHelper
from oio.content.factory import ContentFactory
from oio.content.quality import NB_LOCATION_LEVELS, format_location, get_current_items
from oio.crawler.common.base import Filter
from oio.common.utils import (
    get_nb_chunks,
    is_chunk_id_valid,
    request_id,
    service_pool_to_dict,
)
from oio.crawler.rawx.chunk_wrapper import (
    ChunkWrapper,
    PlacementImproverCrawlerError,
)
from oio.common import exceptions as exc


class Changelocation(Filter):
    """
    Initialize the filter used to relocate misplaced chunks
    """

    NAME = "Changelocation"
    NEW_ATTEMPT_DELAY = 900
    MIN_DELAY_SECS = 300
    SERVICE_UPDATE_INTERVAL = 3600
    ORPHANS_DIR = "orphans"
    NON_OPTIMAL_DIR = "non_optimal_placement"

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
        # Minimum time after the creation of non optimal symlink
        # before improver process it, to make sure that all meta2 entry are updated.
        # By default equal to 300 seconds.
        self.min_delay_secs = int_value(
            self.conf.get("min_delay_secs"), self.MIN_DELAY_SECS
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
        # Get content object
        self.content_factory = ContentFactory(
            self.conf, logger=self.logger, watchdog=watchdog
        )
        self.rawx_srv_data = None
        self.rawx_srv_locations = {}
        self.policy_data = {}

    def _check_chunk_location(self, chunk, reqid, force_master=False):
        """
        Verify if the misplaced chunk exists

        :param chunk: chunk representation
        :type chunk: ChunkWrapper
        :param reqid: request id
        :type reqid: str
        :param force_master: force the request to the master if True
        :type force_master: bool
        :raises exc.OrphanChunk: raised in case a orphan chunk is found
        """
        # Get all object chunks location
        _, chunks = self.api.container.content_locate(
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
        # Increment the counter of chunks relocated
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

    def _post_process(self, chunkwrapper):
        """
        Launch post process event: delete symbolic link

        :param chunkwrapper: chunk representation
        :type chunkwrapper: ChunkWrapper
        """
        try:
            # Unlink the symbolic link
            symb_link_path = chunkwrapper.chunk_symlink_path
            unlink(symb_link_path)
            # Increment the counter of process which succeeded
            self.successes += 1
        except Exception as chunk_exc:
            self.logger.warning(
                "Delete the symbolic link %s failed due to: %s",
                symb_link_path,
                str(chunk_exc),
            )

    def _get_new_symlink_path(self, chunk_id, path, is_symlink_new_format, now):
        """
        Return new symlink file path after changing in the file name the number of
        attempt and the timestamp representing the next time we will try to change
        the location of misplaced chunk.

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
        # Define the next time we will be allowed to move the misplaced chunk
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

    def process(self, env, cb):
        """
        Change location of a misplaced chunk

        :param env: used to create chunk representation
        :type env: dict
        :param cb: callback function
        :type cb: function
        """
        chunkwrapper = ChunkWrapper(env)
        # Get a request id for chunk placement improvement
        reqid = request_id("placementImprover-")
        chunk_id = chunkwrapper.chunk_id
        content_id = chunkwrapper.meta["content_id"]
        content_version = chunkwrapper.meta["content_version"]
        try:
            now = time.time()
            path = chunkwrapper.chunk_symlink_path
            # get mtime
            mtime = lstat(path).st_mtime
            if (now - mtime) < self.min_delay_secs:
                self.waiting_new_attempt += 1
                return self.app(env, cb)
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
                # Content not found or container not found
                self.logger.warning(
                    "Possible orphan chunk %s found: %s", chunk_id, str(chunk_exc)
                )
                try:
                    # Double check by forcing the request to the master
                    chunks = self._check_chunk_location(
                        chunkwrapper, reqid, force_master=True
                    )
                    return self.app(env, cb)
                except Exception as c_exc:
                    if isinstance(c_exc, (exc.OrphanChunk, exc.NotFound)):
                        self.logger.warning(
                            "Chunk %s still considered as orphan chunk after request to"
                            " the master: %s",
                            chunk_id,
                            str(chunk_exc),
                        )
                        orphan_chunk_symlink_path = self.ORPHANS_DIR.join(
                            chunkwrapper.chunk_symlink_path.rsplit(
                                self.NON_OPTIMAL_DIR, 1
                            )
                        )
                        orphan_chunk_symlink_path = self._get_new_symlink_path(
                            chunk_id,
                            orphan_chunk_symlink_path,
                            is_symlink_new_format,
                            now,
                        )
                        self.orphan_chunks_found += 1
                        orphan_chunk_folder = orphan_chunk_symlink_path.rsplit("/", 1)[
                            0
                        ]
                        if not isdir(orphan_chunk_folder):
                            # Create orphan folder if it does not exist
                            makedirs(orphan_chunk_folder)
                        # Move orphan chunk symlink to orphan chunk symlink folder
                        move(chunkwrapper.chunk_symlink_path, orphan_chunk_symlink_path)
                        self.logger.warning(
                            "Orphan chunk symlink %s moved to orphans folder %s.",
                            chunk_id,
                            orphan_chunk_folder,
                        )
                        return self.app(env, cb)

            self.errors += 1
            resp = PlacementImproverCrawlerError(
                chunk=chunkwrapper,
                body=(
                    f"Error while looking for chunks location: {chunk_exc} "
                    f"reqid={reqid}, chunk_id={chunk_id}, "
                    f"content_id={content_id}, "
                    f"content_version={content_version}"
                ),
            )
            return resp(env, cb)
        try:
            # Get content object
            content = self.content_factory.get_by_path_and_version(
                container_id=chunkwrapper.meta["container_id"],
                content_id=content_id,
                path=chunkwrapper.meta["content_path"],
                version=content_version,
                reqid=reqid,
            )
            self._move_chunk(chunkwrapper, content, reqid, cur_items=cur_items)
        except Exception as chunk_exc:
            if isinstance(chunk_exc, exc.SpareChunkException):
                # Get misplaced chunks
                misplaced_chunks_ids = self._get_misplaced_chunks(
                    chunks, policy=content.policy, content_id=content.content_id
                )
                # Check if symlink found, links actually to a misplaced chunk
                if chunk_id not in misplaced_chunks_ids:
                    # Chunk is well placed, remove symlink
                    symb_link_path = chunkwrapper.chunk_symlink_path
                    unlink(symb_link_path)
                    self.removed_symlinks += 1
                    # As we have encountered in some cases misplaced chunks without
                    # non optimal placement header, for each misplaced chunk we do
                    # a post to add non optimal placement header.
                    misplaced_chunk_urls = [
                        chunk["url"]
                        for chunk in chunks
                        if (
                            chunk["url"].split("/", 3)[3] in misplaced_chunks_ids
                            and chunk["url"].split("/", 3)[3] != chunk_id
                        )
                    ]

                    (
                        created_symlinks,
                        failed_post,
                    ) = self.api.blob_client.tag_misplaced_chunk(
                        misplaced_chunk_urls, self.logger
                    )
                    self.created_symlinks += created_symlinks
                    self.failed_post += failed_post
                    return self.app(env, cb)
                else:
                    # An error occured when moving the chunk, we need to set
                    # a time after which we will retry.
                    new_symlink_path = self._get_new_symlink_path(
                        chunk_id,
                        chunkwrapper.chunk_symlink_path,
                        is_symlink_new_format,
                        now,
                    )
                    rename(chunkwrapper.chunk_symlink_path, new_symlink_path)

            self.errors += 1
            resp = PlacementImproverCrawlerError(
                chunk=chunkwrapper,
                body=(
                    f"Error while moving the chunk {chunk_exc}"
                    f"reqid={reqid}, chunk_id={chunk_id}, "
                    f"content_id={content_id}, "
                    f"content_version={content_version}"
                ),
            )
            return resp(env, cb)
        # Delete the symbolic link refering the chunk as misplaced
        # This action is called only when the chunk has been moved
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
