# Copyright (C) 2023-2024 OVH SAS
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

import sqlite3
from collections import Counter
from urllib.parse import urlparse
from oio.blob.operator import ChunkOperator
from oio.common.easy_value import float_value, int_value, true_value
from oio.common.exceptions import NoSuchObject, NotFound
from oio.common.green import time
from oio.common.utils import (
    cid_from_name,
    get_nb_chunks,
    request_id,
    service_pool_to_dict,
    ratelimit,
)
from oio.content.quality import NB_LOCATION_LEVELS, format_location
from oio.crawler.common.base import Filter
from oio.crawler.meta2.meta2db import Meta2DB, Meta2DBError, delete_meta2_db
from oio.directory.admin import AdminClient


class VerifyChunkPlacement(Filter):
    """
    Trigger chunks placement verification on all meta2 database.
    This filter will also trigger rebuild of chunks that need to be recovered.
    """

    NAME = "VerifyChunkPlacement"
    MAX_SCANNED_PER_SECOND = 10000
    SERVICE_UPDATE_INTERVAL = 3600

    def init(self):
        self.successes = 0
        self.errors = 0
        self.created_symlinks = 0
        self.rebuilt_chunks = 0
        self.failed_post = 0
        self.failed_rebuild = 0
        # Counter for slaves database
        self.slave_volume_skipped = 0
        self.api = self.app_env["api"]
        self.volume_id = self.app_env["volume_id"]
        self.conscience_client = self.api.conscience
        self.admin_client = AdminClient(
            self.conf, logger=self.logger, pool_manager=self.api.container.pool_manager
        )
        # Object scanned per second
        self.max_scanned_per_second = float_value(
            self.conf.get("max_scanned_per_second"), self.MAX_SCANNED_PER_SECOND
        )
        # Interval of time in sec after which the services are updated
        self.service_update_interval = int_value(
            self.conf.get("service_update_interval"), self.SERVICE_UPDATE_INTERVAL
        )
        self.dry_run_rebuild = true_value(self.conf.get("dry_run_rebuild", False))
        self.dry_run_checker = true_value(self.conf.get("dry_run_checker", False))
        # Used to rebuild invalid chunks
        self.chunk_operator = ChunkOperator(
            self.conf, logger=self.logger, watchdog=self.app_env["watchdog"]
        )
        self.last_services_update = 0.0
        self.rawx_srv_data = None
        self.rawx_srv_locations = {}
        self.policy_data = {}
        self.rawx_volume = {}
        timestamp = f"-{int(time.time())}"
        self.suffix = self.NAME + timestamp

    def _update_srv_data(self):
        """
        Update attributes gathering rawx service data (constraints, policy,
        location, etc.)
        """
        now = time.time()
        if self.rawx_srv_data is None or (
            (now - self.last_services_update) >= self.service_update_interval
        ):
            # Caching the services data  to avoid doing the request each time
            # the function is called. The update will be done within an interval
            # of one hour between two calls
            # Get a request id for verify chunks placement meta2 crawler
            reqid = request_id("verify-chunk-placement-")
            self.rawx_srv_data = self.conscience_client.all_services(
                service_type="rawx",
                reqid=reqid,
            )
            # Update the rawx server locations
            self.chunk_operator.rawx_srv_locations = self.rawx_srv_locations
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
                    constraint_service_pool = pool_dict[
                        "fair_location_constraint"
                    ].split(".")
                    data_security = cluster_info["data_security"][data_security]
                    # Fetch expected chunks for a policy with a specific data security
                    expected_nb_chunks = get_nb_chunks(data_security)
                    storage_constraints = list(map(int, constraint_service_pool))
                    self.policy_data[policy] = (
                        expected_nb_chunks,
                        data_security,
                        storage_constraints,
                    )
                except Exception as exc:
                    self.logger.exception(
                        "Failed to fetch policy data of %s: %s.", policy, exc
                    )
                    continue
            self.last_services_update = now

    def _get_chunk_to_rebuild(self, obj_data):
        """
        Returns positions of chunks to rebuild

        :param obj_data: object chunks data
            [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :type obj_data: list
        :return: chunks to rebuild, version, path
        :rtype: tuple
        """
        _, _, _, policy, obj_name, version = obj_data[0]
        nb_chunks = len(obj_data)
        # Fetch positions really occupied
        positions = [chunk[1] for chunk in obj_data]
        # Fetch expected number of chunks for the storage policy
        expected = self.policy_data[policy][0]
        # Fetch data security defined for the storage policy
        data_security = self.policy_data[policy][1]
        diff = expected - nb_chunks
        if diff == 0:
            return [], version, obj_name
        if nb_chunks < expected:
            # One metachunk
            to_rebuild = self._get_chunk_to_rebuild_from_metachunk(
                data_security, expected, diff, positions
            )
        else:
            # Get positions of each chunk
            positions = [chunk[1] for chunk in obj_data]
            to_rebuild = self._get_chunks_to_rebuild_from_metachunks(
                data_security, expected, positions=positions
            )
        return to_rebuild, version, obj_name

    def _get_chunk_to_rebuild_from_metachunk(
        self, data_security, expected, diff, positions
    ):
        """
        Return the chunks to rebuild for an object with one metachunk

        :param data_security: data security defined for the object storage policy
        :type data_security: str
        :param expected: number of chunks expected for the object
        :type expected: int
        :param diff: difference between expected and actual number of chunks
        :type diff: int
        :param positions: positions occupied by object chunks
        :type positions: [str]
        :return: list of chunks positions to rebuild
        :rtype: [str]
        """
        if "nb_copy" in data_security:
            # All copies has the same position for Plain replication environment
            to_rebuild = [0 for _ in range(diff)]
        else:
            # Position format is 0.1, 0.2 , etc.
            expected_pos = list(map(lambda x: str(x / 10), range(expected)))
            to_rebuild = [pos for pos in expected_pos if pos not in positions]
        return to_rebuild

    def _get_chunks_to_rebuild_from_metachunks(
        self, data_security, expected, positions
    ):
        """
        Return list of chunks to rebuild for an object with multiple metachunk

        :param data_security: data security defined for the object storage policy
        :type data_security: str
        :param expected: number of chunks expected for the object
        :type expected: int
        :param positions: positions occupied by object chunks
        :type positions: [str]
        :return: list of chunks positions to rebuild
        :rtype: [str]
        """
        to_rebuild = []
        # several metachunks object
        if "nb_copy" in data_security:
            # For copy policies
            current_meta_chunk = None
            counter = 0
            try:
                for pos in positions:
                    if current_meta_chunk is None:
                        current_meta_chunk = pos
                        counter += 1
                        continue
                    if current_meta_chunk != pos:
                        to_rebuild.extend(
                            [current_meta_chunk for _ in range(expected - counter)]
                        )
                        current_meta_chunk = pos
                        counter = 0
                    counter += 1
            except StopIteration:
                pass
            finally:
                # The chunks on the last metachunk are handled here
                to_rebuild.extend(
                    [current_meta_chunk for _ in range(expected - counter)]
                )
        else:
            # For erasure coding
            current_meta_chunk = None
            occupied_pos = []
            # Positions expected for the chunks
            expected_pos = list(map(str, range(expected)))
            try:
                for pos in positions:
                    # Get metachunk number and chunk position
                    m_n, c_p = pos.split(".")
                    if current_meta_chunk is None:
                        current_meta_chunk = m_n
                        occupied_pos.append(c_p)
                        continue
                    if current_meta_chunk != m_n:
                        to_rebuild.extend(
                            [
                                ".".join([current_meta_chunk, exp_pos])
                                for exp_pos in expected_pos
                                if exp_pos not in occupied_pos
                            ]
                        )
                        occupied_pos = []
                        current_meta_chunk = m_n
                    occupied_pos.append(c_p)
            except StopIteration:
                pass
            finally:
                # The chunks on the last metachunk are handled here
                to_rebuild.extend(
                    [
                        ".".join([current_meta_chunk, exp_pos])
                        for exp_pos in expected_pos
                        if exp_pos not in occupied_pos
                    ]
                )
        return to_rebuild

    def _get_misplaced_chunks(self, obj_data, account, container):
        """
        Return the misplaced chunks positions among the list of chunks passed in
        the parameters. In addition to that if a chunk needs to be recovered a restore
        request will be sent.

        :param obj_data: object chunks data
            [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :type obj_data: list
        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        :return: list of misplaced chunks position
        :rtype: list
        """
        misplaced_chunks_pos = list()
        counters = {}
        container_id = cid_from_name(account, container)
        _, _, content_id, policy, obj_name, _ = obj_data[0]
        try:
            # Constraint defined for all the chunks object
            fair_location_constraint = self.policy_data[policy][2]
        except KeyError as exc:
            self.logger.warning(
                "Policy %s has no fair location constraint defined, "
                "cannot verify chunks placement for the object %s, cid %s: %s.",
                policy,
                obj_name,
                container_id,
                exc,
            )
            return misplaced_chunks_pos
        self._rebuild_chunks_if_needed(obj_data, container_id, content_id)
        for chunk_data in obj_data:
            # [(rawx_srv_id, position, content_id, policy, object name, version), ...]
            rawx_srv_id = chunk_data[0]
            pos = chunk_data[1]
            # Location of the rawx of the chunk selected
            location = format_location(self.rawx_srv_locations[rawx_srv_id])
            for depth in range(NB_LOCATION_LEVELS):
                # Create a counter for each depth
                depth_counter = counters.setdefault(depth, Counter())
                subloc = location[: depth + 1]
                depth_counter[subloc] += 1
                if depth_counter[subloc] > fair_location_constraint[depth]:
                    misplaced_chunks_pos.append((rawx_srv_id, pos))
        return misplaced_chunks_pos

    def _rebuild_chunks_if_needed(self, obj_data, container_id, content_id):
        """
        Rebuild chunk not pushed if needed

        :param obj_data: object chunks data
            [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :type obj_data: list
        :param container_id: container (cid)
        :type container_id: str
        :param content_id: object id
        :type content_id: str
        """
        # Get chunks to rebuild
        chunk_pos_to_rebuild, version, path = self._get_chunk_to_rebuild(obj_data)
        for position in chunk_pos_to_rebuild:
            try:
                if self.dry_run_rebuild:
                    # This chunk would be rebuilt
                    msg = "Chunk of object %s at position %s would be rebuilt, cid %s."
                else:
                    self.chunk_operator.rebuild(
                        container_id,
                        content_id,
                        position,
                        path=path,
                        version=version,
                    )
                    msg = "Chunk of object %s at position %s rebuilt, cid %s."

                self.rebuilt_chunks += 1
                self.logger.debug(
                    msg,
                    path,
                    position,
                    container_id,
                )

            except Exception as exc:
                self.logger.exception(
                    "Rebuild chunk of object %s at position %s has failed, cid %s: %s.",
                    path,
                    position,
                    container_id,
                    exc,
                )
                self.failed_rebuild += 1

    def _find_misplaced_chunks(self, chunks, account, container):
        """
        Find misplaced chunks among object chunks.

        :param chunks: object chunks data
            [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :type chunks: list
        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        """
        if len(chunks) == 0:
            return
        # Update the rawx service data if needed
        self._update_srv_data()
        # Fetch misplaced chunks among the list of chunks belonging to the same object
        misplaced_chunks_pos = self._get_misplaced_chunks(chunks, account, container)
        for index, pos in enumerate(misplaced_chunks_pos):
            if index == 0:
                # We only need to do this one time
                _, _, _, _, obj_name, version = chunks[0]
                try:
                    # Get object location to fetch the chunks url
                    _, chunks_loc = self.api.object_locate(
                        account, container, obj_name, version
                    )
                    chunk_urls = {
                        (
                            urlparse(chunk_loc["url"]).netloc,
                            chunk_loc["pos"],
                        ): chunk_loc["url"]
                        for chunk_loc in chunks_loc
                    }
                except (NoSuchObject, NotFound):
                    self.logger.warning(
                        "Object %s not found account %s, container %s.",
                        obj_name,
                        account,
                        container,
                    )
                    raise

            url = chunk_urls[pos]
            self.logger.debug(
                "Chunk %s of object %s at position %s identified as misplaced,"
                " account %s, container %s",
                url,
                obj_name,
                pos,
                account,
                container,
            )
            yield url

    def _verify_chunks_from_meta2_db(self, account, container, chunks_data):
        """
        Parse meta2 database to identify misplaced chunks and tag them as so.
        Chunks will be grouped by content_id

        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        :param chunks_data: iterator on chunks referenced in the meta2 database
                [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :type chunks_data: list
        """
        last_scan_time = 0
        content_id = None
        # Will gather chunks of one object
        obj_chunks = []
        # Used while iterating on chunks to gather chunks object
        chunks = []
        try:
            for chunk in chunks_data:
                chunks.append(chunk)
                # New object
                if content_id is None:
                    content_id = chunk[2]
                    continue
                # Chunk of the same object (content_id is still the same)
                if content_id == chunk[2]:
                    continue
                # Content_id is different , all chunks of the current object
                # has been gathered. The last chunk in chunks belongs to the
                # following object
                obj_chunks = chunks[:-1]
                chunks = chunks[-1:]
                self._tag_misplaced_chunks(account, container, obj_chunks)
                content_id = None
                last_scan_time = ratelimit(last_scan_time, self.max_scanned_per_second)
        except StopIteration:
            pass
        finally:  # The last object will be handled by the call below
            obj_chunks = chunks
            self._tag_misplaced_chunks(account, container, obj_chunks)

    def _tag_misplaced_chunks(self, account, container, obj_chunks):
        """Add non optimal placement tag to misplaced chunks

        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        :param obj_chunks: list of chunks
        :type obj_chunks: list
        """
        try:
            misplaced_chunk_urls = self._find_misplaced_chunks(
                chunks=obj_chunks, account=account, container=container
            )
            if self.dry_run_checker:
                # Show the number of symlinks that would be created
                self.created_symlinks += len(misplaced_chunk_urls)
                return

            created_symlinks, failed_post = self.api.blob_client.tag_misplaced_chunk(
                misplaced_chunk_urls, self.logger
            )
            self.created_symlinks += created_symlinks
            self.failed_post += failed_post

        except Exception as exc:
            if obj_chunks:
                obj_name = obj_chunks[0][-2]
                self.logger.exception(
                    "Tag misplaced chunks of the object %s failed,"
                    " container %s, account %s: %s.",
                    obj_name,
                    container,
                    account,
                    exc,
                )

    def _get_all_chunks(self, meta2db_cur):
        """
        Return chunks information referenced in the meta2 data base. Their rawx
        service id, position and the id, policy, name and the version of the object

        :param meta2db_cur: sqlite3 cursor
        :type meta2db_cur: Cursor
        :return: iterator on chunks referenced in the meta2 database
                [(rawx_srv_id, position, content_id, policy, object name, version), ...]
        :rtype: list
        """
        # Query to fetch all the chunks referenced in the meta2 database
        chunks_data = meta2db_cur.execute(
            "SELECT chunks.id, chunks.position, hex(contents.id), contents.policy,"
            " aliases.alias , aliases.version FROM chunks INNER JOIN contents ON"
            " contents.id = chunks.content INNER JOIN aliases ON chunks.content ="
            " aliases.content ORDER BY chunks.content, chunks.position"
        )
        for chunk_data in chunks_data:
            yield chunk_data

    def _analyse_chunks_from_meta2_db(self, db_path, account, container):
        """
        Analyse chunks location in meta2 database and tag misplaced chunks

        :param db_path: path of the local meta2 database copy
        :type db_path: str
        :param account: account name
        :type account: str
        :param container: container name
        :type container: str
        """
        try:
            # Connection to meta2 database local copy
            with sqlite3.connect(db_path) as connection:
                cursor = connection.cursor()
                try:
                    chunks_data = self._get_all_chunks(meta2db_cur=cursor)
                    self._verify_chunks_from_meta2_db(
                        account=account,
                        container=container,
                        chunks_data=chunks_data,
                    )
                finally:
                    # Close the cursor of the meta2 database local copy
                    cursor.close()
        except Exception as exc:
            self.logger.exception("Error while analysing meta2db %s: %s.", db_path, exc)
            raise

    def _copy_meta2_db(self, meta2db):
        """
        Copy locally meta2 master database

        :param meta2db: meta2db representation
        :type meta2db: Meta2DB
        :return: (True, None) if copy succeeded and (False, error) if not
        :rtype: tuple
        """
        try:
            params = {
                "service_type": "meta2",
                "cid": meta2db.cid,
                "svc_from": self.volume_id,
                "suffix": self.suffix,
            }
            # Request a local copy of the meta2 database
            self.admin_client.copy_base_local(**params)
            return True, None
        except Exception as exc:
            self.logger.exception(
                "Failed to make meta2 local copy cid = %s, meta2db path %s: %s",
                meta2db.cid,
                meta2db.env["path"],
                exc,
            )
            return False, exc

    def _delete_copy(self, meta2db):
        """
        Delete the local meta2db copy

        :param meta2db: meta2db representation
        :type meta2db: Meta2DB
        """
        cid = meta2db.cid
        path = meta2db.env["path"]
        suffix = self.suffix
        volume_id = self.volume_id
        admin_client = self.admin_client
        logger = self.logger
        delete_meta2_db(cid, path, suffix, volume_id, admin_client, logger)

    def process(self, env, cb):
        """
        Verify location of chunks referenced in the meta2 data base

        :param env: dictionary with environment details
        :type env: dict
        :param cb: callback function
        :type cb: function
        """
        meta2db = Meta2DB(self.app_env, env)
        cid = meta2db.cid
        account = meta2db.system["sys.account"]
        container = meta2db.system["sys.user.name"]
        try:
            status = self.admin_client.election_status(
                "meta2", account=account, reference=container
            )
            master = status.get("master", "")
            # Only run the filter on master database
            # and only if we are on the master meta2 database host
            if master != self.volume_id:
                self.slave_volume_skipped += 1
                return self.app(env, cb)
            is_copied, exc = self._copy_meta2_db(meta2db)
            if not is_copied:
                self.errors += 1
                resp = Meta2DBError(
                    meta2db,
                    body=(
                        f"Failed to process {self.NAME} "
                        f"for the container {cid}: {exc}"
                    ),
                )
                return resp(env, cb)

            meta2db_copy_path = meta2db.env["path"] + "." + self.suffix
            try:
                self._analyse_chunks_from_meta2_db(
                    meta2db_copy_path, account, container
                )
                self.successes += 1
            finally:
                # Delete the copied meta2 database
                self._delete_copy(meta2db=meta2db)

        except Exception as exc:
            self.logger.exception(
                "Failed to verify misplaced chunks referenced in %s: %s",
                meta2db.env["path"],
                exc,
            )
            self.errors += 1
            resp = Meta2DBError(
                meta2db,
                body=(
                    f"Failed to process {self.NAME} " f"for the container {cid}: {exc}"
                ),
            )
            return resp(env, cb)
        return self.app(env, cb)

    def _get_filter_stats(self):
        return {
            "successes": self.successes,
            "errors": self.errors,
            "created_symlinks": self.created_symlinks,
            "failed_post": self.failed_post,
            "slave_volume_skipped": self.slave_volume_skipped,
            "rebuilt_chunks": self.rebuilt_chunks,
            "failed_rebuild": self.failed_rebuild,
        }

    def _reset_filter_stats(self):
        self.successes = 0
        self.errors = 0
        self.created_symlinks = 0
        self.failed_post = 0
        self.slave_volume_skipped = 0
        self.rebuilt_chunks = 0
        self.failed_rebuild = 0


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def verify_chunk_placement_filter(app):
        return VerifyChunkPlacement(app, conf)

    return verify_chunk_placement_filter
