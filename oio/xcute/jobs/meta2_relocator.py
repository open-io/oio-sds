# Copyright (C) 2024-2025 OVH SAS
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

from collections import Counter
from itertools import combinations

from oio.api.object_storage import ObjectStorageApi
from oio.common.easy_value import boolean_value
from oio.common.exceptions import DisusedUninitializedDB, RemainsDB
from oio.common.utils import depaginate, service_pool_to_dict
from oio.content.quality import count_items_per_loc, format_location, get_distance
from oio.directory.meta2 import Meta2Database
from oio.xcute.common.job import XcuteJob, XcuteTask


class Meta2RelocationTask(XcuteTask):
    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super().__init__(
            conf,
            job_params,
            logger=logger,
            watchdog=watchdog,
        )
        self.analyze_only = job_params["analyze_only"]
        self.dry_run = job_params["dry_run"] or self.analyze_only
        self.meta2 = Meta2Database(conf, logger=logger)
        pool_info = self.meta2.conscience.info()["service_pools"]
        self.pool_params = service_pool_to_dict(pool_info.get("meta2", "3,meta2"))
        self.logger.info(
            "%s meta2 pool info: %s",
            self.__class__.__name__,
            self.pool_params,
        )

    def check_service_dist(self, svc_info_by_id, dist_type="warn_dist"):
        dist_limit = self.pool_params.get(dist_type)
        too_close = set()
        if not dist_limit:
            return too_close

        for s1, s2 in combinations(svc_info_by_id.keys(), 2):
            s1loc = svc_info_by_id[s1]["tags"].get("tag.loc", "unknown")
            s2loc = svc_info_by_id[s2]["tags"].get("tag.loc", "unknown")
            dist = get_distance(s1loc, s2loc)
            if dist < dist_limit:
                too_close.add(s1)
                too_close.add(s2)
                svc_info_by_id[s1].setdefault("defects", []).append(
                    f"too close to {s2} (dist={dist}, {dist_type}={dist_limit})"
                )
                svc_info_by_id[s2].setdefault("defects", []).append(
                    f"too close to {s1} (dist={dist}, {dist_type}={dist_limit})"
                )

        return too_close

    def check_service_locations(
        self,
        svc_info_by_id,
        constraint_type="fair_location_constraint",
    ):
        constraint_str = self.pool_params.get(constraint_type)
        if not constraint_str:
            return set()

        limits = [int(li) for li in constraint_str.split(".")]
        svc_locs = [
            format_location(s["tags"].get("tag.loc", "unknown"))
            for s in svc_info_by_id.values()
        ]
        loc_counts = count_items_per_loc(svc_locs)
        crowded_locs = {}
        for loc, count in loc_counts.items():
            lvl = len(loc) - 1
            if count > limits[lvl]:
                crowded_locs[loc] = f"{count}/{limits[lvl]}"

        misplaced = set()
        for svc in svc_info_by_id.values():
            svc.setdefault("defects", [])
            loc = format_location(svc["tags"].get("tag.loc", "unknown"))
            for i in range(len(loc)):
                excess = crowded_locs.get(loc[0 : i + 1])
                if excess:
                    loc_str = ".".join(loc[0 : i + 1])
                    svc["defects"].append(f"too many copies in {loc_str} ({excess})")
                    misplaced.add(svc["id"])
                    break
        return misplaced

    def process(self, task_id, task_payload, reqid=None):
        account = task_payload["account"]
        container = task_payload["container"]
        resp = Counter()

        # 1. Locate peers
        # (won't raise NotFound if a container has been created then deleted)
        all_dir_svcs = self.meta2.directory.list(
            account,
            container,
            service_type="meta2",
            reqid=reqid,
        )
        cid = all_dir_svcs["cid"]
        m2_peers = [s["host"] for s in all_dir_svcs["srv"]]
        if not m2_peers:
            self.logger.info(
                "%s/%s (%s) has no meta2 services linked, recently deleted?",
                account,
                container,
                cid,
            )
            resp["zero_peers"] += 1
            return resp

        # Make a copy, because we add fields later.
        m2_peers_info = {s: self.meta2.all_service_ids[s].copy() for s in m2_peers}

        # 2. Evaluate distance constraints
        misplaced = self.check_service_dist(m2_peers_info, "warn_dist")

        # 3. Evaluate location constraints
        misplaced.update(
            self.check_service_locations(
                m2_peers_info,
                "fair_location_constraint",
            )
        )

        if misplaced:
            resp["misplaced"] += 1
        else:
            resp["well_placed"] += 1
            return resp

        # 4. Select peers to move
        for svc in m2_peers_info.values():
            # The "defect score" is the number of defects we found for this service
            # (too close to another service, or too many services selected on
            # its location), divided by the score of the service.
            # - If two services have the same number of defects: move the one with
            #   the lowest score.
            # - If two services have the same score: move the one with the highest
            #   number of defects.
            svc["defect_score"] = len(svc.get("defects", [])) / max(1, svc["score"])
        moveable = [svc for svc in m2_peers_info.values() if svc["defect_score"] > 0]

        # 5. Move peers
        last_error = None
        for svc in sorted(moveable, key=lambda x: x["defect_score"], reverse=True):
            self.logger.info(
                "%s move %s out of %s (reason: %s)",
                "[dryrun] Would" if self.dry_run else "Will",
                cid,
                svc["id"],
                svc["defects"],
            )
            if self.dry_run:
                resp["moveable"] = 1
                if self.analyze_only:
                    break
            try:
                res = list(
                    self.meta2.move(
                        cid,
                        src=svc["id"],
                        dry_run=self.dry_run,
                        force_fair_constraints=True,
                        raise_error=True,
                        reqid=reqid,
                    )
                )[0]
                self.logger.info(
                    "Moved %s from %s to %s (reqid=%s)",
                    cid,
                    res["src"],
                    res["dst"],
                    reqid,
                )
                resp["moved"] += 1
                break
            except DisusedUninitializedDB:
                self.logger.info(
                    "Base %s  is disused, ignored (reqid=%s)",
                    cid,
                    reqid,
                )
                break
            except RemainsDB:
                self.logger.info(
                    "Base %s does not exist anymore, ignored (reqid=%s)",
                    cid,
                    reqid,
                )
                break

            except Exception as err:
                last_error = err
                continue
        else:
            self.logger.error(
                "Failed to relocate %s (%d attempts): %s (reqid=%s)",
                cid,
                len(moveable),
                last_error,
                reqid,
            )
            # If we want the XcuteJob to end in error, we must raise an exception
            # instead of just incrementing the error counter.
            # resp["move_error"] += 1
            raise last_error

        return resp


class Meta2RelocationJob(XcuteJob):
    JOB_TYPE = "meta2-relocation"
    TASK_CLASS = Meta2RelocationTask

    DEFAULT_ANALYZE_ONLY = False
    DEFAULT_DRY_RUN = False

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(Meta2RelocationJob, cls).sanitize_params(
            job_params
        )
        # TODO(FVE): read incident date
        for key in ("account_marker", "container_marker"):
            sanitized_job_params[key] = job_params.get(key)
        sanitized_job_params["analyze_only"] = boolean_value(
            job_params.get("analyze_only"), cls.DEFAULT_ANALYZE_ONLY
        )
        sanitized_job_params["dry_run"] = boolean_value(
            job_params.get("dry_run"), cls.DEFAULT_DRY_RUN
        )
        lock_key = cls.__name__
        return sanitized_job_params, lock_key

    def __init__(self, conf, logger=None, **kwargs):
        super().__init__(conf, logger=logger, **kwargs)
        self.api = ObjectStorageApi(conf["namespace"], logger=logger)

    def get_tasks(self, job_params, marker=None, reqid=None):
        containers_it = self._containers_from_account_service(
            job_params,
            marker,
            reqid=reqid,
        )
        for account, container_info in containers_it:
            task_id = f"{account}/{container_info[0]}"
            yield (
                task_id,
                {
                    "account": account,
                    "container": container_info[0],
                    "mtime": container_info[4],
                },
            )

    def get_total_tasks(self, job_params, marker=None, reqid=None):
        containers_it = self._containers_from_account_service(
            job_params,
            marker,
            reqid=reqid,
        )
        i = 0
        for i, (account, container_info) in enumerate(containers_it, 1):
            if i % 1000 == 0:
                yield f"{account}/{container_info[0]}", 1000

        remaining = i % 1000
        if remaining == 0:
            return

        # FIXME(FVE): incr_total_tasks() doesn't like marker=None
        marker = f"{account}/{container_info[0]}"

        yield marker, remaining

    def _containers_from_account_service(self, job_params, marker, reqid=None):
        account_marker = job_params.get("account_marker")
        container_marker = job_params.get("container_marker")

        if marker:
            account_marker, container_marker = marker.split("/", 1)

        accounts = depaginate(
            self.api.account.account_list,
            listing_key=lambda x: x["listing"],
            item_key=lambda x: x["id"],
            marker_key=lambda x: x["next_marker"],
            truncated_key=lambda x: x["truncated"],
            marker=account_marker,
            reqid=reqid,
            sharding_accounts=True,
        )
        for account in accounts:
            self.logger.info(
                "Listing containers for account %s",
                account,
            )
            containers = depaginate(
                self.api.account.container_list,
                listing_key=lambda x: x["listing"],
                marker_key=lambda x: x["next_marker"],
                truncated_key=lambda x: x["truncated"],
                account=account,
                marker=container_marker,
                region=self.api.account.region,
                reqid=reqid,
            )
            container_marker = None

            for container_info in containers:
                # container_info: (name, objects, bytes, isprefix, mtime)
                yield account, container_info
