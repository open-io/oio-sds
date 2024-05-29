# Copyright (C) 2022-2024 OVH SAS
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

from itertools import chain

from oio.common.easy_value import boolean_value, int_value
from oio.rdir.client import RdirDispatcher
from oio.xcute.common.job import XcuteTask
from oio.xcute.jobs.common import XcuteRdirJob


class RdirDecommissionTask(XcuteTask):
    """
    Xcute task in charge of decommissioning a single database from an
    rdir service.
    """

    def __init__(self, conf, job_params, logger=None, watchdog=None):
        super(RdirDecommissionTask, self).__init__(
            conf, job_params, logger=logger, watchdog=watchdog
        )

        # Id of the rdir we are decommissioning
        self.service_id = job_params["service_id"]
        self.dry_run = job_params["dry_run"]
        self.min_dist = job_params["min_dist"]
        self.replicas = job_params["replicas"]

    def process(self, task_id, task_payload, reqid=None):
        hosted_service_type = task_payload["service_type"]
        hosted_service_id = task_payload["service_id"]

        if self.dry_run:
            self.logger.debug(
                "[reqid=%s] [dryrun] Reassigning rdir for %s (%s)",
                reqid,
                hosted_service_id,
                hosted_service_type,
            )
            return {"skipped_bases": 1}

        dispatcher = RdirDispatcher(self.conf, logger=self.logger)
        old_rdirs = dispatcher.rdir._get_rdir_addr(hosted_service_id, reqid=reqid)
        self.logger.debug(
            "[reqid=%s] Reassigning DB of %s out of %s",
            reqid,
            hosted_service_id,
            self.service_id,
        )
        all_services = dispatcher.assign_services(
            hosted_service_type,
            reassign=self.service_id,
            service_id=hosted_service_id,
            min_dist=self.min_dist,
            replicas=self.replicas,
            reqid=reqid,
        )
        new_rdirs = {
            (x.get("tag.service_id") or x["addr"]) for x in all_services[0]["rdir"]
        } - set(old_rdirs)
        copy_func = {
            "meta2": dispatcher.rdir.meta2_copy_vol,
            "rawx": dispatcher.rdir.chunk_copy_vol,
        }
        self.logger.debug(
            "[reqid=%s] Copying DB of %s to %s", reqid, hosted_service_id, new_rdirs
        )
        # Let this deal with available sources automatically
        copy_func[hosted_service_type](
            hosted_service_id, dests=list(new_rdirs), reqid=reqid
        )


class RdirDecommissionJob(XcuteRdirJob):
    JOB_TYPE = "rdir-decommission"
    TASK_CLASS = RdirDecommissionTask

    ALLOWED_SERVICE_TYPES = ["rawx", "meta2"]
    DEFAULT_DRY_RUN = False
    DEFAULT_MIN_DIST = 3
    DEFAULT_REPLICAS = 3

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, _ = super(RdirDecommissionJob, cls).sanitize_params(
            job_params
        )

        # specific configuration
        service_id = job_params.get("service_id")
        if not service_id:
            raise ValueError("Missing rdir service ID")
        sanitized_job_params["service_id"] = service_id

        sanitized_job_params["service_types"] = job_params.get(
            "service_types", cls.ALLOWED_SERVICE_TYPES
        )
        for type_ in sanitized_job_params["service_types"]:
            if type_ not in cls.ALLOWED_SERVICE_TYPES:
                raise ValueError(f"Unknown service type {type_}")

        sanitized_job_params["dry_run"] = boolean_value(
            job_params.get("dry_run"), cls.DEFAULT_DRY_RUN
        )

        sanitized_job_params["min_dist"] = int_value(
            job_params.get("min_dist"), cls.DEFAULT_MIN_DIST
        )

        sanitized_job_params["replicas"] = int_value(
            job_params.get("replicas"), cls.DEFAULT_REPLICAS
        )

        return sanitized_job_params, f"rdir/{service_id}"

    def __init__(self, conf, logger=None, **kwargs):
        super(RdirDecommissionJob, self).__init__(conf, logger=logger, **kwargs)
        self.rdir_dispatcher = RdirDispatcher(self.conf, logger=self.logger)

    def get_tasks_for_type(self, job_params, service_type, reqid=None):
        job_rdir_id = job_params["service_id"]
        task_template = {"service_type": service_type}
        assignments = self.rdir_dispatcher.get_aggregated_assignments(
            service_type, reqid=reqid
        )

        # Look at all the services, and yield only those that match our ID
        for svc_id in assignments.get(job_rdir_id, []):
            next_task = task_template.copy()
            next_task["service_id"] = svc_id
            task_id = "|".join((job_rdir_id, svc_id))
            yield task_id, next_task

    def get_tasks(self, job_params, marker=None, reqid=None):
        typed_iters = [
            self.get_tasks_for_type(job_params, type_, reqid=reqid)
            for type_ in job_params["service_types"]
        ]
        return chain(*typed_iters)

    def get_total_tasks(self, job_params, marker=None, reqid=None):
        # Yes, we will generate the list of tasks twice, but ¯\_(ツ)_/¯
        for type_ in job_params["service_types"]:
            yield type_, len(
                list(self.get_tasks_for_type(job_params, type_, reqid=reqid))
            )
