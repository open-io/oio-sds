# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from oio.common.easy_value import float_value, int_value
from oio.xcute.common.job import XcuteJob


class XcuteUsageTargetJob(XcuteJob):
    """Abstract parent class for rawx and meta2 jobs."""

    DEFAULT_USAGE_TARGET = 0

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, lock = super(XcuteUsageTargetJob, cls).sanitize_params(
            job_params
        )
        if cls.__name__.endswith("DecommissionJob"):
            sanitized_job_params["usage_target"] = int_value(
                job_params.get("usage_target"), cls.DEFAULT_USAGE_TARGET
            )

        return sanitized_job_params, lock


class XcuteRdirJob(XcuteUsageTargetJob):
    """Abstract parent class for rawx and meta2 jobs."""

    DEFAULT_RDIR_FETCH_LIMIT = 1000
    DEFAULT_RDIR_TIMEOUT = 60.0

    @classmethod
    def sanitize_params(cls, job_params):
        sanitized_job_params, lock = super(XcuteRdirJob, cls).sanitize_params(
            job_params
        )

        sanitized_job_params["rdir_fetch_limit"] = int_value(
            job_params.get("rdir_fetch_limit"), cls.DEFAULT_RDIR_FETCH_LIMIT
        )

        sanitized_job_params["rdir_timeout"] = float_value(
            job_params.get("rdir_timeout"), cls.DEFAULT_RDIR_TIMEOUT
        )

        return sanitized_job_params, lock
