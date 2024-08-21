# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
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

from .blob_mover import RawxDecommissionJob
from .blob_rebuilder import RawxRebuildJob
from .meta2_decommissioner import Meta2DecommissionJob
from .meta2_rebuilder import Meta2RebuildJob
from .meta2_relocator import Meta2RelocationJob
from .rdir_decommissionner import RdirDecommissionJob
from .tester import TesterJob


JOB_TYPES = {
    Meta2DecommissionJob.JOB_TYPE: Meta2DecommissionJob,
    Meta2RebuildJob.JOB_TYPE: Meta2RebuildJob,
    Meta2RelocationJob.JOB_TYPE: Meta2RelocationJob,
    RawxDecommissionJob.JOB_TYPE: RawxDecommissionJob,
    RawxRebuildJob.JOB_TYPE: RawxRebuildJob,
    RdirDecommissionJob.JOB_TYPE: RdirDecommissionJob,
    TesterJob.JOB_TYPE: TesterJob,
}
