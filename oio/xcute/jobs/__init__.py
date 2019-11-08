from .mover import RawxDecommissionJob
from .tester import TesterJob


JOB_TYPES = {
    RawxDecommissionJob.JOB_TYPE: RawxDecommissionJob,
    TesterJob.JOB_TYPE: TesterJob
}
