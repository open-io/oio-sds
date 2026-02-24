# Copyright (C) 2026 OVH SAS
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import json
import os
import time

from oio import ObjectStorageApi
from oio.common.configuration import read_conf
from oio.common.constants import STRLEN_REQID
from oio.common.kafka import KafkaSender
from oio.common.logger import get_logger
from oio.common.redis_conn import RedisConnection
from oio.common.utils import request_id
from oio.event.evob import EventTypes
from oio.xcute.jobs.batch_replicator import BatchReplicatorJob, iter_lines_from_stream


class CatchupBatchRepli:
    def __init__(self, args: argparse.Namespace) -> None:
        self.conf = read_conf(args.conf_path)
        namespace = os.environ.get("OIO_NS", "OPENIO")
        self.conf["namespace"] = namespace
        self.logger = get_logger(self.conf, verbose=args.verbose)
        self.dry_run = args.dry_run
        self.job_id = args.job_id

        # Same trick as in orchestrator
        reqid = self.job_id + request_id(f"-{BatchReplicatorJob.JOB_TYPE[:10]}-")
        self.reqid = reqid[:STRLEN_REQID]

        redis_conf = {
            k[6:]: v
            for k, v in self.conf.get("xcute-orchestrator", {}).items()
            if k.startswith("redis_")
        }
        if not redis_conf:
            raise ValueError("redis conf not found")
        self.redis = RedisConnection(**redis_conf)

        self.running_tasks = self.redis.conn.smembers(
            f"xcute-customer:tasks:running:{self.job_id}"
        )
        nb_running_tasks = len(self.running_tasks)
        if nb_running_tasks == 0:
            raise ValueError(f"No running tasks found for job={self.job_id}")
        self.logger.info("%d remaining tasks found on redis", nb_running_tasks)

        self.api = ObjectStorageApi(namespace)
        self.job_show = self.api.xcute_customer.job_show(job_id=self.job_id)

        self.kafka_producer = None
        self.kafka_endpoint = self.conf.get("xcute-orchestrator", {}).get(
            "broker_endpoint"
        )
        self.jobs_topic = self.conf.get("xcute-orchestrator", {}).get("jobs_topic")

    def run(self) -> None:
        try:
            for task in self.running_tasks:
                self._catchup_one_task(task.decode())
        finally:
            if self.kafka_producer is not None:
                self.kafka_producer.close()
                self.kafka_producer = None

    def _get_payload_from_task_id(self, task_id: str) -> dict:
        _, manifest_name, line_marker = task_id.split(";")
        line_marker = int(line_marker)
        _, stream = self.api.object_fetch(
            self.job_show["config"]["params"]["technical_account"],
            self.job_show["config"]["params"]["technical_bucket"],
            manifest_name,
        )
        iterator = iter_lines_from_stream(stream=stream, marker=line_marker)
        _, event = next(iterator)
        stream.close()
        return json.loads(event)

    def _build_event(self, task_id: str, payload: dict) -> dict:
        return {
            "event": EventTypes.XCUTE_CUSTOMER_TASKS,
            "data": {
                "job_id": self.job_id,
                "job_type": BatchReplicatorJob.JOB_TYPE,
                "job_config": self.job_show["config"],
                "tasks": {task_id: payload},
            },
            "when": int(time.time() * 1000000),  # use time in micro seconds
            "request_id": self.reqid,
        }

    def _send_event(self, event: dict) -> None:
        if self.kafka_producer is None:
            self.kafka_producer = KafkaSender(
                self.kafka_endpoint, self.logger, self.conf
            )

        res = self.kafka_producer.send(self.jobs_topic, event, flush=True)
        if res > 0:
            raise Exception("event not sent")

    def _catchup_one_task(self, task_id: str) -> None:
        self.logger.info("catchup task_id=%s", task_id)
        payload = self._get_payload_from_task_id(task_id)
        event = self._build_event(task_id, payload)
        if self.dry_run:
            self.logger.info("event=%s (not sent because dry run enabled)", event)
        else:
            self.logger.debug("send event=%s", event)
            self._send_event(event)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="tool to emit again stuck events of a batch repli job"
    )
    # The xcute customer conf has almost everything we need
    parser.add_argument(
        "--xcute-customer-conf-path",
        type=str,
        dest="conf_path",
        required=True,
        help="absolute path of the xcute customer conf",
    )
    parser.add_argument(
        "--job-id",
        type=str,
        required=True,
        help="id of the batch repli job",
    )
    parser.add_argument(
        "--debug",
        dest="verbose",
        action="store_true",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
    )
    args = parser.parse_args()

    catchup = CatchupBatchRepli(args)
    catchup.run()
