# Copyright (C) 2019-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021-2025 OVH SAS
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

from datetime import datetime

from oio.cli import Lister, ShowOne, flat_dict_from_dict
from oio.cli.admin.xcute import CustomerCommand, XcuteCommand
from oio.cli.common.utils import KeyValueAction
from oio.common.utils import depaginate
from oio.xcute.common.job import XcuteJobStatus
from oio.xcute.jobs import JOB_TYPES


class JobList(XcuteCommand, Lister):
    """
    List jobs sorted by descending creation date.
    """

    columns = ("ID", "Status", "Type", "Service ID", "Lock", "Progress")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--date",
            help="Filter jobs with the specified job date (%%Y-%%m-%%dT%%H:%%M:%%S)",
        )
        parser.add_argument(
            "--results",
            action="store_true",
            help="Display an extra column with jobs results and errors",
        )
        parser.add_argument(
            "--status",
            choices=XcuteJobStatus.ALL,
            help="Filter jobs with the specified job status",
        )
        parser.add_argument(
            "--type",
            choices=JOB_TYPES.keys(),
            help="Filter jobs with the specified job type",
        )
        parser.add_argument(
            "--lock", help="Filter jobs with the specified job lock (wildcards allowed)"
        )
        parser.add_argument(
            "--limit",
            metavar="<limit>",
            type=int,
            default=1000,
            help="Limit the number of results (1000 by default)",
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging")
        parser.add_argument(
            "--no-paging",
            dest="no_paging",
            default=False,
            help="List all elements without paging (and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        return parser

    def _build_list_prefix(self, parsed_args):
        prefix = None
        if parsed_args.date:
            datetime_input_format = ""
            datetime_output_format = ""
            datetime_info_split = parsed_args.date.split("T", 1)
            date_info_split = datetime_info_split[0].split("-", 2)
            if len(date_info_split) > 0:
                datetime_input_format += "%Y"
                datetime_output_format += "%Y"
            if len(date_info_split) > 1:
                datetime_input_format += "-%m"
                datetime_output_format += "%m"
            if len(date_info_split) > 2:
                datetime_input_format += "-%d"
                datetime_output_format += "%d"
            if len(datetime_info_split) > 1:
                if len(date_info_split) != 3:
                    raise ValueError("Wrong date format")
                time_info_split = datetime_info_split[1].split(":", 2)
                if len(time_info_split) > 0:
                    datetime_input_format += "T%H"
                    datetime_output_format += "%H"
                if len(time_info_split) > 1:
                    datetime_input_format += ":%M"
                    datetime_output_format += "%M"
                if len(time_info_split) > 2:
                    datetime_input_format += ":%S"
                    datetime_output_format += "%S"
            try:
                job_date = datetime.strptime(parsed_args.date, datetime_input_format)
            except ValueError:
                raise ValueError("Wrong date format")
            prefix = job_date.strftime(datetime_output_format)
        return prefix

    def _take_action(self, parsed_args):
        prefix = self._build_list_prefix(parsed_args)

        if parsed_args.no_paging:
            jobs = depaginate(
                self.xcute.job_list,
                prefix=prefix,
                limit=parsed_args.limit,
                marker=parsed_args.marker,
                job_status=parsed_args.status,
                job_type=parsed_args.type,
                job_lock=parsed_args.lock,
                listing_key=lambda x: x["jobs"],
                marker_key=lambda x: x.get("next_marker"),
                truncated_key=lambda x: x.get("truncated"),
            )
        else:
            jobs_list = self.xcute.job_list(
                prefix=prefix,
                limit=parsed_args.limit,
                marker=parsed_args.marker,
                job_status=parsed_args.status,
                job_type=parsed_args.type,
                job_lock=parsed_args.lock,
            )
            jobs = jobs_list["jobs"]

        for job_info in jobs:
            job_main_info = job_info["job"]
            job_tasks = job_info["tasks"]
            job_errors = job_info["errors"]
            try:
                progress = job_tasks["processed"] * 100.0 / job_tasks["total"]
            except ZeroDivisionError:
                if job_tasks["is_total_temp"]:
                    progress = 0.0
                else:
                    progress = 100.0
            status = job_main_info["status"]
            if status == XcuteJobStatus.FINISHED and job_errors.get("total", 0) > 0:
                status += "_WITH_ERRORS"
            service_id = job_info["config"].get("params", {}).get("service_id", "n/a")
            entry = (
                job_main_info["id"],
                status,
                job_main_info["type"],
                service_id,
                job_main_info.get("lock"),
                f"{progress:.2f}%",
            )
            if parsed_args.results:
                job_errors.pop("total", None)
                entry += (job_errors, job_info.get("results", {}))
            yield entry

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        if parsed_args.results:
            self.columns += (
                "Errors",
                "Results",
            )

        return self.columns, self._take_action(parsed_args)


class CustomerJobList(CustomerCommand, JobList):
    pass


class JobShow(XcuteCommand, ShowOne):
    """
    Get all information about the job.
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument("job_id", metavar="<job_id>", help="ID of the job to show")
        parser.add_argument(
            "--raw", action="store_true", help="Display raw information"
        )
        return parser

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        job_info = self.xcute.job_show(parsed_args.job_id)

        if not parsed_args.raw:
            job_main_info = job_info["job"]
            duration = job_main_info["mtime"] - job_main_info["ctime"]
            job_main_info["duration"] = duration

            job_tasks = job_info["tasks"]
            try:
                sent_percent = job_tasks["sent"] * 100.0 / job_tasks["total"]
            except ZeroDivisionError:
                if job_tasks["is_total_temp"]:
                    sent_percent = 0.0
                else:
                    sent_percent = 100.0
            job_tasks["sent_percent"] = sent_percent
            job_tasks["processed_per_second"] = job_tasks["processed"] / (
                duration or 0.00001
            )
            try:
                processed_percent = job_tasks["processed"] * 100.0 / job_tasks["total"]
            except ZeroDivisionError:
                if job_tasks["is_total_temp"]:
                    processed_percent = 0.0
                else:
                    processed_percent = 100.0
            job_tasks["processed_percent"] = processed_percent

            if parsed_args.formatter == "table":
                if not job_tasks["all_sent"]:
                    if job_tasks["is_total_temp"]:
                        total_state = "estimating"
                    else:
                        total_state = "estimated"
                    job_tasks["total"] = "%d (%s)" % (job_tasks["total"], total_state)

            job_info.pop("orchestrator", None)
            job_main_info.pop("request_pause", None)
            job_tasks.pop("all_sent", None)
            job_tasks.pop("last_sent", None)
            job_tasks.pop("is_total_temp", None)
            job_tasks.pop("total_marker", None)

        return zip(*sorted(flat_dict_from_dict(parsed_args, job_info).items()))


class CustomerJobShow(CustomerCommand, JobShow):
    pass


class JobPause(XcuteCommand, Lister):
    """
    Pause the jobs.
    """

    columns = ("ID", "Paused")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "job_ids", nargs="+", metavar="<job_id>", help="IDs of the job to pause"
        )
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            paused = True
            try:
                self.xcute.job_pause(job_id)
            except Exception as exc:
                self.logger.error("Failed to paused job %s: %s", job_id, exc)
                paused = False
            yield (job_id, paused)

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)


class CustomerJobPause(CustomerCommand, JobPause):
    pass


class JobResume(XcuteCommand, Lister):
    """
    Resume the jobs.
    """

    columns = ("ID", "Resumed")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "job_ids",
            nargs="+",
            metavar="<job_id>",
            help="IDs of the job to to resume",
        )
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            resumed = True
            try:
                self.xcute.job_resume(job_id)
            except Exception as exc:
                self.logger.error("Failed to resumed job %s: %s", job_id, exc)
                resumed = False
            yield (job_id, resumed)

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)


class CustomerJobResume(CustomerCommand, JobResume):
    pass


class JobUpdate(XcuteCommand, ShowOne):
    """
    Update job configuration.
    """

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "job_id", metavar="<job_id>", help="ID of the job to update."
        )
        parser.add_argument(
            "--tasks-per-second", type=int, help="Max tasks per second."
        )
        parser.add_argument(
            "--tasks-batch-size", type=int, help="Max tasks batch size."
        )
        parser.add_argument(
            "-p",
            "--param",
            dest="params",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Configuration parameter to update",
        )
        return parser

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        job_config = dict()
        if parsed_args.tasks_per_second is not None:
            job_config["tasks_per_second"] = parsed_args.tasks_per_second
        if parsed_args.tasks_batch_size is not None:
            job_config["tasks_batch_size"] = parsed_args.tasks_batch_size
        if parsed_args.params is not None:
            job_config["params"] = parsed_args.params
        new_job_config = self.xcute.job_update(parsed_args.job_id, job_config)

        return zip(*sorted(flat_dict_from_dict(parsed_args, new_job_config).items()))


class CustomerJobUpdate(CustomerCommand, JobUpdate):
    pass


class JobAbort(XcuteCommand, Lister):
    """
    Abort the jobs.
    """

    columns = ("ID", "Aborted")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "job_ids",
            nargs="+",
            metavar="<job_id>",
            help="IDs of the job to to abort",
        )
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            aborted = True
            try:
                self.xcute.job_abort(job_id)
            except Exception as exc:
                self.logger.error("Failed to aborted job %s: %s", job_id, exc)
                aborted = False
            yield (job_id, aborted)

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)


class CustomerJobAbort(CustomerCommand, JobAbort):
    pass


class JobDelete(XcuteCommand, Lister):
    """
    Delete all information about the jobs.
    """

    columns = ("ID", "Deleted")

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "job_ids", nargs="+", metavar="<job_id>", help="IDs of the job to delete"
        )
        return parser

    def _take_action(self, parsed_args):
        for job_id in parsed_args.job_ids:
            deleted = True
            try:
                self.xcute.job_delete(job_id)
            except Exception as exc:
                self.logger.error("Failed to deleted job %s: %s", job_id, exc)
                deleted = False
            yield (job_id, deleted)

    def take_action(self, parsed_args):
        self.logger.debug("take_action(%s)", parsed_args)

        return self.columns, self._take_action(parsed_args)


class CustomerJobDelete(CustomerCommand, JobDelete):
    pass
