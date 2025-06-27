# Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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

"""Container-related commands"""

from logging import getLogger
from time import sleep
from time import time as now

from oio.cli import Command, Lister, ShowOne
from oio.common.constants import (
    BUCKET_PROP_RATELIMIT,
    DRAINING_STATE_NAME,
    DRAINING_STATE_NEEDED,
    GLOBAL_RATELIMIT_GROUP,
    M2_PROP_BUCKET_NAME,
    M2_PROP_CTIME,
    M2_PROP_DEL_EXC_VERSIONS,
    M2_PROP_DRAINING_STATE,
    M2_PROP_DRAINING_TIMESTAMP,
    M2_PROP_LIFECYCLE_CUSTOM_BUDGET,
    M2_PROP_LIFECYCLE_TIME_BYPASS,
    M2_PROP_OBJECTS,
    M2_PROP_SHARDING_LOWER,
    M2_PROP_SHARDING_MASTER,
    M2_PROP_SHARDING_PREVIOUS_LOWER,
    M2_PROP_SHARDING_PREVIOUS_UPPER,
    M2_PROP_SHARDING_QUEUE,
    M2_PROP_SHARDING_ROOT,
    M2_PROP_SHARDING_STATE,
    M2_PROP_SHARDING_TIMESTAMP,
    M2_PROP_SHARDING_UPPER,
    M2_PROP_SHARDS,
    M2_PROP_STORAGE_POLICY,
    M2_PROP_USAGE,
    M2_PROP_VERSIONING_POLICY,
    OIO_DB_DISABLED,
    OIO_DB_ENABLED,
    OIO_DB_FROZEN,
    OIO_DB_STATUS_NAME,
    SHARDING_STATE_NAME,
)
from oio.common.easy_value import boolean_value, int_value
from oio.common.exceptions import (
    CommandError,
    Conflict,
    NoSuchContainer,
    NotFound,
    OioException,
)
from oio.common.timestamp import Timestamp
from oio.common.utils import depaginate, timeout_to_deadline


class SetPropertyCommandMixin(object):
    """Command setting storage policy or generic property"""

    def patch_parser(self, parser):
        from oio.cli.common.utils import KeyValueAction

        parser.add_argument(
            "--property",
            metavar="<key=value>",
            action=KeyValueAction,
            help="Property to add/update for the container(s)",
        )
        parser.add_argument(
            "--storage-policy",
            "--stgpol",
            metavar="<storage_policy>",
            help="Set the storage policy of the container",
        )
        parser.add_argument(
            "--max-versions",
            "--versioning",
            metavar="<n>",
            type=int,
            help="""Set the versioning policy of the container.
 n<0 is unlimited number of versions.
 n=0 is disabled (cannot overwrite existing object).
 n=1 is suspended (can overwrite existing object).
 n>1 is maximum n versions.
""",
        )
        parser.add_argument(
            "--delete-exceeding-versions",
            metavar="<bool>",
            type=boolean_value,
            help="""Delete exceeding versions when adding a new object
 (only if versioning is enabled).
""",
        )


class ContainerCommandMixin(object):
    """Command taking a container or CID as parameter"""

    def patch_parser_container(self, parser):
        parser.add_argument(
            "--cid",
            dest="is_cid",
            default=False,
            help="Interpret container as a CID",
            action="store_true",
        )
        parser.add_argument(
            "container",
            metavar="<container>",
            help="Name or CID of the container to interact with.\n",
        )

    def take_action_container(self, parsed_args):
        parsed_args.cid = None
        if parsed_args.is_cid:
            parsed_args.cid = parsed_args.container
            parsed_args.container = None


class ContainersCommandMixin(object):
    """Command taking some containers or CIDs as parameter"""

    def patch_parser_container(self, parser):
        parser.add_argument(
            "--cid",
            dest="is_cid",
            default=False,
            help="Interpret containers as a CID",
            action="store_true",
        )
        parser.add_argument(
            "containers",
            metavar="<containers>",
            nargs="+",
            help="Names or CIDs of the containers to interact with.\n",
        )


class CreateBucket(Lister):
    """Create a bucket."""

    log = getLogger(__name__ + ".CreateBucket")

    def get_parser(self, prog_name):
        parser = super(CreateBucket, self).get_parser(prog_name)
        parser.add_argument(
            "--region", help="Ensure the container is created in this region"
        )
        parser.add_argument(
            "buckets", metavar="<bucket-name>", nargs="+", help="New bucket name(s)"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reqid = self.app.request_id(prefix="CLI-bucket-create-")
        results = []
        account = self.app.client_manager.account
        for bucket in parsed_args.buckets:
            success = True
            # We are about to create a root container, reserve its name.
            try:
                self.app.client_manager.storage.bucket.bucket_reserve(
                    bucket, account, region=parsed_args.region, reqid=reqid
                )
            except Exception as exc:
                self.log.error("Failed to reserve bucket name %s: %s", bucket, exc)
                success = False
            if success:
                # Create the root container
                try:
                    system = {M2_PROP_BUCKET_NAME: bucket}
                    created = self.app.client_manager.storage.container_create(
                        account,
                        bucket,
                        region=parsed_args.region,
                        system=system,
                        reqid=reqid,
                    )
                    if not created:
                        self.app.client_manager.storage.container_set_properties(
                            account, bucket, system=system, reqid=reqid
                        )
                except Exception as exc:
                    self.log.error(
                        "Failed to create root container %s: %s", bucket, exc
                    )
                    success = False
                    # Container creation failed, remove reservation
                    try:
                        self.app.client_manager.storage.bucket.bucket_release(
                            bucket, account, region=parsed_args.region, reqid=reqid
                        )
                    except Exception as exc2:
                        self.log.error("Failed to release bucket %s: %s", bucket, exc2)
            if success:
                # Container creation succeeded,
                # confirm reservation by creating the bucket.
                try:
                    self.app.client_manager.storage.bucket.bucket_create(
                        bucket, account, region=parsed_args.region, reqid=reqid
                    )
                except Exception as exc:
                    self.log.error("Failed to create bucket %s: %s", bucket, exc)
                    success = False
                    # Try to rollback by deleting the new container
                    try:
                        if created:
                            self.app.client_manager.storage.container_delete(
                                account, bucket, reqid=reqid
                            )
                        self.app.client_manager.storage.bucket.bucket_release(
                            bucket, account, region=parsed_args.region, reqid=reqid
                        )
                    except Exception as exc2:
                        self.log.error("Failed to release bucket %s: %s", bucket, exc2)
            if success:
                if created:
                    self.log.warning(
                        "The root container %s was created, but it lacks some "
                        "properties (like ACLs) to be compatible with S3",
                        bucket,
                    )
                else:
                    self.log.warning(
                        "The root container %s linked to the bucket, "
                        "but it lacks some properties (like ACLs) "
                        "to be compatible with S3",
                        bucket,
                    )
            results.append((bucket, success))

        return ("Name", "Created"), (r for r in results)


class CreateContainer(SetPropertyCommandMixin, Lister):
    """Create an object container."""

    log = getLogger(__name__ + ".CreateContainer")

    def get_parser(self, prog_name):
        parser = super(CreateContainer, self).get_parser(prog_name)
        self.patch_parser(parser)
        parser.add_argument(
            "--bucket-name",
            help="Declare the container belongs to the specified bucket",
        )
        parser.add_argument(
            "--region", help="Ensure the container is created in this region"
        )
        parser.add_argument(
            "containers",
            metavar="<container-name>",
            nargs="+",
            help="New container name(s)",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reqid = self.app.request_id(prefix="CLI-container-create-")
        properties = parsed_args.property
        system = {}
        if parsed_args.bucket_name:
            system[M2_PROP_BUCKET_NAME] = parsed_args.bucket_name
        if parsed_args.storage_policy is not None:
            system[M2_PROP_STORAGE_POLICY] = parsed_args.storage_policy
        if parsed_args.max_versions is not None:
            system[M2_PROP_VERSIONING_POLICY] = str(parsed_args.max_versions)
        if parsed_args.delete_exceeding_versions is not None:
            system[M2_PROP_DEL_EXC_VERSIONS] = str(
                int(parsed_args.delete_exceeding_versions)
            )

        results = []
        account = self.app.client_manager.account
        if len(parsed_args.containers) > 1:
            results = self.app.client_manager.storage.container_create_many(
                account,
                parsed_args.containers,
                properties=properties,
                region=parsed_args.region,
                system=system,
                reqid=reqid,
            )

        else:
            container = parsed_args.containers[0]
            success = self.app.client_manager.storage.container_create(
                account,
                container,
                properties=properties,
                region=parsed_args.region,
                system=system,
                reqid=reqid,
            )
            results.append((container, success))

        return ("Name", "Created"), (r for r in results)


class SetBucket(Command):
    """Set metadata on a bucket."""

    log = getLogger(__name__ + ".SetBucket")

    def get_parser(self, prog_name):
        parser = super(SetBucket, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of the bucket to query.")
        parser.add_argument(
            "--check-owner",
            default=False,
            help="Check if the bucket owner is the account used",
            action="store_true",
        )
        parser.add_argument("--region", help="Change the bucket region")
        parser.add_argument(
            "--ratelimit",
            metavar="<[group=]value>",
            action="append",
            default=[],
            help="""
            Ratelimit per second (for specific S3 operations group).
            All ratelimit values must be set at the same time, the new values
            replace the old value (option must be repeated in the same command
            if there are several groups).
            """,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reqid = self.app.request_id(prefix="CLI-bucket-set-")
        try:
            account = self.app.client_manager.account
        except CommandError:
            account = None
        bucket_client = self.app.client_manager.storage.bucket
        metadata = {}
        if parsed_args.region:
            metadata["region"] = parsed_args.region
        if parsed_args.ratelimit:
            ratelimit = {}
            for rl in parsed_args.ratelimit:
                group = GLOBAL_RATELIMIT_GROUP
                if "=" in rl:
                    group, rl = rl.split("=", 1)
                if group in ratelimit:
                    raise ValueError("Only one ratelimit per group")
                ratelimit[group] = rl
            metadata[BUCKET_PROP_RATELIMIT] = ratelimit
        bucket_client.bucket_update(
            parsed_args.bucket,
            account=account,
            check_owner=parsed_args.check_owner,
            metadata=metadata,
            to_delete=None,
            reqid=reqid,
        )


class SetContainer(SetPropertyCommandMixin, ContainerCommandMixin, Command):
    """
    Set container properties, storage policy, status or versioning.
    """

    log = getLogger(__name__ + ".SetContainer")

    def get_parser(self, prog_name):
        self.status_value = {
            "enabled": str(OIO_DB_ENABLED),
            "disabled": str(OIO_DB_DISABLED),
            "frozen": str(OIO_DB_FROZEN),
        }

        self.time_bypass_value = {
            "enabled": "1",
            "disabled": "0",
        }

        parser = super(SetContainer, self).get_parser(prog_name)
        self.patch_parser(parser)
        self.patch_parser_container(parser)
        # Same as in CreateContainer class
        parser.add_argument(
            "--bucket-name",
            help="Declare the container belongs to the specified bucket",
        )
        parser.add_argument(
            "--clear",
            dest="clear",
            default=False,
            help="Clear previous properties",
            action="store_true",
        )
        parser.add_argument(
            "--status",
            choices=self.status_value.keys(),
            help="Set container status",
        )
        parser.add_argument(
            "--lifecycle-bypass-time",
            choices=self.time_bypass_value.keys(),
            help="Apply time factor (reducing day duration) for lifecycle actions",
        )
        parser.add_argument(
            "--lifecycle-custom-budget",
            type=int,
            help="Override lifecycle per bucket budget",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        super(SetContainer, self).take_action_container(parsed_args)
        reqid = self.app.request_id(prefix="CLI-container-set-")
        properties = parsed_args.property
        system = {}
        if parsed_args.lifecycle_bypass_time:
            system[M2_PROP_LIFECYCLE_TIME_BYPASS] = self.time_bypass_value[
                parsed_args.lifecycle_bypass_time
            ]
        if parsed_args.lifecycle_custom_budget is not None:
            system[M2_PROP_LIFECYCLE_CUSTOM_BUDGET] = str(
                parsed_args.lifecycle_custom_budget
            )

        if parsed_args.bucket_name:
            system[M2_PROP_BUCKET_NAME] = parsed_args.bucket_name
        if parsed_args.storage_policy is not None:
            system[M2_PROP_STORAGE_POLICY] = parsed_args.storage_policy
        if parsed_args.max_versions is not None:
            system[M2_PROP_VERSIONING_POLICY] = str(parsed_args.max_versions)
        if parsed_args.delete_exceeding_versions is not None:
            system[M2_PROP_DEL_EXC_VERSIONS] = str(
                int(parsed_args.delete_exceeding_versions)
            )
        if parsed_args.status is not None:
            system["sys.status"] = self.status_value[parsed_args.status]

        self.app.client_manager.storage.container_set_properties(
            self.app.client_manager.account,
            parsed_args.container,
            properties,
            clear=parsed_args.clear,
            system=system,
            cid=parsed_args.cid,
            reqid=reqid,
        )


class TouchContainer(ContainersCommandMixin, Command):
    """Touch an object container, triggers asynchronous treatments on it."""

    log = getLogger(__name__ + ".TouchContainer")

    def get_parser(self, prog_name):
        parser = super(TouchContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--recompute",
            dest="recompute",
            default=False,
            help="Recompute the statistics of the specified container",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        reqid = self.app.request_id(prefix="CLI-container-set-")
        if parsed_args.is_cid:
            for container in parsed_args.containers:
                self.app.client_manager.storage.container_touch(
                    self.app.client_manager.account,
                    None,
                    recompute=parsed_args.recompute,
                    cid=container,
                    reqid=reqid,
                )
        else:
            for container in parsed_args.containers:
                self.app.client_manager.storage.container_touch(
                    self.app.client_manager.account,
                    container,
                    recompute=parsed_args.recompute,
                    reqid=reqid,
                )


class DeleteBucket(Lister):
    """Delete a bucket (and only the root container)."""

    log = getLogger(__name__ + ".DeleteBucket")

    def get_parser(self, prog_name):
        parser = super(DeleteBucket, self).get_parser(prog_name)
        parser.add_argument(
            "buckets", metavar="<bucket-name>", nargs="+", help="New bucket name(s)"
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reqid = self.app.request_id(prefix="CLI-bucket-delete-")

        results = []
        account = self.app.client_manager.account
        for bucket in parsed_args.buckets:
            success = True
            try:
                meta = self.app.client_manager.storage.bucket.bucket_show(
                    bucket, account, reqid=reqid
                )
                if meta["containers"] > 1:
                    raise OioException("Too many containers in bucket")
            except NotFound:
                # The bucket no longer exists, but try deleting anyway
                # to really clean everything up
                pass
            except Exception as exc:
                self.log.error(
                    "Failed to fetch bucket information for %s: %s", bucket, exc
                )
                success = False
            if success:
                try:
                    self.app.client_manager.storage.container_delete(
                        account, bucket, reqid=reqid
                    )
                except NoSuchContainer:
                    self.log.info("Root container %s does not exist", bucket)
                except Exception as exc:
                    self.log.error(
                        "Failed to delete root container %s: %s", bucket, exc
                    )
                    success = False
            if success:
                try:
                    for i in range(1, 11):
                        try:
                            self.app.client_manager.storage.bucket.bucket_delete(
                                bucket, account, reqid=reqid
                            )
                            break
                        except Conflict:
                            if i == 10:
                                raise
                            # Wait for the container delete event to process
                            sleep(1)
                except Exception as exc:
                    self.log.error("Failed to delete bucket %s: %s", bucket, exc)
                    success = False
            results.append((bucket, success))

        return ("Name", "Deleted"), (r for r in results)


class DeleteContainer(ContainersCommandMixin, Command):
    """Delete an object container."""

    log = getLogger(__name__ + ".DeleteContainer")

    def get_parser(self, prog_name):
        parser = super(DeleteContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--force",
            default=False,
            help=(
                "Force deletion, even if it contains objects "
                "(the chunks of these objects will not be deleted)"
            ),
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        reqid = self.app.request_id(prefix="CLI-container-create-")
        if parsed_args.is_cid:
            for container in parsed_args.containers:
                self.app.client_manager.storage.container_delete(
                    self.app.client_manager.account,
                    None,
                    cid=container,
                    force=parsed_args.force,
                    reqid=reqid,
                )
        else:
            for container in parsed_args.containers:
                self.app.client_manager.storage.container_delete(
                    self.app.client_manager.account,
                    container,
                    force=parsed_args.force,
                    reqid=reqid,
                )


class FlushContainer(ContainerCommandMixin, Command):
    """Flush an object container."""

    log = getLogger(__name__ + ".FlushContainer")

    def get_parser(self, prog_name):
        parser = super(FlushContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--quickly",
            action="store_true",
            dest="quick",
            help="""Flush container quickly, may put high pressure
 on the event system. Does not work on a sharded bucket
 (but can be called on each shard individually).""",
        )
        parser.add_argument(
            "--limit",
            help="Limit the number of objects per iteration.",
        )
        parser.add_argument(
            "--delay",
            default=0.0,
            type=float,
            help="""Delay between each iteration (default: 0.0s),
 not relevant with "quickly" option.""",
        )
        parser.add_argument(
            "--all-versions",
            action="store_true",
            dest="all_versions",
            help="""Flush all versions (quickly already flushes all versions)""",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        kwargs = {}
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit
        else:
            kwargs["limit"] = int_value(
                self.app.client_manager.sds_conf.get("proxy.bulk.max.delete_many"), 100
            )
        if parsed_args.delay:
            kwargs["delay"] = parsed_args.delay

        self.take_action_container(parsed_args)
        reqid = self.app.request_id(prefix="CLI-container-flush-")
        if parsed_args.cid is None:
            account = self.app.client_manager.account
            container = parsed_args.container
        else:
            account, container = self.app.client_manager.storage.resolve_cid(
                parsed_args.cid,
                reqid=reqid,
                timeout=self.app.options.timeout,
            )
        self.app.client_manager.storage.container_flush(
            account,
            container,
            fast=parsed_args.quick,
            all_versions=parsed_args.all_versions,
            timeout=self.app.options.timeout,
            reqid=reqid,
            **kwargs,
        )


class DrainContainer(ContainersCommandMixin, Command):
    """
    Set the draining state to 'needed'. Draining is not performed here,
    the meta2-crawler will do it on his next pass.
    """

    log = getLogger(__name__ + ".DrainContainer")

    def get_parser(self, prog_name):
        parser = super(DrainContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        system = {
            M2_PROP_DRAINING_STATE: str(DRAINING_STATE_NEEDED),
            M2_PROP_DRAINING_TIMESTAMP: str(round(now() * 1000000)),
        }
        for container in parsed_args.containers:
            account = self.app.client_manager.account
            cid = None
            if parsed_args.is_cid:
                cid = container

            self.app.client_manager.storage.container_set_properties(
                account,
                container,
                cid=cid,
                system=system,
                propagate_to_shards=True,
                reqid=self.app.request_id(prefix="CLI-container-drain-"),
            )


class ShowBucket(ShowOne):
    """Display information about a bucket."""

    log = getLogger(__name__ + ".ShowBucket")

    def get_parser(self, prog_name):
        parser = super(ShowBucket, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of the bucket to query.")
        parser.add_argument(
            "--check-owner",
            default=False,
            help="Check if the bucket owner is the account used",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        try:
            account = self.app.client_manager.account
        except CommandError:
            account = None
        bucket_client = self.app.client_manager.storage.bucket
        data = bucket_client.bucket_show(
            parsed_args.bucket,
            account=account,
            check_owner=parsed_args.check_owner,
            details=True,
            reqid=self.app.request_id(prefix="CLI-bucket-show-"),
        )
        if parsed_args.formatter == "table":
            from oio.common.easy_value import convert_size, convert_timestamp

            data["bytes"] = convert_size(data["bytes"], unit="iB")
            if "ctime" in data:
                data["ctime"] = convert_timestamp(data.get("ctime", 0.0))
            data["mtime"] = convert_timestamp(data.get("mtime", 0.0))
        return zip(*sorted(data.items()))


class ShowContainer(ContainerCommandMixin, ShowOne):
    """Display information about an object container."""

    log = getLogger(__name__ + ".ShowContainer")

    def get_parser(self, prog_name):
        parser = super(ShowContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--extra-counters",
            default=False,
            help="Get some extra counters (nb drained objects, ...)",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        from oio.common.easy_value import convert_size, convert_timestamp

        self.log.debug("take_action(%s)", parsed_args)

        account = self.app.client_manager.account
        self.take_action_container(parsed_args)
        # The command is named 'show' but we must call
        # container_get_properties() because container_show() does
        # not return system properties (and we need them).
        data = self.app.client_manager.storage.container_get_properties(
            account,
            parsed_args.container,
            cid=parsed_args.cid,
            admin_mode=True,
            params={"urgent": 1},
            extra_counters=parsed_args.extra_counters,
            reqid=self.app.request_id(prefix="CLI-container-show-"),
        )
        sys = data["system"]
        ctime = float(sys[M2_PROP_CTIME]) / 1000000.0
        bytes_usage = sys.get(M2_PROP_USAGE, 0)
        objects = sys.get(M2_PROP_OBJECTS, 0)
        shards = sys.get(M2_PROP_SHARDS, 0)
        if parsed_args.formatter == "table":
            ctime = convert_timestamp(ctime)
            bytes_usage = convert_size(int(bytes_usage), unit="iB")
            objects = convert_size(int(objects))
            shards = convert_size(int(shards))
        info = {
            "account": sys["sys.account"],
            "base_name": sys["sys.name"],
            "container": sys["sys.user.name"],
            "ctime": ctime,
            "bytes_usage": bytes_usage,
            "objects": objects,
            "shards": shards,
            "storage_policy": sys.get(M2_PROP_STORAGE_POLICY, "Namespace default"),
            "max_versions": sys.get(M2_PROP_VERSIONING_POLICY, "Namespace default"),
            "status": OIO_DB_STATUS_NAME.get(sys.get("sys.status"), "Unknown"),
        }
        for key, value in sys.items():
            if key.startswith(M2_PROP_USAGE + "."):
                key = f"bytes_usage.{key[len(M2_PROP_USAGE + '.') :]}"
                if parsed_args.formatter == "table":
                    value = convert_size(int(value), unit="iB")
            elif key.startswith(M2_PROP_OBJECTS + "."):
                key = f"objects.{key[len(M2_PROP_OBJECTS + '.') :]}"
                if parsed_args.formatter == "table":
                    value = convert_size(int(value))
            else:
                continue
            info[key] = value

        if M2_PROP_SHARDING_STATE in sys:
            sharding_state = sys[M2_PROP_SHARDING_STATE]
            try:
                sharding_state = SHARDING_STATE_NAME[int(sharding_state)]
            except (ValueError, KeyError, TypeError):
                sharding_state = "Unknown"
            info["sharding.state"] = sharding_state
            sharding_timestamp = sys.get(M2_PROP_SHARDING_TIMESTAMP)
            if sharding_timestamp is None:
                self.log.warning("Missing sharding timestamp")
            elif parsed_args.formatter == "table":
                sharding_timestamp = convert_timestamp(sharding_timestamp)
            info["sharding.timestamp"] = sharding_timestamp

        if M2_PROP_SHARDING_ROOT in sys:
            info["sharding.root"] = sys.get(M2_PROP_SHARDING_ROOT)
            sharding_lower = sys.get(M2_PROP_SHARDING_LOWER)
            if not sharding_lower:
                self.log.warning("Missing sharding lower")
            if sharding_lower[0] == ">":
                sharding_lower = sharding_lower[1:]
            else:
                self.log.warning("Wrong format for sharding lower")
            info["sharding.lower"] = sharding_lower
            sharding_upper = sys.get(M2_PROP_SHARDING_UPPER)
            if not sharding_upper:
                self.log.warning("Missing sharding upper")
            if sharding_upper[0] == "<":
                sharding_upper = sharding_upper[1:]
            else:
                self.log.warning("Wrong format for sharding upper")
            info["sharding.upper"] = sharding_upper
            sharding_previous_lower = sys.get(M2_PROP_SHARDING_PREVIOUS_LOWER)
            if sharding_previous_lower:
                if sharding_previous_lower[0] == ">":
                    sharding_previous_lower = sharding_previous_lower[1:]
                else:
                    self.log.warning("Wrong format for previous sharding lower")
                info["sharding.lower.previous"] = sharding_previous_lower
            sharding_previous_upper = sys.get(M2_PROP_SHARDING_PREVIOUS_UPPER)
            if sharding_previous_upper:
                if sharding_previous_upper[0] == "<":
                    sharding_previous_upper = sharding_previous_upper[1:]
                else:
                    self.log.warning("Wrong format for previous sharding upper")
                info["sharding.upper.previous"] = sharding_previous_upper
            if M2_PROP_SHARDING_MASTER in sys:
                info["sharding.master"] = sys[M2_PROP_SHARDING_MASTER]
            if M2_PROP_SHARDING_QUEUE in sys:
                info["sharding.queue"] = sys[M2_PROP_SHARDING_QUEUE]

        if M2_PROP_DRAINING_STATE in sys:
            draining_state = sys[M2_PROP_DRAINING_STATE]
            try:
                draining_state = DRAINING_STATE_NAME[int(draining_state)]
            except (ValueError, KeyError, TypeError):
                draining_state = "Unknown"
            info["draining.state"] = draining_state
            draining_timestamp = sys.get(M2_PROP_DRAINING_TIMESTAMP)
            if draining_timestamp is not None:
                if parsed_args.formatter == "table":
                    draining_timestamp = convert_timestamp(draining_timestamp)
                info["draining.timestamp"] = draining_timestamp

        objects_drained = sys.get("extra_counter.drained")
        if objects_drained:
            if parsed_args.formatter == "table":
                objects_drained = convert_size(int(objects_drained))
            info["objects_drained"] = objects_drained

        lifecycle_time_bypass = sys.get(M2_PROP_LIFECYCLE_TIME_BYPASS)
        if lifecycle_time_bypass:
            info["lifecycle.time_bypass"] = (
                "Enabled" if lifecycle_time_bypass == "1" else "Disabled"
            )

        lifecycle_custom_budget = int_value(
            sys.get(M2_PROP_LIFECYCLE_CUSTOM_BUDGET), -1
        )
        if lifecycle_custom_budget != -1:
            info["lifecycle.custom_budget"] = lifecycle_custom_budget

        for k in ("stats.page_count", "stats.freelist_count", "stats.page_size"):
            info[k] = int_value(sys.get(k), 0)
        db_size = info["stats.page_count"] * info["stats.page_size"]
        if parsed_args.formatter == "table":
            db_size = convert_size(int(db_size), unit="iB")
        info["stats.db_size"] = db_size
        wasted = info["stats.freelist_count"] / info["stats.page_count"]
        wasted_bytes = info["stats.freelist_count"] * info["stats.page_size"]
        info["stats.space_wasted"] = "%5.2f%% (est. %s)" % (
            wasted * 100,
            convert_size(wasted_bytes),
        )

        bucket = sys.get(M2_PROP_BUCKET_NAME, None)
        if bucket is not None:
            info["bucket"] = bucket
        delete_exceeding = sys.get(M2_PROP_DEL_EXC_VERSIONS, None)
        if delete_exceeding is not None:
            info["delete_exceeding_versions"] = delete_exceeding != "0"
        for k, v in data["properties"].items():
            info["meta." + k] = v
        return list(zip(*sorted(info.items())))


class ListBuckets(Lister):
    """Get the list of buckets owned by an account."""

    log = getLogger(__name__ + ".ListBuckets")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListBuckets, self).get_parser(prog_name)
        parser.add_argument(
            "--prefix", metavar="<prefix>", help="Filter list using <prefix>"
        )
        parser.add_argument(
            "--region",
            metavar="<region>",
            help="Filter list by selecting buckets belonging to the <region>",
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging")
        parser.add_argument(
            "--end-marker", metavar="<end-marker>", help="End marker for paging"
        )
        parser.add_argument(
            "--limit", metavar="<limit>", help="Limit the number of buckets returned"
        )
        parser.add_argument(
            "--no-paging",
            "--full",
            dest="full_listing",
            default=False,
            help="List all buckets without paging (and set output format to 'value')",
            action=ValueFormatStoreTrueAction,
        )
        parser.add_argument(
            "--versioning",
            action="store_true",
            dest="versioning",
            help="Display the versioning state of each bucket",
        )
        parser.add_argument(
            "--human",
            action="store_true",
            dest="humanize",
            default=False,
            help="Display bytes size in a human-readable format",
        )
        return parser

    def take_action(self, parsed_args):
        from oio.common.easy_value import convert_size

        self.log.debug("take_action(%s)", parsed_args)

        kwargs = {}
        if parsed_args.prefix:
            kwargs["prefix"] = parsed_args.prefix
        if parsed_args.region:
            kwargs["region"] = parsed_args.region
        if parsed_args.marker:
            kwargs["marker"] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs["end_marker"] = parsed_args.end_marker
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit

        account = self.app.client_manager.account
        acct_client = self.app.client_manager.storage.account
        storage = self.app.client_manager.storage
        reqid = self.app.request_id(prefix="CLI-bucket-list-")

        if parsed_args.full_listing:
            listing = depaginate(
                acct_client.bucket_list,
                listing_key=lambda x: x["listing"],
                marker_key=lambda x: x.get("next_marker"),
                truncated_key=lambda x: x["truncated"],
                account=account,
                reqid=reqid,
                **kwargs,
            )
        else:
            acct_meta = acct_client.bucket_list(account, reqid=reqid, **kwargs)
            listing = acct_meta["listing"]

        columns = ("Name", "Objects", "Bytes", "Mtime", "Region")

        def versioning(bucket):
            try:
                data = storage.container_get_properties(account, bucket, reqid=reqid)
            except NoSuchContainer:
                self.log.info("Bucket %s does not exist", bucket)
                return "Error"

            sys = data["system"]
            # WARN it doe not reflect namespace versioning if enabled
            status = sys.get(M2_PROP_VERSIONING_POLICY, None)
            if status is None or int(status) == 0:
                return "Suspended"
            else:
                return "Enabled"

        if parsed_args.versioning:
            columns += ("Versioning",)

            def enrich(listing):
                for v in listing:
                    v["versioning"] = versioning(v["name"])
                    yield v

            listing = enrich(listing)

        if parsed_args.humanize:

            def humanize(listing):
                for v in listing:
                    v["bytes"] = "{:>10}".format(convert_size(v["bytes"], unit="iB"))
                    yield v

            listing = humanize(listing)

        return columns, ([v[k.lower()] for k in columns] for v in listing)


class ListContainer(Lister):
    """List containers."""

    log = getLogger(__name__ + ".ListContainer")

    def get_parser(self, prog_name):
        from oio.cli.common.utils import ValueFormatStoreTrueAction

        parser = super(ListContainer, self).get_parser(prog_name)
        parser.add_argument(
            "--prefix", metavar="<prefix>", help="Filter list using <prefix>"
        )
        parser.add_argument(
            "--region",
            metavar="<region>",
            help="""
                Filter list by selecting containers belonging to the <region>
                """,
        )
        parser.add_argument(
            "--bucket",
            metavar="<bucket>",
            help="""
                Filter list by selecting containers belonging to the <bucket>
                """,
        )
        parser.add_argument("--marker", metavar="<marker>", help="Marker for paging")
        parser.add_argument(
            "--end-marker", metavar="<end-marker>", help="End marker for paging"
        )
        parser.add_argument(
            "--limit", metavar="<limit>", help="Limit the number of containers returned"
        )
        parser.add_argument(
            "--no-paging",
            "--full",
            dest="full_listing",
            default=False,
            help=(
                "List all containers without paging (and set output format to 'value')"
            ),
            action=ValueFormatStoreTrueAction,
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        from oio.common.utils import cid_from_name

        kwargs = {}
        if parsed_args.prefix:
            kwargs["prefix"] = parsed_args.prefix
        if parsed_args.region:
            kwargs["region"] = parsed_args.region
        if parsed_args.bucket:
            kwargs["bucket"] = parsed_args.bucket
        if parsed_args.marker:
            kwargs["marker"] = parsed_args.marker
        if parsed_args.end_marker:
            kwargs["end_marker"] = parsed_args.end_marker
        if parsed_args.limit:
            kwargs["limit"] = parsed_args.limit

        account = self.app.client_manager.account
        acct_client = self.app.client_manager.storage.account
        reqid = self.app.request_id(prefix="CLI-container-list-")

        if parsed_args.full_listing:
            listing = depaginate(
                acct_client.container_list,
                listing_key=lambda x: x["listing"],
                item_key=lambda x: x,
                marker_key=lambda x: x["next_marker"],
                truncated_key=lambda x: x["truncated"],
                account=account,
                reqid=reqid,
                **kwargs,
            )
        else:
            acct_meta = acct_client.container_list(account, reqid=reqid, **kwargs)
            listing = acct_meta["listing"]

        columns = ("Name", "Count", "Bytes", "Mtime", "CID")
        return columns, (
            (v[0], v[1], v[2], v[4], cid_from_name(account, v[0])) for v in listing
        )


class UnsetContainer(ContainerCommandMixin, Command):
    """Unset container properties."""

    log = getLogger(__name__ + ".UnsetContainer")

    def get_parser(self, prog_name):
        parser = super(UnsetContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--bucket-name",
            action="store_true",
            help="Declare the container no more belongs to any bucket",
        )
        parser.add_argument(
            "--property",
            metavar="<key>",
            action="append",
            default=[],
            help="Property to remove from container",
        )
        parser.add_argument(
            "--storage-policy",
            "--stgpol",
            action="store_true",
            help="Reset the storage policy of the container to the namespace default",
        )
        parser.add_argument(
            "--max-versions",
            "--versioning",
            action="store_true",
            help=(
                "Reset the versioning policy of the container to the namespace default"
            ),
        )
        parser.add_argument(
            "--delete-exceeding-versions",
            action="store_true",
            help="Reset the deletion of the exceeding versions to the default value",
        )

        parser.add_argument(
            "--lifecycle-custom-budget",
            action="store_true",
            help="Reset the lifecycle per bucket budget to the namespace default",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        self.take_action_container(parsed_args)
        properties = parsed_args.property
        system = {}
        if parsed_args.bucket_name:
            system[M2_PROP_BUCKET_NAME] = ""
        if parsed_args.storage_policy:
            system[M2_PROP_STORAGE_POLICY] = ""
        if parsed_args.max_versions:
            system[M2_PROP_VERSIONING_POLICY] = ""
        if parsed_args.delete_exceeding_versions:
            system[M2_PROP_DEL_EXC_VERSIONS] = ""
        if parsed_args.lifecycle_custom_budget:
            system[M2_PROP_LIFECYCLE_CUSTOM_BUDGET] = ""
        reqid = self.app.request_id(prefix="CLI-container-unset-")

        if properties or not system:
            self.app.client_manager.storage.container_del_properties(
                self.app.client_manager.account,
                parsed_args.container,
                properties,
                cid=parsed_args.cid,
                reqid=reqid,
            )
        if system:
            self.app.client_manager.storage.container_set_properties(
                self.app.client_manager.account,
                parsed_args.container,
                system=system,
                cid=parsed_args.cid,
                reqid=reqid,
            )


class UnsetBucket(Command):
    """Unset metadata from a bucket."""

    log = getLogger(__name__ + ".UnsetBucket")

    def get_parser(self, prog_name):
        parser = super(UnsetBucket, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of the bucket to query.")
        parser.add_argument(
            "--check-owner",
            default=False,
            help="Check if the bucket owner is the account used",
            action="store_true",
        )
        parser.add_argument(
            "--ratelimit",
            default=False,
            help="Use the default value",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        try:
            account = self.app.client_manager.account
        except CommandError:
            account = None
        bucket_client = self.app.client_manager.storage.bucket
        to_delete = []
        if parsed_args.ratelimit is not None:
            to_delete.append(BUCKET_PROP_RATELIMIT)
        bucket_client.bucket_update(
            parsed_args.bucket,
            account=account,
            check_owner=parsed_args.check_owner,
            metadata=None,
            to_delete=to_delete,
            reqid=self.app.request_id(prefix="CLI-bucket-unset-"),
        )


class SaveContainer(ContainerCommandMixin, Command):
    """Save all objects of a container locally."""

    log = getLogger(__name__ + ".SaveContainer")

    def get_parser(self, prog_name):
        parser = super(SaveContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        return parser

    def take_action(self, parsed_args):
        import os

        self.log.debug("take_action(%s)", parsed_args)
        self.take_action_container(parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container
        cid = parsed_args.cid
        reqid = self.app.request_id(prefix="CLI-container-save-")
        objs = self.app.client_manager.storage.object_list(
            account, container, cid=cid, reqid=reqid
        )

        for obj in objs["objects"]:
            obj_name = obj["name"]
            reqid = self.app.request_id(prefix="CLI-container-save-")
            _, stream = self.app.client_manager.storage.object_fetch(
                account, container, obj_name, properties=False, cid=cid, reqid=reqid
            )

            if not os.path.exists(os.path.dirname(obj_name)):
                if len(os.path.dirname(obj_name)) > 0:
                    os.makedirs(os.path.dirname(obj_name))
            with open(obj_name, "wb") as f:
                for chunk in stream:
                    f.write(chunk)


class LocateContainer(ContainerCommandMixin, ShowOne):
    """Locate the services in charge of a container."""

    log = getLogger(__name__ + ".LocateContainer")

    def get_parser(self, prog_name):
        parser = super(LocateContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        self.take_action_container(parsed_args)

        account = self.app.client_manager.account
        container = parsed_args.container
        cid = parsed_args.cid
        reqid = self.app.request_id(prefix="CLI-container-locate-")
        m2_sys = self.app.client_manager.storage.container_get_properties(
            account, container, cid=cid, reqid=reqid
        )["system"]

        data_dir = self.app.client_manager.storage.directory.list(
            account, container, cid=cid
        )

        info = {
            "account": m2_sys["sys.account"],
            "base_name": m2_sys["sys.name"],
            "name": m2_sys["sys.user.name"],
            "meta0": list(),
            "meta1": list(),
            "meta2": list(),
            "meta2.sys.peers": list(),
            "status": OIO_DB_STATUS_NAME.get(m2_sys.get("sys.status"), "Unknown"),
        }

        for d in data_dir["srv"]:
            if d["type"] == "meta2":
                info["meta2"].append(d["host"])

        for peer in m2_sys.get("sys.peers", "Unknown").split(","):
            info["meta2.sys.peers"].append(peer)

        for d in data_dir["dir"]:
            if d["type"] == "meta0":
                info["meta0"].append(d["host"])
            if d["type"] == "meta1":
                info["meta1"].append(d["host"])

        for stype in ["meta0", "meta1", "meta2", "meta2.sys.peers"]:
            info[stype] = ", ".join(info[stype])
        return list(zip(*sorted(info.items())))


class PurgeContainer(ContainerCommandMixin, Command):
    """Purge exceeding object versions."""

    log = getLogger(__name__ + ".PurgeContainer")

    def get_parser(self, prog_name):
        parser = super(PurgeContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--max-versions",
            metavar="<n>",
            type=int,
            help="""The number of versions to keep
 (overrides the container configuration).
 n<0 is unlimited number of versions (purge only deleted aliases).
 n=0 is 1 version.
 n>0 is n versions.
""",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        self.take_action_container(parsed_args)

        account = self.app.client_manager.account
        self.app.client_manager.storage.container_purge(
            account,
            parsed_args.container,
            maxvers=parsed_args.max_versions,
            cid=parsed_args.cid,
            reqid=self.app.request_id(prefix="CLI-container-purge-"),
        )


class RefreshBucket(Command):
    """
    Refresh the counters of a bucket.

    Reset all statistics counters and recompute them by summing
    the counters of all shards (containers).
    """

    log = getLogger(__name__ + ".RefreshBucket")

    def get_parser(self, prog_name):
        parser = super(RefreshBucket, self).get_parser(prog_name)
        parser.add_argument("bucket", help="Name of the bucket to refresh.")
        parser.add_argument(
            "--check-owner",
            default=False,
            help="Check if the bucket owner is the account used",
            action="store_true",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)

        try:
            account = self.app.client_manager.account
        except CommandError:
            account = None
        bucket_client = self.app.client_manager.storage.bucket
        bucket_client.bucket_refresh(
            parsed_args.bucket,
            account=account,
            check_owner=parsed_args.check_owner,
            reqid=self.app.request_id(prefix="CLI-bucket-refresh-"),
        )


class RefreshContainer(ContainerCommandMixin, Command):
    """Refresh counters of an account (triggers asynchronous treatments)"""

    log = getLogger(__name__ + ".RefreshContainer")

    def get_parser(self, prog_name):
        parser = super(RefreshContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        self.take_action_container(parsed_args)
        reqid = self.app.request_id(prefix="CLI-container-refresh-")
        if parsed_args.cid is None:
            account = self.app.client_manager.account
            container = parsed_args.container
        else:
            account, container = self.app.client_manager.storage.resolve_cid(
                parsed_args.cid,
                reqid=reqid,
            )
        self.app.client_manager.storage.container_refresh(
            account=account,
            container=container,
            reqid=reqid,
        )


class SnapshotContainer(ContainerCommandMixin, Lister):
    """
    Take a snapshot of a container.

    Create a separate database containing all information about the contents
    from the original database, but with copies of the chunks at the time
    of the snapshot. This new database is frozen (you cannot write into it).

    Pay attention to the fact that the source container is frozen during
    the snapshot capture. The capture may take some time, depending on
    the number of objects hosted by the container.
    """

    log = getLogger(__name__ + ".SnapshotContainer")

    def get_parser(self, prog_name):
        parser = super(SnapshotContainer, self).get_parser(prog_name)
        self.patch_parser_container(parser)
        parser.add_argument(
            "--dst-account",
            metavar="<account>",
            help=(
                "The account where the snapshot should be created. "
                "By default the same account as the snapshotted container."
            ),
        )
        parser.add_argument(
            "--dst-container",
            metavar="<container>",
            help=(
                "The name of the container hosting the snapshot. "
                "By default the name of the snapshotted container "
                "suffixed by a timestamp."
            ),
        )
        parser.add_argument(
            "--chunk-batch-size",
            metavar="<size>",
            default=100,
            help="The number of chunks updated at the same time.",
        )
        # FIXME(FVE): do not override --timeout
        # find a way to set the default in self.app.parser
        parser.add_argument(
            "--timeout",
            default=60.0,
            type=float,
            help="Timeout for the operation (default: 60.0s).",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        self.take_action_container(parsed_args)
        cid = parsed_args.cid
        reqid = self.app.request_id(prefix="CLI-container-snapshot-")
        if cid is None:
            account = self.app.client_manager.account
            container = parsed_args.container
        else:
            account, container = self.app.client_manager.storage.resolve_cid(
                cid,
                reqid=reqid,
            )
        # FIXME(FVE): use self.app.options.timeout
        deadline = timeout_to_deadline(parsed_args.timeout)
        dst_account = parsed_args.dst_account or account
        dst_container = parsed_args.dst_container or (
            container + "-" + Timestamp().normal
        )
        batch_size = parsed_args.chunk_batch_size

        self.app.client_manager.storage.container_snapshot(
            account,
            container,
            dst_account,
            dst_container,
            batch_size=batch_size,
            deadline=deadline,
            reqid=reqid,
        )
        lines = [(dst_account, dst_container, "OK")]
        return ("Account", "Container", "Status"), lines
