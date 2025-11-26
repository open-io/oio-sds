# Copyright (C) 2017-2020 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2022-2025 OVH SAS
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

"""Lifecycle-related commands"""

from logging import getLogger

from oio.cli import Command, Lister
from oio.common.exceptions import LifecycleNotFound
from oio.container.lifecycle import ContainerLifecycle
from oio.lifecycle.metrics import LifecycleMetricTracker


class LifecycleSet(Command):
    """Set container lifecycle configuration."""

    log = getLogger(__name__ + ".LifecycleSet")

    def get_parser(self, prog_name):
        parser = super(LifecycleSet, self).get_parser(prog_name)
        parser.add_argument(
            "container",
            metavar="<container>",
            help="Container whose lifecycle configuration to set",
        )
        parser.add_argument(
            "configuration", metavar="<configuration>", help="Lifecycle configuration"
        )
        parser.add_argument(
            "--from-file",
            action="store_true",
            help="Consider <configuration> as a path to a file",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        if parsed_args.from_file:
            with open(parsed_args.configuration, "r", encoding="utf-8") as file_:
                conf = file_.read()
        else:
            conf = parsed_args.configuration

        lc = ContainerLifecycle(
            self.app.client_manager.storage,
            self.app.client_manager.account,
            parsed_args.container,
            self.log,
        )
        lc.load_json(conf)
        lc.save()


class LifecycleGet(Command):
    """Get container lifecycle configuration."""

    log = getLogger(__name__ + ".LifecycleGet")

    def get_parser(self, prog_name):
        parser = super(LifecycleGet, self).get_parser(prog_name)
        parser.add_argument(
            "container",
            metavar="<container>",
            help="Container whose lifecycle configuration to get",
        )
        return parser

    def take_action(self, parsed_args):
        self.log.debug("take_action(%s)", parsed_args)
        lc = ContainerLifecycle(
            self.app.client_manager.storage,
            self.app.client_manager.account,
            parsed_args.container,
            self.log,
        )
        json_conf = lc.get_configuration()
        if json_conf is None:
            raise LifecycleNotFound(
                f"No lifecycle configuration for container {parsed_args.container}"
                f" in account {self.app.client_manager.account}"
            )
        self.app.stdout.write(json_conf)


class LifecycleContainers(Lister):
    """
    List containers in processed for a bucket during a lifecycle run
    """

    log = getLogger(__name__ + ".LifecycleContainers")

    CONF_KEY_PREFIX = "lifecycle."

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "run_id",
            metavar="<run_id>",
            help="Lifecycle run id",
        )
        parser.add_argument(
            "bucket",
            metavar="<bucket>",
            help="Bucket id",
        )

        return parser

    def take_action(self, parsed_args):
        account = self.app.client_manager.account

        conf = {
            k[len(self.CONF_KEY_PREFIX) :]: v
            for k, v in self.app.client_manager.sds_conf.items()
            if k.startswith(self.CONF_KEY_PREFIX)
        }

        client = LifecycleMetricTracker(conf, logger=self.log)

        containers = client.get_containers(
            parsed_args.run_id, account, parsed_args.bucket
        )

        return ("Container id",), [(c,) for c in containers]
