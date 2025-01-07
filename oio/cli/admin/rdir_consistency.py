# Copyright (C) 2024 OVH SAS
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

import os
from collections import Counter
from time import monotonic as time

from oio.blob.utils import chunk_id_to_path
from oio.cli import Lister
from oio.common.exceptions import ClientException, NotFound, ServiceBusy
from oio.common.utils import ratelimit


class NotLocalError(Exception):
    pass


class RdirConsistency(Lister):
    """
    Check data consistency of rdirs attached to a rawx volume.
    For each rdir, list all chunks. And for each chunk, check it exists in rawx
    and in meta2 database.
    """

    STATUS_UPDATE_COOLDOWN = 30

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cm = self.app.client_manager
        self.__validate_chunk_presence_fn = self.__validate_chunk_presence_remote
        self.__volume_local_path = None
        self.__next_status_update = time() + self.STATUS_UPDATE_COOLDOWN
        self.__hash_depth = 0
        self.__hash_width = 0

    @property
    def logger(self):
        return self.cm.logger

    def get_parser(self, prog_name):
        parser = super().get_parser(prog_name)
        parser.add_argument(
            "--ratelimit",
            type=int,
            help="Maximum requests per second (default=0:disable)",
            default=0,
        )
        parser.add_argument(
            "--local",
            action="store_true",
            default=False,
            help=(
                "Verify chunk presence by calling os.stat() instead of a HEAD request "
                "(requires the command to be run from the same host as the volume)"
            ),
        )
        parser.add_argument(
            "volume",
            metavar="<volume_id>",
            help="Volume",
            type=str,
        )
        return parser

    def __build_key(self, present, orphan):
        return (
            ("present" if present else "missing")
            + "."
            + ("orphan" if orphan else "non-orphan")
        )

    def __validate_chunk_presence_local(self, _volume, chunk):
        chunk_path = chunk_id_to_path(
            chunk,
            hash_width=self.__hash_width,
            hash_depth=self.__hash_depth,
            volume_path=self.__volume_local_path,
        )
        try:
            os.stat(chunk_path)
            return True
        except FileNotFoundError:
            self.logger.debug(
                "Chunk %s not found in volume. Expected path: %s",
                chunk,
                chunk_path,
            )
        return False

    def __validate_chunk_presence_remote(self, volume, chunk):
        chunk_url = f"http://{volume}/{chunk}"
        for _ in range(3):
            try:
                _ = self.cm.storage.blob_client.chunk_head(chunk_url)
                return True
            except ServiceBusy:
                continue
            except ClientException:
                break
        return False

    def __is_orphan(self, container, path, version):
        try:
            self.cm.storage.container.content_locate(
                cid=container, path=path, version=version
            )
        except NotFound:
            return True
        return False

    def __show_status(self, msg, *args):
        now = time()
        if now >= self.__next_status_update:
            self.logger.info(msg, *args)
            self.__next_status_update = now + self.STATUS_UPDATE_COOLDOWN

    def _list_chunks(self, volume, rdir_hosts, rate_limit=0):
        rdir_counters = {}
        volume_host = self.cm.rdir.cs.resolve_service_id("rawx", volume)
        run_time = 0
        for rdir_host in rdir_hosts:
            counters = rdir_counters.setdefault(rdir_host, Counter())
            self.logger.info("Fetching from rdir: %s", rdir_host)
            chunk_count = 0
            for container, chunk, value in self.cm.rdir.chunk_fetch(
                volume, rdir_hosts=(rdir_host,)
            ):
                run_time = ratelimit(run_time, rate_limit)
                self.logger.debug(
                    "Chunk: %s Container: %s Value: %s", chunk, container, value
                )
                is_present = self.__validate_chunk_presence_fn(volume_host, chunk)
                is_orphan = self.__is_orphan(
                    container, value.get("path"), value.get("version")
                )
                self.logger.debug(
                    "Chunk: %s, orphan: %s, present: %s", chunk, is_orphan, is_present
                )
                chunk_count += 1
                self.__show_status(
                    "Processed chunks for rdir %s: %s, counters: %s",
                    rdir_host,
                    chunk_count,
                    counters,
                )
                key = self.__build_key(is_present, is_orphan)
                counters[key] += 1
        return rdir_counters

    def _check_chunks_status(self, chunks):
        for container, chunk, value in chunks:
            self.logger.debug(
                "Chunk: %s Container: %s Value: %s", chunk, container, value
            )
            self.__validate_chunk_presence_fn(container, chunk)

    def _get_volume_local_path(self, volume):
        services = self.cm.rdir.cs.local_services()
        for svc in services:
            if svc["type"] != "rawx":
                continue
            tags = svc.get("tags", {})
            if tags.get("tag.service_id") == volume:
                return tags.get("tag.vol")
        raise NotLocalError(f"Volume '{volume}' is not a local service")

    def _get_hash_properties(self, volume):
        self.logger.debug("Fetching volume '%s' configuration", volume)
        conf = self.cm.admin.service_get_info(volume, "rawx")
        return int(conf.get("hash_depth", [1])[0]), int(conf.get("hash_width", [1])[0])

    def take_action(self, parsed_args):
        volume = parsed_args.volume

        if parsed_args.local:
            self.__volume_local_path = self._get_volume_local_path(volume)
            self.__validate_chunk_presence_fn = self.__validate_chunk_presence_local
        else:
            self.logger.warning(
                "Running this command from remote can be very slow."
                "Please consider the --local option for better performances"
            )

        self.__hash_depth, self.__hash_width = self._get_hash_properties(volume)

        rdir_hosts = self.cm.rdir._get_resolved_rdir_hosts(volume)
        self.logger.info("Rdir hosts assigned to volume %s: %s", volume, rdir_hosts)
        rdir_counters = self._list_chunks(
            volume, rdir_hosts, rate_limit=parsed_args.ratelimit
        )

        # Build columns
        columns = ["Service Id", "Addr"]
        columns.extend(
            [self.__build_key(r, o) for r in (True, False) for o in (True, False)]
        )
        all_services = self.cm.conscience.all_services("rdir")
        all_services = [svc for svc in all_services if svc["addr"] in rdir_hosts]
        values = []
        for rdir, counters in rdir_counters.items():
            service_id = "-"
            for svc in all_services:
                if svc["addr"] == rdir:
                    service_id = svc.get("tags", {}).get("tag.service_id")
                    break

            value = [service_id, rdir]
            total = 0
            for col in columns[2:]:
                count = counters.get(col, 0)
                total += count
                value.append(count)
            value.append(total)
            values.append(value)
        columns.append("Total")

        return columns, values
