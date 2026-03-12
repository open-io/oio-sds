# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2026 OVH SAS
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
import signal
import subprocess
import time

import pytest

from tests.utils import BaseTestCase, random_str


class TestProxyFailure(BaseTestCase):
    def setUp(self):
        super().setUp()

    def _test_admin_debug_on_srvtype(self, srvtype):
        params = {"ref": random_str(64), "acct": random_str(64), "type": srvtype}
        self.request("POST", self._url("admin/debug"), params=params)

    def test_admin_debug_on_meta1(self):
        self._test_admin_debug_on_srvtype("meta1")

    def test_admin_debug_on_meta0(self):
        self._test_admin_debug_on_srvtype("meta0")

    def _get_oioproxy_pid(self) -> int:
        """Get the PID of the oio-proxy process"""
        try:
            # Use systemctl to get the PID of the proxy service
            cmd = [
                *self.__class__._service_ctl_cmd(),
                "show",
                self.service_to_ctl_key("proxy-1", "proxy"),
                "--property=MainPID",
                "--value",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
            )
            return int(result.stdout.strip())
        except (subprocess.CalledProcessError, ValueError):
            # Fallback: try to find proxy process manually
            try:
                result = subprocess.run(
                    ["ps", "-C", "oio-proxy", "--no-headers", "-o", "pid"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                pids = result.stdout.strip().split("\n")
                if not pids or pids[0] == "":
                    self.fail("No oio-proxy process found")
                return int(pids[0])
            except (subprocess.CalledProcessError, ValueError):
                self.fail("Failed to get oio-proxy process PID")

    @pytest.mark.requires_systemd
    def test_watchdog_restart(self):
        """
        Check that when oio-proxy is stuck, systemd restarts it.
        """
        pid = self._get_oioproxy_pid()
        # Send STOP signal to the process
        try:
            self.logger.info("Sending SIGSTOP to process %d", pid)
            os.kill(pid, signal.SIGSTOP)
        except OSError as e:
            self.fail(f"Failed to send SIGSTOP to process {pid}: {e}")

        # Wait for systemd to restart the process (max 30 seconds)
        timeout = 30
        start_time = time.monotonic()
        while time.monotonic() - start_time < timeout:
            new_pid = self._get_oioproxy_pid()
            if new_pid != pid:
                self.logger.info("oio-proxy pid is now %d", new_pid)
                return  # Success - process was restarted with new PID

            self.logger.debug("oio-proxy pid is still %d", new_pid)
            time.sleep(1.0)  # Brief pause before retry

        self.fail("oio-proxy was not restarted by systemd within 30 seconds")
