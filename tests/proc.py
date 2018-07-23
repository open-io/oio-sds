# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from time import sleep
from subprocess import Popen
import errno


def wait_for_slow_startup(port):
    for i in range(5):
        if check_for_server(port):
            return True
        sleep(i * 0.2)
    return False


def check_process_absent(proc):
    for i in range(5):
        if proc.poll() is not None:
            return True
        sleep(i * 0.2)
    try:
        proc.terminate()
    except OSError as exc:
        return exc.errno == errno.ESRCH
    except Exception:
        pass
    return False


def check_for_server(port):
    hexport = "%04X" % port
    with open("/proc/net/tcp", "r") as f:
        for line in f:
            tokens = line.strip().split()
            port = tokens[1][9:13]
            if port == hexport:
                return True
    return False


def does_startup_fail(path):
    with open('/dev/null', 'w') as out:
        fd = out.fileno()
        proc = Popen(['oio-rdir-server', path], stderr=fd)
        return check_process_absent(proc)
