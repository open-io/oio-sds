# Copyright (C) 2015-2030 OpenIO SAS, as part of OpenIO SDS
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

from oio.container.backup import ContainerBackup


def create_app(conf=None):
    app = ContainerBackup(conf)
    return app


if __name__ == "__main__":
    from werkzeug.serving import run_simple
    run_simple('127.0.0.1', 6002, create_app(),
               use_debugger=True, use_reloader=True)
