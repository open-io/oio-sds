# Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS
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

import sys
from tempfile import NamedTemporaryFile
from oio.common.logger import get_logger, redirect_stdio

with NamedTemporaryFile(mode='rb', prefix='nolog-') as tmp:
    LOGGER = get_logger({'log_address': tmp.name})
    redirect_stdio(LOGGER)
    LOGGER.warn('Trying to log something boring.')

sys.exit(0)
