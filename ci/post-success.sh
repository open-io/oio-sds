#!/usr/bin/env bash
# vim: ts=4 shiftwidth=4 noexpandtab

# ci/post-success.sh
# Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS
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
set -e
set -x

bash <(curl -s https://codecov.io/bash) -f /tmp/cmake_coverage.output

codecov
if cat ${HOME}/go_coverage.output.* > go_coverage.output; then
	rm ${HOME}/go_coverage.output.*
else
	echo "" > go_coverage.output
fi
bash <(curl -s https://codecov.io/bash) -f go_coverage.output

./tools/oio-gdb.py

BEANSTALK=$(oio-test-config.py -t beanstalkd)
if [ -n "${BEANSTALK}" ]; then
	# some tests stop all services, we must start beanstalk to dump events
	gridinit_cmd -S "$HOME/.oio/sds/run/gridinit.sock" start @beanstalkd
	oio-dump-buried-events.py ${BEANSTALK}
fi
