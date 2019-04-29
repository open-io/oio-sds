#!/usr/bin/env bash

# oio-build-sdk.sh
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
set -e
set -x

SRCDIR="$1" ; [[ -n "$SRCDIR" ]] ; [[ -d "$SRCDIR" ]]

D=$(mktemp -d)
cd $D
for TYPE in Debug Release ; do
	cmake ${CMAKE_OPTS} -D CMAKE_BUILD_TYPE=$TYPE -D SDK_ONLY=on ${SRCDIR}
	make -j 8 all
	make test
	make clean
done
cd
rm -rf "$D"
