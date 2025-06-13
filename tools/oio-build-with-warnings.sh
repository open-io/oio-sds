#!/usr/bin/env bash

# oio-build-with-warnings.sh
# Copyright (C) 2020 OpenIO SAS, as part of OpenIO SDS
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

SRCDIR="$1" ; [ -n "$SRCDIR" ] ; [ -d "$SRCDIR" ]

echo "Compiling with extra warnings enabled..."
D=$(mktemp -d)
cd $D
cmake ${CMAKE_OPTS} -D CMAKE_BUILD_TYPE=Release -D EXTRA_WARNINGS=1 ${SRCDIR}
make -j  all  2> >(tee warnings.log >&2)
echo
echo "--- Summary of warnings ------------------------------------------------"
sed -r -n -e 's,([^\[]+)\[-W([^\]+)\],\2,p' warnings.log | sort | uniq -c
echo "------------------------------------------------------------------------"
echo
make clean
cd
rm -rf "$D"
