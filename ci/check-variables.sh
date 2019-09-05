#!/usr/bin/env bash

# check-variables.sh
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

SRCDIR=$1 ; [[ -n "$SRCDIR" ]] ; [[ -d "$SRCDIR" ]]

cd $SRCDIR
h0=$(md5sum Variables.md)
h1=$(md5sum Variables.CMakeFile)
./confgen.py cmake conf.json
./confgen.py github conf.json
if ! [[ "$h0" = $(md5sum Variables.md) ]] ; then
	echo "Please regenerate the GitHub markdown doc about the configuration" >&2
	exit 1
fi
if ! [[ "$h1" = $(md5sum Variables.CMakeFile) ]] ; then
	echo "Please regenerate the CMake directives about the configuration" >&2
	exit 1
fi
