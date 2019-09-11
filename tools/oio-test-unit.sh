#!/usr/bin/env bash

# oio-test-func.sh
# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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
WRKDIR="$2" ; [[ -n "$WRKDIR" ]] ; [[ -d "$WRKDIR" ]]

export OIO_NS=NS-${RANDOM}
export OIO_ACCOUNT=ACCT-${RANDOM}
export OIO_USER=USER-$RANDOM

cd $WRKDIR
make -C tests/unit test

cd $SRCDIR
if [ "${TRAVIS_PYTHON_VERSION:-2.7}" \< "3.6" ]
then
  tox -e pep8
  tox -e py27
else
  tox -e py3_pep8
  tox -e py3
fi
