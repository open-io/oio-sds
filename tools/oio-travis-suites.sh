#!/usr/bin/env bash

# oio-travis-suites.sh
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
source $HOME/oio/bin/activate
export PATH="$PATH:/tmp/oio/bin"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/tmp/oio/lib"
ulimit -c unlimited -S

fold_start() { echo -e "travis_fold:start:$1\033[33;1m$2\033[0m" ; }
fold_end() { echo -e "\ntravis_fold:end:$1\r" ; }
fold() {
	local tag ; tag="$1" ; shift
	echo -e "\n### $tag : $(date '+%F %R:%S')"
	time ( fold_start "$tag" ; set -x ; $@ ; set +x ; fold_end "$tag" )
}

fold configure  cmake ${CMAKE_OPTS} -DCMAKE_BUILD_TYPE="Debug" ${PWD}
fold build      make -j 8 all
fold install    make install
fold virtualenv python ./setup.py develop

export PYTHON_COVERAGE=1
fold coverage_init make coverage_init
./tools/oio-test-suites.sh ${PWD} ${PWD}
fold coverage_fini make coverage

