#!/usr/bin/env bash

# oio-travis-failfast.sh
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

# Not required, Travis tests already run in a virtualenv if language is python.
#source $HOME/oio/bin/activate

fold_start() { echo -e "travis_fold:start:$1\033[33;1m$2\033[0m" ; }
fold_end() { echo -e "\ntravis_fold:end:$1\r" ; }
fold() {
	local tag ; tag="$1" ; shift
	echo -e "\n### $tag : $(date '+%F %R:%S')"
	time ( fold_start "$tag" ; set -x ; $@ ; set +x ; fold_end "$tag" )
}

fold SDK ./tools/oio-build-sdk.sh ${PWD}
fold Release ./tools/oio-build-release.sh ${PWD}
fold Copyright ./tools/oio-check-copyright.sh ${PWD}
fold Virtualenv python ./setup.py develop
fold Variables tox -e variables
fold VariablesPy3 tox -e py3_variables

