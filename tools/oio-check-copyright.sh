#!/usr/bin/env bash

# oio-check-copyright.sh
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

BASEDIR=$1 ; [[ -n "$BASEDIR" ]] ; [[ -d "$BASEDIR" ]]

/bin/ls -1f ${BASEDIR} \
| grep -i -v -e '^\.' -e '^build' -e '^cmake' -e '^setup' -e '^oioenv' \
| while read D ; do
	/usr/bin/find "${BASEDIR}/${D}" -type f \
		-name '*.h' -or -name '*.c' -or -name '*.py' -or -name '*.go' \
	| while read F ; do
		if ! [[ -s "$F" ]] ; then continue ; fi
		if ! /usr/bin/git ls-files --error-unmatch "$F" >/dev/null ; then continue ; fi
		if ! /bin/grep -q 'Copyright' "$F" ; then
			echo "Missing Copyright section in $F" 1>&2
			exit 1
		fi
	done
done

if [ -n "$TRAVIS_COMMIT_RANGE" ]
then
	INCLUDE='.+\.(c|go|h|py)$'
	YEAR=$(date +%Y)
	FAIL=0
	echo "Checking copyright for year $YEAR."
	git diff --name-only "$TRAVIS_COMMIT_RANGE" | grep -E "$INCLUDE" \
	| while read name ; do
		# Ignore empty files
		if ! [[ -s "$name" ]] ; then continue ; fi
		# Ignore removed files
		if ! [[ -e "$name" ]] ; then continue ; fi

		COPYRIGHT_LINE=$(grep -E 'Copyright.+[[:digit:]]{4}.+OpenIO' "$name")
		if [[ ! "$COPYRIGHT_LINE" =~ .+$YEAR.* ]]
		then
			echo "ERROR $name ($YEAR) has \"$COPYRIGHT_LINE\""
			FAIL=1
		fi
	done
	if [[ "$FAIL" != 0 ]] ; then exit $FAIL ; fi
fi
