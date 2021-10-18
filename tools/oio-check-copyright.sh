#!/usr/bin/env bash

# oio-check-copyright.sh
# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
# Copyright (C) 2021 OVH SAS
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

EXCLUDED_FILES=("core/tree.h" "metautils/lib/tree.h")

function find_last_modification {
	FILE=$1
	(git log -8 --no-merges --pretty="format:%H" -- "${FILE}"; echo) |
		while read COMMIT; do
			if [ -z "${COMMIT}" ]; then
				continue
			fi
			MODIFIED=$(git show "${COMMIT}" -- "${FILE}" | grep -v -E '(^(\+\+\+|---)|Copyright \(C\) )' | grep -E '^(\+|-)' | head -n 1)
			if [ -z "${MODIFIED}" ]; then
				continue
			fi
			echo "${COMMIT}"
			return
		done
}

check_copyright () {
	RETCODE=0
	while read FILE; do
		if [[ ! "${FILE}" =~ ^.+\.(c|go|h|py)$ ]]; then
			[ -n "$VERBOSE" ] && echo "${FILE} not source code file"
			continue
		fi
		if [[ "${FILE}" =~ ^setup\.(py|cfg)$ ]]; then
			[ -n "$VERBOSE" ] && echo "${FILE} on black list"
			continue
		fi
		if [ ! -s "${FILE}" ]; then
			[ -n "$VERBOSE" ] && echo "${FILE} is empty"
			continue
		fi
		if [[ " ${EXCLUDED_FILES[@]} " =~ " ${FILE} " ]]; then
			continue
		fi

		COMMIT=$(find_last_modification "${FILE}")
		if [ -z "${COMMIT}" ]; then
			echo "The last 8 commits of${FILE} only modify the Copyright section" 1>&2
			RETCODE=1
            continue
		fi
		YEAR=$(git show -s --pretty="format:%cd" --date="format:%Y" "${COMMIT}")

		COMPANY="OpenIO"
		if [ "${YEAR}" -gt "2020" ]; then
			COMPANY="OVH"
		elif [ "${YEAR}" -eq "2020" ]; then
			COMPANY="(OpenIO|OVH)"
		fi

		COPYRIGHT_LINE=$(head -n 8 "${FILE}" | grep -E "Copyright \(C\) ([[:digit:]]{4}-|)${YEAR} ${COMPANY} SAS")
		if [ -z "${COPYRIGHT_LINE}" ]; then
			echo "The Copyright section in ${FILE} is not up to date, the last modification dates from ${YEAR} with the commit ${COMMIT}" 1>&2
			[ -n "$VERBOSE" ] && git show "${COMMIT}" -- "${FILE}" | head -n 32
			RETCODE=1
		fi
	done
    exit $RETCODE
}

declare -x FILES
if [ ${1:-__all__} == "__all__" ]
then
	FILES=$(git ls-tree -r --name-only HEAD)
else
	FILES=$(echo "$*" | tr ' ' '\n')
fi

echo -e "${FILES}" | check_copyright
