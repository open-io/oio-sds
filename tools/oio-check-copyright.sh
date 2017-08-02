#!/usr/bin/env bash
set -e

BASEDIR=$1
[[ -n "$BASEDIR" ]]
[[ -d "$BASEDIR" ]]

/bin/ls -1f ${BASEDIR} \
| grep -i -v -e '^\.' -e '^build' -e '^cmake' -e '^setup' \
| while read D ; do
	/usr/bin/find "${BASEDIR}/${D}" -type f \
		-name '*.h' -or -name '*.c' -or -name '*.py' \
	| while read F ; do
		if ! [[ -s "$F" ]] ; then continue ; fi
		if ! /usr/bin/git ls-files --error-unmatch "$F" ; then continue ; fi
		if ! /bin/grep -q 'Copyright' "$F" ; then
			echo "Missing Copyright section in $F" 1>&2
			exit 1
		fi
	done
done

