#!/usr/bin/env bash
set -e

BASEDIR=$1
[[ -n "$BASEDIR" ]]
[[ -d "$BASEDIR" ]]

/bin/ls -1f ${BASEDIR} \
| grep -i -v -e '^\.' -e '^build' -e '^cmake' -e '^setup' \
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
