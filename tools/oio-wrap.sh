#!/bin/bash
set -e
LOG=$1 ; shift
CMD=$1 ; shift
#exec "$1" $@ > "${LOG}${$}.out" 2> "${LOG}${$}.err"
exec "$CMD" $@ 2>&1 | /usr/bin/logger --id --tag "${LOG}"
