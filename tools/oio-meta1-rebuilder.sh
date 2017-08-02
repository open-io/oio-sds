#!/bin/bash

# oio-meta1-rebuilder.sh
# Copyright (C) 2016-2017 OpenIO SAS, original work as part of OpenIO SDS
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

#set -x

usage() {
	echo "Usage: `basename $0` -r ip_redis_host:redis_port -n namespace -p ip_oioproxy:oioproxy_port "
	echo "Example: `basename $0` -r 192.120.17.12:6051 -n OPENIO -p 192.120.17.21:6006 " ;
	exit
}

[ $# -ne 6 ] && usage


while getopts ":r:n:p:" opt; do
  case $opt in
    r)
      echo "-r was triggered, Parameter: $OPTARG" >&2
      REDIS_HOST=${OPTARG/:*/}
      REDIS_PORT=${OPTARG/*:/}
      if [[ $REDIS_HOST == "" ]]
          then
          echo "Missing  ip_redis_host"
	  exit 1
      fi
      if [[ $REDIS_PORT == "" ]]
	  then
	      echo "Missing  redis_port"
	      exit 1
      fi
      ;;
    n)
      echo "-n was triggered, Parameter: $OPTARG" >&2
      NAMESPACE=$OPTARG
      ;;
    p)
      echo "-p was triggered, Parameter: $OPTARG" >&2
      OIOP_IP=${OPTARG/:*/}
      OIOP_PORT=${OPTARG/*:/}
      if [[ $OIOP_IP == "" ]]
          then
          echo "Missing  ip_oioproxy"
	  exit 1
      fi
      if [[ $OIOP_PORT == "" ]]
	  then
	      echo "Missing  oioproxy_port"
	      exit 1
      fi
      ;;
     *)
	usage
	exit 0
      ;;
  esac
done


#Get account list
redis_bin=$(which redis-cli)
ACCOUNT_LIST=$(${redis_bin} -h $REDIS_HOST -p $REDIS_PORT  keys account:* | sed 's@.*account:\(.*\)@\1@' | tr "\n" " ")

#Launch meta1 repair
for account in $ACCOUNT_LIST
do
	openio container list --oio-ns ${NAMESPACE} --oio-account $account -f value -c Name --full | sed "s;^;${NAMESPACE}/${account}/;" \
	  | xargs -n 1024 oio-tool cid \
	  | cut -c1-3 | sort -u | sed 's/$/0000000000000000000000000000000000000000000000000000000000000/' \
	  | while read CID ; do
	      echo "curl -v -X POST \"http://${OIOP_IP}:${OIOP_PORT}/v3.0/${NAMESPACE}/admin/ping?cid=${CID}&type=meta1\""
              curl -v -X POST "http://${OIOP_IP}:${OIOP_PORT}/v3.0/${NAMESPACE}/admin/ping?cid=${CID}&type=meta1" 
	  done
done
