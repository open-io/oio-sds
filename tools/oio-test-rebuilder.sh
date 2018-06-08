#!/usr/bin/env bash

NAMESPACE=$($(which oio-test-config.py) -n)
WORKERS=10

usage() {
  echo "Usage: $(basename "${0}") -n namespace -w workers"
  echo "Example (default): $(basename "${0}") -n ${NAMESPACE} -w ${WORKERS}"
  exit
}

while getopts ":n:w:p:" opt; do
  case $opt in
    n)
      echo "-n was triggered, Parameter: $OPTARG" >&2
      NAMESPACE=$OPTARG
      if [ -z "${NAMESPACE}" ]; then
        echo "Missing namespace name"
        exit 1
      fi
      ;;
    w)
      echo "-w was triggered, Parameter: $OPTARG" >&2
      WORKERS=$OPTARG
      if [ -z "${WORKERS}" ]; then
        echo "Missing number of workers"
        exit 1
      fi
      ;;
    *)
      usage
      exit 0
      ;;
  esac
done

PROXY=$($(which oio-test-config.py) -t proxy -1)

FAIL=false

TMP_VOLUME="/tmp/openio_volume_before"
TMP_FILE_BEFORE="/tmp/openio_file_before"
TMP_FILE_AFTER="/tmp/openio_file_after"

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

oio_meta_rebuilder()
{
  set -e

  TYPE=$1

  mysqldiff()
  {
    if ! TABLES_1=$(/usr/bin/sqlite3 "${1}" ".tables" 2> /dev/null) \
        || [ -z "${TABLES_1}" ]; then
      return 1
    fi
    if ! TABLES_2=$(/usr/bin/sqlite3 "${2}" ".tables" 2> /dev/null) \
        || [ -z "${TABLES_2}" ]; then
      return 1
    fi
    if [ "${TABLES_1}" != "${TABLES_2}" ]; then
      echo "${TABLES_1}"
      echo "${TABLES_2}"
      return 0
    fi
    OLD_IFS=$IFS
    IFS=' '
    for TABLE in $(echo "${TABLES_1}"); do
      if ! TABLE_1=$(/usr/bin/sqlite3 "${1}" "SELECT * FROM ${TABLE}" \
          2> /dev/null); then
        IFS=$OLD_IFS
        return 1
      fi
      if ! TABLE_2=$(/usr/bin/sqlite3 "${2}" "SELECT * FROM ${TABLE}" \
          2> /dev/null); then
        IFS=$OLD_IFS
        return 1
      fi
      if [ "${TABLE_1}" != "${TABLE_2}" ]; then
        echo "${TABLE_1}"
        echo "${TABLE_2}"
        IFS=$OLD_IFS
        return 0
      fi
    done
    IFS=$OLD_IFS
    return 0
  }

  echo ""
  echo "***** oio-${TYPE}-rebuilder *****"
  echo ""

  META_COPY=$(/usr/bin/curl -X POST \
      "http://${PROXY}/v3.0/${NAMESPACE}/lb/poll?pool=${TYPE}" 2> /dev/null \
      | /bin/grep -o "\"addr\":" | /usr/bin/wc -l)
  if [ "${META_COPY}" -le 0 ]; then
    echo "proxy: No response"
    exit 1
  fi
  if [ "${META_COPY}" -le 1 ]; then
    printf "\noio-%s-rebuilder: SKIP (need at least 2 %s to run)\n" \
        "${TYPE}" "${TYPE}"
    return
  fi

  OLD_IFS=$IFS
  IFS=' ' read -r META_IP_TO_REBUILD META_LOC_TO_REBUILD <<< \
      "$($(which openio) cluster list "${TYPE}" -c Addr -c Volume \
      -f value | /usr/bin/shuf -n 1)"
  IFS=$OLD_IFS

  echo "Remove the ${TYPE} ${META_IP_TO_REBUILD}"
  /bin/rm -rf "${TMP_VOLUME}"
  /bin/cp -a "${META_LOC_TO_REBUILD}" "${TMP_VOLUME}"
  /bin/rm -rf "${META_LOC_TO_REBUILD}"
  /bin/mkdir "${META_LOC_TO_REBUILD}"

  REBULD_TIME=$(date +%s)

  set +e

  echo "Start the rebuilding for the ${TYPE} ${META_IP_TO_REBUILD}" \
      "with ${WORKERS} workers"
  if ! $(which oio-"${TYPE}"-rebuilder) --workers "${WORKERS}" \
      "${NAMESPACE}"; then
    FAIL=true
  fi

  echo "Check the differences"

  for META in ${TMP_VOLUME}/*/*; do
    if [ "${TYPE}" == "meta1" ]; then
      if ! USER=$(/usr/bin/sqlite3 "${META}" "SELECT user FROM users LIMIT 1" \
          2> /dev/null); then
        echo "${META}: sqlite3 failed for the ${TYPE} ${META_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
      if [ -z "${USER}" ]; then
        continue
      fi
    fi

    META_AFTER=${META//"${TMP_VOLUME}"/"${META_LOC_TO_REBUILD}"}
    if ! [ -f "${META_AFTER}" ]; then
      echo "${META}: No such file for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi

    if ! LAST_REBUILD=$(/usr/bin/sqlite3 "${META_AFTER}" \
        "SELECT v FROM admin where k == 'user.sys.last_rebuild'" \
        2> /dev/null); then
      echo "${META}: sqlite3 failed for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    if [ -z "${LAST_REBUILD}" ] \
        || [ "${REBULD_TIME}" -gt "${LAST_REBUILD}" ]; then
      echo "${META}: Last rebuild too old for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi

    /bin/cp -a "${META}" "${TMP_FILE_BEFORE}"
    /bin/cp -a "${META_AFTER}" "${TMP_FILE_AFTER}"
    if ! /usr/bin/sqlite3 "${TMP_FILE_BEFORE}" \
        "DELETE FROM admin WHERE k == 'version:main.admin';
        DELETE FROM admin WHERE k == 'user.sys.last_rebuild'" &> /dev/null; then
      echo "${META}: sqlite3 failed for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    /usr/bin/sqlite3 "${TMP_FILE_AFTER}" \
        "DELETE FROM admin WHERE k == 'version:main.admin';
        DELETE FROM admin WHERE k == 'user.sys.last_rebuild'" &> /dev/null
    if ! /usr/bin/sqlite3 "${TMP_FILE_AFTER}" \
        "DELETE FROM admin WHERE k == 'version:main.admin';
        DELETE FROM admin WHERE k == 'user.sys.last_rebuild'" &> /dev/null; then
      echo "${META}: sqlite3 failed for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    if ! DIFF=$(mysqldiff "${TMP_FILE_BEFORE}" "${TMP_FILE_AFTER}" \
        2> /dev/null); then
      echo "${META}: sqldiff failed for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    if [ -n "${DIFF}" ]; then
      echo "${META}: Wrong content for the ${TYPE} ${META_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
  done

  if [ "${FAIL}" = true ]; then
    printf "${RED}\noio-%s-rebuilder: FAILED\n${NO_COLOR}" "${TYPE}"
    exit 1
  else
    printf "${GREEN}\noio-%s-rebuilder: OK\n${NO_COLOR}" "${TYPE}"
  fi
}

oio_blob_rebuilder()
{
  set -e

  echo ""
  echo "***** oio-blob-rebuilder *****"
  echo ""

  OLD_IFS=$IFS
  IFS=' ' read -r RAWX_IP_TO_REBUILD RAWX_LOC_TO_REBUILD <<< \
      "$($(which openio) cluster list rawx -c Addr -c Volume -f value \
      | /usr/bin/shuf -n 1)"
  IFS=$OLD_IFS

  TOTAL_CHUNKS=0
  while read -r RAWX_LOC; do
    TOTAL_CHUNKS=$(( TOTAL_CHUNKS + $(/usr/bin/find "${RAWX_LOC}" -type f \
    | /usr/bin/wc -l) ))
  done < <($(which openio) cluster list rawx -c Volume -f value)

  echo "Remove the rawx ${RAWX_IP_TO_REBUILD}"
  /bin/rm -rf "${TMP_VOLUME}"
  /bin/cp -a "${RAWX_LOC_TO_REBUILD}" "${TMP_VOLUME}"
  /bin/rm -rf "${RAWX_LOC_TO_REBUILD}"
  /bin/mkdir "${RAWX_LOC_TO_REBUILD}"

  echo "Create an incident for the rawx ${RAWX_IP_TO_REBUILD}"
  $(which openio) volume admin incident "${RAWX_IP_TO_REBUILD}"

  set +e

  echo "Start the rebuilding for the rawx ${RAWX_IP_TO_REBUILD}"
  if ! $(which oio-blob-rebuilder) --volume "${RAWX_IP_TO_REBUILD}" \
      --workers "${WORKERS}" --allow-same-rawx "${NAMESPACE}"; then
    FAIL=true
  fi

  echo "Check the differences"

  TOTAL_CHUNKS_AFTER=0
  while read -r RAWX_LOC; do
    TOTAL_CHUNKS_AFTER=$(( TOTAL_CHUNKS_AFTER + \
        $(/usr/bin/find "${RAWX_LOC}" -type f | /usr/bin/wc -l) ))
  done < <($(which openio) cluster list rawx -c Volume -f value)
  if [ "${TOTAL_CHUNKS}" -ne "${TOTAL_CHUNKS_AFTER}" ]; then
    echo "Wrong number of chunks:" \
        "before=${TOTAL_CHUNKS} after=${TOTAL_CHUNKS_AFTER}"
    FAIL=true
  fi

  for CHUNK in ${TMP_VOLUME}/*/*; do
    if ! CONTAINER_ID=$(/usr/bin/getfattr -n "user.grid.content.container" \
        --only-values "${CHUNK}" 2> /dev/null); then
      echo "${CHUNK}: Missing attribute for the rawx ${RAWX_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    if ! CONTENT_ID=$(/usr/bin/getfattr -n "user.grid.content.id" \
        --only-values "${CHUNK}" 2> /dev/null); then
      echo "${CHUNK}: Missing attribute for the rawx ${RAWX_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    if ! POSITION=$(/usr/bin/getfattr -n "user.grid.chunk.position" \
        --only-values "${CHUNK}" 2> /dev/null); then
      echo "${CHUNK}: Missing attribute for the rawx ${RAWX_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi

    if ! CONTENT_INFO=$($(which python) -c "from oio import ObjectStorageApi
api = ObjectStorageApi('${NAMESPACE}')
properties = api.container_get_properties(None, None, cid='${CONTAINER_ID}')
account = properties['system']['sys.account']
container = properties['system']['sys.user.name']
properties = api.object_get_properties(account, container, None, content='${CONTENT_ID}')
content = properties['name']
version = properties['version']
print(account + ' ' + container + ' ' + content + ' ' + version)" \
        2> /dev/null); then
      echo "${CHUNK}: Retrieving properties failed for the rawx" \
          "${RAWX_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    OLD_IFS=$IFS
    IFS=' ' read -r ACCOUNT CONTAINER CONTENT VERSION <<< "${CONTENT_INFO}"
    IFS=$OLD_IFS

    if ! CHUNK_URLS=$($(which openio) object locate \
        --oio-account "${ACCOUNT}" "${CONTAINER}" "${CONTENT}" \
        --object-version "${VERSION}" -f value -c Pos -c Id \
        | /bin/grep "^${POSITION} " | /usr/bin/cut -d' ' -f2) \
        || [ -z "${CHUNK_URLS}" ]; then
      echo "${CHUNK}: Location failed for the rawx ${RAWX_IP_TO_REBUILD}"
      FAIL=true
      continue
    fi
    OLD_IFS=$IFS
    IFS=$'\n'
    for CHUNK_URL in $(echo "${CHUNK_URLS}"); do
      if [ "${CHUNK_URL##*/}" = "${CHUNK##*/}" ]; then
        echo "${CHUNK}: (${CHUNK_URL}) meta2 not updated for the rawx " \
            "${RAWX_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
      if ! $(which oio-crawler-integrity) "${NAMESPACE}" "${ACCOUNT}" \
          "${CONTAINER}" "${CONTENT}" "${CHUNK_URL}" &> /dev/null; then
        echo "${CHUNK}: (${CHUNK_URL}) oio-crawler-integrity failed for the" \
            "rawx ${RAWX_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
      if ! /usr/bin/wget -O "${TMP_FILE_AFTER}" "${CHUNK_URL}" \
          &> /dev/null; then
        echo "$${CHUNK}: (${CHUNK_URL}) wget failed for the rawx" \
            "${RAWX_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
      if ! DIFF=$(/usr/bin/diff "${CHUNK}" "${TMP_FILE_AFTER}" \
          2> /dev/null); then
        echo "${CHUNK}: (${CHUNK_URL}) diff failed for the rawx" \
            "${RAWX_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
      if [ -n "${DIFF}" ]; then
        echo "${CHUNK}: (${CHUNK_URL}) Wrong content for the rawx" \
            "${RAWX_IP_TO_REBUILD}"
        FAIL=true
        continue
      fi
    done
    IFS=$OLD_IFS
  done

  if [ "${FAIL}" = true ]; then
    printf "${RED}\noio-blob-rebuilder: FAILED\n${NO_COLOR}"
    exit 1
  else
    echo "Remove the incident for the rawx ${RAWX_IP_TO_REBUILD}"
    $(which openio) volume admin clear "${RAWX_IP_TO_REBUILD}"

    printf "${GREEN}\noio-blob-rebuilder: OK\n${NO_COLOR}}"
  fi
}

oio_meta_rebuilder "meta1"
oio_meta_rebuilder "meta2"
oio_blob_rebuilder
