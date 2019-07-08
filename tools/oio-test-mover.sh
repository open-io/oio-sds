#!/usr/bin/env bash

NAMESPACE=$($(command -v oio-test-config.py) -n)
META1_DIGITS=$($(command -v oio-test-config.py) -v meta1_digits)
CLI=$(command -v openio)
M2_MOVER="$(command -v oio-meta2-mover)"

SVCID_ENABLED=$(openio cluster list rawx -c 'Service Id' -f value | grep -v 'n/a')

usage() {
  echo "Usage: $(basename "${0}") -n namespace -d meta1_digits"
  echo "Example (default): $(basename "${0}") -n ${NAMESPACE}" \
      "-d ${META1_DIGITS}"
  exit
}

while getopts ":n:d:" opt; do
  case $opt in
    n)
      echo "-n was triggered, Parameter: $OPTARG" >&2
      NAMESPACE=$OPTARG
      if [ -z "${NAMESPACE}" ]; then
        echo "Missing namespace name"
        exit 1
      fi
      ;;
    d)
      echo "-d was triggered, Parameter: $OPTARG" >&2
      META1_DIGITS=$OPTARG
      if [ -z "${META1_DIGITS}" ]; then
        echo "Missing meta1 digits"
        exit 1
      fi
      ;;
    *)
      usage
      exit 0
      ;;
  esac
done

PROXY=$($(command -v oio-test-config.py) -t proxy -1)

FAIL=false

TMP_VOLUME="${TMPDIR:-/tmp}/openio_volume_before"
TMP_FILE_BEFORE="${TMPDIR:-/tmp}/openio_file_before"
TMP_FILE_AFTER="${TMPDIR:-/tmp}/openio_file_after"

EMPTY_META1_PREFIX="0000"

RED='\033[0;31m'
GREEN='\033[0;32m'
NO_COLOR='\033[0m'

oio_meta2_mover()
{
  set -e

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
    for TABLE in ${TABLES_1}; do
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
  echo "***** oio-meta2-mover *****"
  echo ""

  ALL_META2=$(${CLI} cluster list meta2 -c Addr -c "Service Id" -c Volume -f value)
  META2_COPY=$(/usr/bin/curl -sS -X POST \
      "http://${PROXY}/v3.0/${NAMESPACE}/lb/poll?pool=meta2" 2> /dev/null \
      | /bin/grep -o "\"addr\":" | /usr/bin/wc -l)
  if [ "${META2_COPY}" -eq 0 ]; then
    echo "proxy: No response"
    exit 1
  fi
  if [ "${META2_COPY}" -ge "$(echo "${ALL_META2}" | wc -l)" ]; then
    printf "\noio-meta2-mover: SKIP (need more meta2 to run)\n"
    return
  fi
  ALL_META1=$(${CLI} cluster list meta1 -c Addr -c "Service Id" -c Volume -f value)

  OLD_IFS=$IFS
  IFS=' ' read -r META2_IP_TO_MOVE META2_ID META2_LOC_TO_MOVE <<< \
      "$(${CLI} cluster list meta2 -c Addr -c "Service Id" -c Volume -f value \
      | /usr/bin/shuf -n 1)"
  IFS=$OLD_IFS
  if [ -z "${SVCID_ENABLED}" ] || [ "${META2_ID}" = "n/a" ]; then
    META2_ID=${META2_IP_TO_MOVE}
  fi

  echo "Copy the volume ${META2_IP_TO_MOVE} (${META2_ID})"
  if [ "$(/usr/bin/find "${META2_LOC_TO_MOVE}" -type f 2> /dev/null \
      | /usr/bin/wc -l)" -eq 0 ]; then
    echo "No base found in the volume of meta2 ${META2_IP_TO_MOVE} (${META2_ID})"
    printf "${RED}\noio-meta2-mover: FAILED\n${NO_COLOR}"
    exit 1
  fi
  /bin/rm -rf "${TMP_VOLUME}"
  /bin/cp -a "${META2_LOC_TO_MOVE}" "${TMP_VOLUME}"

  set +e

  echo "Move and check the volume ${META2_IP_TO_MOVE} (${META2_ID})"
  for META2 in ${TMP_VOLUME}/*/*; do
    if ! PEERS_BEFORE=$(/usr/bin/sqlite3 "${META2}" \
        "SELECT v FROM admin where k == 'sys.peers'" \
        | /usr/bin/tr ',' '\n'); then
      echo "${META2}: sqlite3 failed"
      FAIL=true
      continue
    fi
    if [ -z "${PEERS_BEFORE}" ]; then
      echo "${META2}: No peer"
      FAIL=true
      continue
    fi

    if ! ACCOUNT=$(/usr/bin/sqlite3 "${META2}" \
        "SELECT v FROM admin where k == 'sys.account'" \
        | /usr/bin/tr ',' '\n'); then
      echo "${META2}: sqlite3 failed"
      FAIL=true
      continue
    fi
    if [ -z "${ACCOUNT}" ]; then
      echo "${META2}: No account"
      FAIL=true
      continue
    fi
    if ! CONTAINER=$(/usr/bin/sqlite3 "${META2}" \
        "SELECT v FROM admin where k == 'sys.user.name'" \
        | /usr/bin/tr ',' '\n'); then
      echo "${META2}: sqlite3 failed"
      FAIL=true
      continue
    fi
    if [ -z "${CONTAINER}" ]; then
      echo "${META2}: No container"
      FAIL=true
      continue
    fi

    if [ "$(/usr/bin/shuf -i 0-1 -n 1)" -eq 0 ]; then
      POSSIBLE_DESTS=$ALL_META2
      OLD_IFS=$IFS
      IFS=$'\n'
      for PEER_ID in ${PEERS_BEFORE}; do
        POSSIBLE_DESTS=$(echo "${POSSIBLE_DESTS}" | /bin/sed "/${PEER_ID}/d")
      done
      IFS=$OLD_IFS

      DEST=$(echo "${POSSIBLE_DESTS}" | /usr/bin/shuf -n 1)
      DEST_ID=$(echo "${DEST}" | /usr/bin/cut -d' ' -f2)
      if [ -z "${SVCID_ENABLED}" ] || [ "${DEST_ID}" = "n/a" ]; then
        DEST_ID=$(echo "${DEST}" | /usr/bin/cut -d' ' -f1)
      fi
    else
      unset DEST_ID
    fi
    PEERS_TO_KEEP=$(echo "${PEERS_BEFORE}" | /bin/sed "/${META2_ID}/d")

    FILE=${META2##*/}
    BASE=$( echo "${FILE}" | /usr/bin/cut -d'.' -f1)
    SEQ=$( echo "${FILE}" | /usr/bin/cut -d'.' -f2)

    if [ -z "${DEST_ID}" ]; then
      echo "$M2_MOVER ${NAMESPACE} ${BASE}.${SEQ} ${META2_ID}"
      if ! $M2_MOVER "${NAMESPACE}" "${BASE}" \
          "${META2_ID}" &> /dev/null; then
        echo "${META2}: oio-meta2-mover failed"
        FAIL=true
      fi
    else
      echo "$M2_MOVER ${NAMESPACE} ${BASE}.${SEQ} ${META2_ID}" \
          "${DEST_ID}"
      if ! $M2_MOVER "${NAMESPACE}" "${BASE}" \
          "${META2_ID}" "${DEST_ID}" &> /dev/null; then
        echo "${META2}: oio-meta2-mover failed"
        FAIL=true
      fi
    fi

    if ! META1_PEERS_ID=$(${CLI} reference locate "${CONTAINER}" \
        --oio-account "${ACCOUNT}" -f shell 2> /dev/null \
        | /bin/grep 'meta1=' | sed 's/meta1=//g' | sed 's/"//g' \
        | sed 's/, /\n/g'); then
      echo "${META2}: meta1 location failed"
      FAIL=true
      continue
    fi
    if [ -z "${META1_PEERS_ID}" ]; then
      echo "${META2}: No meta1 peer"
      FAIL=true
      continue
    fi

    unset REAL_DEST_ID
    OLD_IFS=$IFS
    IFS=$'\n'
    for META1_ID in ${META1_PEERS_ID}; do
      META1_LOC=$(echo "${ALL_META1}" | /bin/grep "${META1_ID}" \
          | /usr/bin/cut -d' ' -f3)
      META1=$(/bin/ls "${META1_LOC}/"*"/${BASE:0:${META1_DIGITS}}${EMPTY_META1_PREFIX:0:4-${META1_DIGITS}}.meta1")
      if ! PEERS_AFTER=$(/usr/bin/sqlite3 "${META1}" \
          "SELECT url FROM services WHERE hex(services.cid) == '${BASE}' and srvtype == 'meta2' and seq == '${SEQ}'" \
          2> /dev/null | /usr/bin/tr ',' '\n'); then
        echo "${META2}: sqlite3 failed for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      if [ -z "${PEERS_AFTER}" ]; then
        echo "${META2}: No peer for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      PEERS_AFTER_COPY=$PEERS_AFTER
      OLD_IFS=$IFS
      IFS=$'\n'
      for PEER_ID in ${PEERS_TO_KEEP}; do
        if ! echo "${PEERS_AFTER_COPY}" | /bin/grep -q "${PEER_ID}" ; then
          echo "${META2}: Missing IP (${PEER_ID}) for meta1 ${META1_ID}"
          FAIL=true
          continue
        fi
        PEERS_AFTER_COPY=$(echo "${PEERS_AFTER_COPY}" \
            | /bin/sed "/${PEER_ID}/d")
      done
      IFS=$OLD_IFS
      if [ "$(echo "${PEERS_AFTER_COPY}" | /usr/bin/wc -l)" -ne 1 ]; then
        echo "${META2}: Missing destination for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      if [ "${PEERS_AFTER_COPY}" == "${META2_ID}" ]; then
        echo "${META2}: Source still present for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      if [ -n "${DEST_ID}" ] && [ "${DEST_ID}" != "${PEERS_AFTER_COPY}" ]; then
        echo "${META2}: Wrong destination for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      if [ -n "${REAL_DEST_ID}" ] \
          && [ "${REAL_DEST_ID}" != "${PEERS_AFTER_COPY}" ]; then
        echo "${META2}: Different destination for meta1 ${META1_ID}"
        FAIL=true
        continue
      fi
      REAL_DEST_ID=$PEERS_AFTER_COPY
    done
    IFS=$OLD_IFS

    unset VERSION_AFTER
    OLD_IFS=$IFS
    IFS=$'\n'
    for PEER_ID in ${PEERS_AFTER}; do
      PEER_LOC=$(echo "${ALL_META2}" | /bin/grep "${PEER_ID}" \
          | /usr/bin/cut -d' ' -f3)
      META2_AFTER=$(/bin/ls "${PEER_LOC}/"*"/${FILE}")
      if ! [ -f "${META2_AFTER}" ]; then
        echo "${META2}: Missing base for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      if ! PEERS_AFTER_BIS=$(/usr/bin/sqlite3 "${META2_AFTER}" \
          "SELECT v FROM admin where k == 'sys.peers'" 2> /dev/null \
          | /usr/bin/tr ',' '\n'); then
        echo "${META2}: sqlite3 failed for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      OLD_IFS=$IFS
      IFS=$'\n'
      for PEER_ID_BIS in ${PEERS_AFTER}; do
        if ! echo "${PEERS_AFTER_BIS}" | /bin/grep -q "${PEER_ID_BIS}"; then
          echo "${META2}: Missing ID (${PEER_ID_BIS}) for meta2 ${PEER_ID}"
          FAIL=true
          continue
        fi
        PEERS_AFTER_BIS=$(echo "${PEERS_AFTER_BIS}" | /bin/sed "/${PEER_ID_BIS}/d")
      done
      IFS=$OLD_IFS
      if [ -n "${PEERS_AFTER_BIS}" ]; then
        echo "${META2}: Too many peers for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi

      if ! VERSION_AFTER_BIS=$(/usr/bin/sqlite3 "${META2_AFTER}" \
          "SELECT v FROM admin where k == 'version:main.admin'" \
          2> /dev/null); then
        echo "${META2}: sqlite3 failed for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      if [ -z "${VERSION_AFTER}" ]; then
        VERSION_AFTER=$VERSION_AFTER_BIS
      elif [ "${VERSION_AFTER_BIS}" != "${VERSION_AFTER}" ]; then
        echo "${META2}: Different version for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi

      /bin/cp -a "${META2}" "${TMP_FILE_BEFORE}"
      /bin/cp -a "${META2_AFTER}" "${TMP_FILE_AFTER}"
      if ! /usr/bin/sqlite3 "${TMP_FILE_BEFORE}" \
          "DELETE FROM admin WHERE k == 'sys.peers' or k == 'version:main.admin'" &> /dev/null; then
        echo "${META2}: sqlite3 failed for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      if ! /usr/bin/sqlite3 "${TMP_FILE_AFTER}" \
          "DELETE FROM admin WHERE k == 'sys.peers' or k == 'version:main.admin'" &> /dev/null; then
        echo "${META2}: sqlite3 failed for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      if ! DIFF=$(mysqldiff "${TMP_FILE_BEFORE}" "${TMP_FILE_AFTER}" \
          2> /dev/null); then
        echo "${META2}: sqldiff failed for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
      if [ -n "${DIFF}" ]; then
        echo "${META2}: Difference found for meta2 ${PEER_ID}"
        FAIL=true
        continue
      fi
    done
    IFS=$OLD_IFS

    if ! PEERS_AFTER_BIS=$(${CLI} container locate "${CONTAINER}" \
        --oio-account "${ACCOUNT}" -f shell 2> /dev/null \
        | /bin/grep 'meta2=' | sed 's/meta2=//g' | sed 's/"//g' \
        | sed 's/, /\n/g'); then
      echo "${META2}: meta2 location failed"
      FAIL=true
      continue
    fi
    if [ -z "${PEERS_AFTER_BIS}" ]; then
      echo "${META2}: No meta2 peer reported by 'container locate'"
      FAIL=true
      continue
    fi

    OLD_IFS=$IFS
    IFS=$'\n'
    for PEER_ID in ${PEERS_AFTER}; do
      if ! echo "${PEERS_AFTER_BIS}" | /bin/grep -q "${PEER_ID}"; then
        echo "${META2}: Missing ID (${PEER_ID}) in the output of 'container locate'"
        FAIL=true
        continue
      fi
      PEERS_AFTER_BIS=$(echo "${PEERS_AFTER_BIS}" | /bin/sed "/${PEER_ID}/d")
    done
    IFS=$OLD_IFS
    if [ -n "${PEERS_AFTER_BIS}" ]; then
      echo "${META2}: Too many peers reported by 'container locate'"
      FAIL=true
      continue
    fi
  done

  if [ "$(/usr/bin/find "${META2_LOC_TO_MOVE}" -type f 2> /dev/null \
      | tee "${TMPDIR:-/tmp}/unwanted_files.txt" | /usr/bin/wc -l)" -ne 0 ]; then
    echo "Extra files found for meta2 ${META2_IP_TO_MOVE} (${META2_ID}):"
    cat "${TMPDIR:-/tmp}/unwanted_files.txt"
    FAIL=true
  fi
  rm -f "${TMPDIR:-/tmp}/unwanted_files.txt"

  if [ "${FAIL}" = true ]; then
    printf "${RED}\noio-meta2-mover: FAILED\n${NO_COLOR}"
    exit 1
  else
    printf "${GREEN}\noio-meta2-mover: OK\n${NO_COLOR}"
  fi
}

oio_meta2_mover
