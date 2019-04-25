#!/usr/bin/env bash

# oio-check-version.sh
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

BASEDIR=$1
[[ -n "$BASEDIR" ]]
[[ -d "$BASEDIR" ]]

cd $BASEDIR

# This will work in the main repository, but not in forks
LATEST_TAG=$(git fetch --tags && git describe --tags --first-parent)
if [ -z "$LATEST_TAG" ]
then
  echo "No tag, cannot check"
  exit 0
fi

echo "latest tag is                      $LATEST_TAG"
export LATEST_TAG
SHORT_VERSION=$(echo "$LATEST_TAG" | sed -E 's/^([[:digit:]]+\.)([[:digit:]]+).*$/\1\2/')

PKGCONFIG_VERSION=$(pkg-config --modversion oio-sds)

echo "oio-sds short version is           $SHORT_VERSION"
echo "oio-sds version from pkg-config is $PKGCONFIG_VERSION"

# Ensure pkg-config version is up-to-date
if [ "$SHORT_VERSION" == "$PKGCONFIG_VERSION" ]
then
  echo "OK"
else
  echo "KO"
  exit 1
fi
