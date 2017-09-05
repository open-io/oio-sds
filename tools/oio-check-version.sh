#!/bin/bash

# This will work in the main repository, but not in forks
LATEST_TAG=$(git fetch --tags && git describe --tags)
if [ -z "$LATEST_TAG" ]
then
  echo "No tag, cannot check"
  exit 0
fi

echo "latest tag is                      $LATEST_TAG"
export LATEST_TAG
SHORT_VERSION=$(echo "$LATEST_TAG" | sed -E 's/^([[:digit:]]+\.)([[:digit:]]+).*$/\1\2/')

PKG_CONFIG_PATH=/tmp/oio/lib/pkgconfig
export PKG_CONFIG_PATH
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
