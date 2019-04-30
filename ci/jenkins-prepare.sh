#!/bin/bash

set -e

apt update -qq
apt install -y -qq curl gnupg software-properties-common locales

curl http://mirror.openio.io/pub/repo/openio/APT-GPG-KEY-OPENIO-0 | apt-key add -
apt-add-repository 'deb http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse'
apt-add-repository 'deb http://mirror.openio.io/pub/repo/openio/sds/18.10/ubuntu/ bionic/'

echo "Install system dependencies"
apt update -qq
apt install -y -qq $(awk '{print $1}' ci/deps-ubuntu-bionic.txt) \
                   cmake \
                   golang \
                   git \
                   build-essential \
                   rsyslog

# launch a simple syslog daemon to expose /dev/log
rsyslogd

locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8
