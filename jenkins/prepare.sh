#!/bin/bash

apt update -qq
apt install -y -qq curl gnupg software-properties-common locales

curl http://mirror.openio.io/pub/repo/openio/APT-GPG-KEY-OPENIO-0 | apt-key add -
apt-add-repository 'deb http://archive.ubuntu.com/ubuntu/ bionic-backports main restricted universe multiverse'
apt-add-repository 'deb http://mirror.openio.io/pub/repo/openio/sds/18.10/ubuntu/ bionic/'

apt update -qq
apt install -qq -y apache2 apache2-dev attr beanstalkd bison curl flex gdb lcov libapache2-mod-wsgi \
    libapreq2-dev libattr1-dev libcurl4-gnutls-dev liberasurecode-dev libglib2.0-dev \
    libjson-c-dev libleveldb-dev liblzo2-dev libsqlite3-dev libzmq3-dev libzookeeper-mt-dev \
    openio-asn1c openio-gridinit python-all-dev python-dev python-pbr python-setuptools \
    python-virtualenv redis-server redis-tools sqlite3 zookeeper zookeeper-bin zookeeperd \
    cmake golang git build-essential redis-server rsyslog

locale-gen en_US.UTF-8
update-locale LANG=en_US.UTF-8

# launch a simple syslog daemon to expose /dev/log
rsyslogd
