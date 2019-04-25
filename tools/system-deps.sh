#!/bin/bash

set -e
set -x

DISTRIB=""
CODENAME=""

get_env() {
    if [ -f /etc/centos-release ]; then
        DISTRIB="centos"
        # TODO(mbo) to be computed for next release of Centos
        CODENAME="7"
    else
        DISTRIB=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
        CODENAME=$(lsb_release -cs)
    fi

    echo "Will install dependencies for ${DISTRIB} ${CODENAME}"
}

install_deps_centos() {
    # Please keep the following list sorted!
    echo "Not Implemented"
    exit 1
}

# used by Jenkins and Travis
install_deps_ubuntu() {
    local APT="apt"
    if [ "${CODENAME}" = "xenial" ]; then
        APT="apt-get"
    fi
    ${APT} update -qq

    ${APT} install -qq -y \
        apache2 \
        apache2-dev \
        attr \
        beanstalkd \
        bison \
        curl \
        flex \
        gdb \
        lcov \
        libapache2-mod-wsgi \
        libapreq2-dev \
        libattr1-dev \
        libcurl4-gnutls-dev \
        liberasurecode-dev \
        libglib2.0-dev \
        libjson-c-dev \
        libleveldb-dev \
        liblzo2-dev \
        libsqlite3-dev \
        libzmq3-dev \
        libzookeeper-mt-dev \
        openio-asn1c \
        openio-gridinit \
        python-all-dev \
        python-dev \
        python-pbr \
        python-setuptools \
        python-virtualenv \
        redis-server \
        redis-tools \
        sqlite3 \
        zookeeper \
        zookeeper-bin \
        zookeeperd

    # add dependencies for Docker used by Jenkins
    if [ -n "${JENKINS_URL}" ]; then
        ${APT} install -qq -y \
            cmake \
            golang \
            git \
            build-essential \
            rsyslog

        # launch a simple syslog daemon to expose /dev/log
        if [ ! -a /dev/log ]; then
            rsyslogd
        fi
    fi

    # TODO(mbo) create a dedicated function
    if  [ -e "${TRAVIS}" ]; then
        systemctl start zookeeper
    fi
}

[ $(id -u) -ne 0 ] && {
    echo "not root, assume packages are already installed"
    exit 1
}

get_env
install_deps_${DISTRIB}

