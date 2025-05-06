# Test

## Setup a cluster

### Locally, the old way

Fetch and build the sources:

```bash
SOURCES=$(mktemp -d)
BUILD=$(mktemp -d)
INSTALL=~/.oio/sds

cd ${SOURCES}
sudo apt install $(cat .cds/deps-ubuntu-focal.txt)
git clone ssh://git@github.com/open-io/oio-sds.git
git submodule update --init
cd ${BUILD}
cmake -D CMAKE_INSTALL_PREFIX=$INSTALL -D CMAKE_BUILD_TYPE=Debug ${SRC}/oio-sds
make -j 8

# This is the ugly to install components using cmake
cmake --install . --component Unspecified # analog to "make install"
cmake --install . --component dev
```

Have a Python virtual environment with all the runtime dependencies of the Python tools of the oio-sds suite. 

```bash
cd ${SRC}
mkdir ~/.local/venv
sudo apt install virtualenv
virtualenv -p python3 ~/.local/venv/oio
source ~/.local/venv/oio/bin/activate
pip install --upgrade pip virtualenv tox
pip install --upgrade -r requirements.txt
pip install --upgrade -r test-requirements.txt
pip install -e .
```

Fetch and install the side services we depend on, kafka and zookeeper, and spawn their services the standalone way.
You need:
- an Apache Kafka implementation, whether it's vanilla kafka or rather RedPanda
- an Apache Zookeeper implementation (for meta\* and kafka)
- a Redis server: on a Debian/Ubuntu dev host, it is brought and maintained by the distro 

```bash
KAFKA_VERSION=3.7.0

# fetch and install Kafka and Zookeeper
cd ~/Downloads
wget https://downloads.apache.org/kafka/${KAFKA_VERSION}/kafka_2.13-${KAFKA_VERSION}.tgz
cd ~/.local
tar xzf ~/Downloads/kafka_2.13-${KAFKA_VERSION}.tgz

mkdir -p ~/.local/var/lib
mkdir -p ~/.local/var/lib/{zookeeper,kafka}

# Patch both configs to work locally and standalone
ZK_CFG=~/.local/kafka_2.13-${KAFKA_VERSION}/config/zookeeper.properties
KAFKA_CFG=~/.local/kafka_2.13-${KAFKA_VERSION}/config/server.properties

sed -i -e "s,^dataDir=.*,dataDir=$HOME/.local/var/lib/zookeeper," ${ZK_CFG}
if ! grep -q clientPortAddress $ZK_CFG ; then
  echo 'clientPortAddress=127.0.0.1' >> ${ZK_CFG}
fi
sed -i -e "s,log.dirs=.*,log.dirs=$HOME/.local/var/lib/kafka," ${KAFKA_CFG}
sed -i -e "s,#listeners=.*,listeners=PLAINTEXT://:19092," ${KAFKA_CFG}

# spawn the services
~/.local/kafka_2.13-${KAFKA_VERSION}/bin/zookeeper-server-start.sh ${ZK_CFG}
~/.local/kafka_2.13-${KAFKA_VERSION}/bin/kafka-server-start.sh ${KAFKA_CFG}
```

Now start the services using `oio-reset.sh`

```bash
source ~/.local/venv/oio/bin/activate
${INSTALL}/bin/oio-reset.sh
```

## Run the tests

You'll need a running cluster. Maybe a 3-nodes docker setup, or use `oio-reset.sh`,
either located using the PATH or found at  ${INSTALL}/bin/oio-reset.sh if you
followed the doc here-above.

### OpenIO SDS yaml config example

Put your cluster configuration in the following file, you also have to change
`sds_path` to replace `${USER}`:

```bash
    export SDS_TEST_CONFIG_FILE=${HOME}/.oio/sds/conf/test.yml

    cat << EOF > ${SDS_TEST_CONFIG_FILE}

    account: test_account
    chunk_size: 1048576
    config: {ns.chunk_size: 1048576, ns.storage_policy: THREECOPIES, proxy.cache.enabled: false}
    storage_policy: THREECOPIES
    container_replicas: 3
    directory_replicas: 3
    meta1_digits: 4
    monitor_period: 1
    namespace: OPENIO
    proxy: 172.17.0.4:6006
    sds_path: /home/${USER}/.oio/sds

    services:
      conscience:
      - {addr: '172.17.0.4:6000', num: '1', path: /var/lib/oio/sds/OPENIO/conscience-1}
      proxy:
      - {addr: '172.17.0.4:6006', num: '1', path: /var/lib/oio/sds/OPENIO/proxy-1}
      - {addr: '172.17.0.3:6006', num: '1', path: /var/lib/oio/sds/OPENIO/proxy-1}
      - {addr: '172.17.0.2:6006', num: '1', path: /var/lib/oio/sds/OPENIO/proxy-1}
      rdir:
      - {addr: '172.17.0.2:6301', num: '1', path: /var/lib/oio/sds/OPENIO/rdir-1}
      - {addr: '172.17.0.3:6301', num: '2', path: /var/lib/oio/sds/OPENIO/rdir-1}
      - {addr: '172.17.0.4:6301', num: '3', path: /var/lib/oio/sds/OPENIO/rdir-1}
      account:
      - {addr: '172.17.0.2:6009', num: '1', path: /var/lib/oio/sds/OPENIO/account-1}
      - {addr: '172.17.0.3:6009', num: '1', path: /var/lib/oio/sds/OPENIO/account-1}
      - {addr: '172.17.0.4:6009', num: '1', path: /var/lib/oio/sds/OPENIO/account-1}
      rawx:
      - {addr: '172.17.0.2:6201', num: '1', path: /var/lib/oio/sds/OPENIO/rawx-1}
      - {addr: '172.17.0.3:6201', num: '1', path: /var/lib/oio/sds/OPENIO/rawx-1}
      - {addr: '172.17.0.4:6201', num: '1', path: /var/lib/oio/sds/OPENIO/rawx-1}
      meta0:
      - {addr: '172.17.0.2:6001', num: '1', path: /var/lib/oio/sds/OPENIO/meta0-1}
      meta1:
      - {addr: '172.17.0.3:6111', num: '1', path: /var/lib/oio/sds/OPENIO/meta1-1}
      meta2:
      - {addr: '172.17.0.2:6121', num: '1', path: /var/lib/oio/sds/OPENIO/meta2-1}
      - {addr: '172.17.0.3:6121', num: '1', path: /var/lib/oio/sds/OPENIO/meta2-1}
      - {addr: '172.17.0.4:6121', num: '1', path: /var/lib/oio/sds/OPENIO/meta2-1}
      container:
      - {addr: '172.17.0.4:6002', num: '1', path: /var/lib/oio/sds/OPENIO/container-1}
      event-agent:
      - {num: '1', path: /var/lib/oio/sds/OPENIO/event-agent-1}
      redis:
      - {addr: '172.17.0.4:6379', num: '1', path: /var/lib/oio/sds/OPENIO/redis-1}
      sqlx:
      - {addr: '172.17.0.4:6019', num: '1', path: /var/lib/oio/sds/OPENIO/sqlx-1}
      - {addr: '172.17.0.4:6020', num: '2', path: /var/lib/oio/sds/OPENIO/sqlx-2}
      - {addr: '172.17.0.4:6021', num: '3', path: /var/lib/oio/sds/OPENIO/sqlx-3}
    EOF
```

### Testing environment

Then follow those steps to setup the automated test suite environment:

```bash
  export OIO_NS=$(sed -e '/^namespace: .*/!d' -e 's/^namespace: \(.*\)$/\1/' ${SDS_TEST_CONFIG_FILE})
  export OIO_PROXY=$(sed -e '/^proxy: .*/!d' -e 's/^proxy: \(.*\)$/proxy=\1/' ${SDS_TEST_CONFIG_FILE})

  cat << EOF > ~/.oio/sds.conf
  [default]
  [OPENIO]
  ${OIO_PROXY}
  EOF

  virtualenv venv-tests
  source venv-tests/bin/activate
  pip install -r test-requirements.txt
  # Some tests run the "openio" CLI, so install it (from sources)
  pip install -e ${SRCDIR}
  ${SRCDIR}/tools/patch-python-modules.sh
```

### Launching tests

Now you can run a single test module:

```bash
  pytest tests/functional/cli/admin
```

Or you can run the whole test suite:

```bash
  pytest tests
```
