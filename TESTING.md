# Test

You'll need a running cluster. Maybe a 3-nodes docker setup, or use
./tools/oio-reset.sh

## OpenIO SDS yaml config example

Put your cluster configuration in the following file, you also have to change
`sds_path` to replace ${USER}:

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
      ecd:
      - {addr: '172.17.0.4:6001', num: '1', path: /var/lib/oio/sds/OPENIO/ecd-1}
      event-agent:
      - {num: '1', path: /var/lib/oio/sds/OPENIO/event-agent-1}
      redis:
      - {addr: '172.17.0.4:6379', num: '1', path: /var/lib/oio/sds/OPENIO/redis-1}
      sqlx:
      - {addr: '172.17.0.4:6019', num: '1', path: /var/lib/oio/sds/OPENIO/sqlx-1}
      - {addr: '172.17.0.4:6020', num: '2', path: /var/lib/oio/sds/OPENIO/sqlx-2}
      - {addr: '172.17.0.4:6021', num: '3', path: /var/lib/oio/sds/OPENIO/sqlx-3}
    EOF

## Testing environment

Then follow those steps to setup the automated test suite environment:

  export OIO_NS=$(sed -e '/^namespace: .*/!d' -e 's/^namespace: \(.*\)$/\1/' ${SDS_TEST_CONFIG_FILE})
  export OIO_PROXY=$(sed -e '/^proxy: .*/!d' -e 's/^proxy: \(.*\)$/proxy=\1/' ${SDS_TEST_CONFIG_FILE})

  cat << EOF > ~/.oio/sds.conf
  [default]
  [OPENIO]
  ${OIO_PROXY}
  EOF

  virtualenv venv-tests
  source venv-tests/bin/activate
  pip install -r all-requirements.txt
  pip install -r test-requirements.txt
  # Some tests run the "openio" CLI, so install it (from sources)
  python setup.py install

## Launching tests

Now you can run a single test module:

  nosetests tests/functional/cli/admin

Or you can run the whole test suite:

  nosetests
