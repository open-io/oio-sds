# Copyright (C) 2021 OVH SAS
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3.0 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.

from oio.common.green import eventlet, eventlet_yield, time, Empty, LightQueue

from greenlet import GreenletExit
from urllib.parse import unquote

from oio.common import exceptions
from oio.common.client import ProxyClient
from oio.common.constants import EXISTING_SHARD_STATE_ABORTED, \
    EXISTING_SHARD_STATE_SHARDED, HEADER_PREFIX, M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_OBJECTS, M2_PROP_SHARDING_LOWER, \
    M2_PROP_SHARDING_ROOT, M2_PROP_SHARDING_STATE, M2_PROP_SHARDING_UPPER, \
    M2_PROP_SHARDS, NEW_SHARD_STATE_CLEANED_UP, STRLEN_CID
from oio.common.easy_value import boolean_value, int_value, is_hexa, true_value
from oio.common.exceptions import BadRequest, OioException, OioTimeout
from oio.common.json import json
from oio.common.logger import get_logger
from oio.common.utils import cid_from_name, depaginate
from oio.container.client import ContainerClient
from oio.common.decorators import ensure_request_id
from oio.directory.admin import AdminClient
from oio.event.beanstalk import Beanstalk, ResponseError


class SavedWritesApplicator(object):

    def __init__(self, sharding_client, parent_shard, new_shards,
                 logger=None, **kwargs):
        self.sharding_client = sharding_client
        self.logger = logger or get_logger(dict())
        url = parent_shard['sharding']['queue']
        tube = parent_shard['cid'] + '.sharding-' \
            + str(parent_shard['sharding']['timestamp'])
        self.logger.info('Connecting to beanstalk tube (URL=%s TUBE=%s)',
                         url, tube)
        self.beanstalk = Beanstalk.from_url(url)
        self.beanstalk.use(tube)
        self.beanstalk.watch(tube)
        self.new_shards = list()
        for new_shard in new_shards:
            self.new_shards.append(new_shard.copy())

        self.main_thread = None
        self.queue_is_empty = False
        self.flush_queries = False
        self.running = True

    def _update_new_shard(self, new_shard, buffer_size=1000, **kwargs):
        queue = new_shard['queue']
        last_queries = False
        buffer = list()
        while True:
            max_remaining = buffer_size
            try:
                queries = queue.get(block=False)
                if queries is None:
                    last_queries = True
                    max_remaining = 0
                else:
                    buffer += queries
            except Empty:
                if self.flush_queries and buffer:
                    max_remaining = 0
                else:
                    eventlet_yield()
                    continue

            while buffer and len(buffer) >= max_remaining:
                queries_to_sent = buffer[:buffer_size]
                buffer = buffer[buffer_size:]
                self.sharding_client._update_new_shard(
                    new_shard, queries_to_sent, **kwargs)

            if last_queries:
                if buffer:
                    raise OioException('Should never happen')
                return

    def _fetch_and_dispatch_queries(self, **kwargs):
        last_check = False
        while True:
            data = None
            try:
                job_id, data = self.beanstalk.reserve(timeout=0)
                self.queue_is_empty = False
                self.beanstalk.delete(job_id)
            except ResponseError as exc:
                if 'TIMED_OUT' in str(exc):
                    self.queue_is_empty = True
                    if not self.running:
                        if last_check:
                            for new_shard in self.new_shards:
                                new_shard['queue'].put(None)
                            return
                        last_check = True
                    else:
                        eventlet_yield()
                    continue
                raise

            if not data:
                continue
            data = json.loads(data)
            path = data.get('path')
            queries = data['queries']
            if not queries:
                continue

            relevant_queues = list()
            for new_shard in self.new_shards:
                if not path:
                    relevant_queues.append(new_shard['queue'])
                    continue
                if new_shard['lower'] and path <= new_shard['lower']:
                    continue
                if new_shard['upper'] and path > new_shard['upper']:
                    continue
                relevant_queues.append(new_shard['queue'])
            if not relevant_queues:
                raise OioException(
                    'The path does not belong to any of the shards')
            for relevant_queue in relevant_queues:
                relevant_queue.put(queries)

    def apply_in_background(self, **kwargs):
        for new_shard in self.new_shards:
            new_shard['queue'] = LightQueue()
            new_shard['thread'] = eventlet.spawn(
                self._update_new_shard, new_shard, **kwargs)
        self.main_thread = eventlet.spawn(
            self._fetch_and_dispatch_queries, **kwargs)

        # Let these threads start
        eventlet_yield()

    def wait_until_queue_is_almost_empty(self, limit=100, timeout=30,
                                         **kwargs):
        """
        Checks if the receive queue is empty
        and if the send queues are almost empty.
        :keyword limit: Limit at which send queues are almost empty.
        :type limit: `int`
        :keyword timeout: Maximum waiting time.
        :type timeout: `int`
        """
        start_time = time.time()
        while True:
            if self.queue_is_empty:
                for new_shard in self.new_shards:
                    shard_queue = new_shard.get('queue')
                    if shard_queue is not None and shard_queue.qsize() > limit:
                        break
                else:
                    return

            # Check if the timeout has not expired
            if timeout is not None and time.time() - start_time > timeout:
                raise OioTimeout(
                    'After more than %d seconds, '
                    'the queue is still not nearly empty' % timeout)

            # In the meantime, let the other threads run
            eventlet_yield()

    def flush(self, **kwargs):
        self.flush_queries = True

    def close(self, timeout=10, **kwargs):
        self.running = False
        self.flush_queries = True
        success = True

        # Wait for the timeout to expire before killing all threads
        all_threads = list()
        if self.main_thread is not None:
            all_threads.append(self.main_thread)
        for new_shard in self.new_shards:
            shard_thread = new_shard.get('thread')
            if shard_thread is not None:
                all_threads.append(shard_thread)
        start_time = time.time()
        while True:
            if all((thread.dead for thread in all_threads)):
                break

            # Check if the timeout has not expired
            if time.time() - start_time > timeout:
                for thread in all_threads:
                    thread.kill()
                break

            # In the meantime, let the other threads run
            eventlet_yield()

        # Close the beanstalk connection
        try:
            self.beanstalk.close()
        except Exception as exc:
            self.logger.error('Failed to close beanstalk connection: %s', exc)
            success = False

        # Fetch all results of all threads.
        # These operations should not be blocking because
        # the threads terminated normally or the threads were killed.
        if self.main_thread is not None:
            try:
                self.main_thread.wait()
            except GreenletExit:
                self.logger.error(
                    'Failed to fetch and dispatch queries: '
                    'After more than %d seconds, '
                    'the thread is still not finished', timeout)
                success = False
            except Exception as exc:
                self.logger.error(
                    'Failed to fetch and dispatch queries: %s', exc)
                success = False
        for new_shard in self.new_shards:
            shard_thread = new_shard.get('thread')
            if shard_thread is None:
                continue
            try:
                shard_thread.wait()
            except GreenletExit:
                self.logger.error(
                    'Failed to update new shard (CID=%s): '
                    'After more than %d seconds, '
                    'the thread is still not finished',
                    new_shard['cid'], timeout)
                success = False
            except Exception as exc:
                self.logger.error(
                    'Failed to update new shard (CID=%s): %s',
                    new_shard['cid'], exc)
                success = False

        return success


class ContainerSharding(ProxyClient):

    DEFAULT_STRATEGY = 'shard-with-partition'
    DEFAULT_PARTITION = [50, 50]
    DEFAULT_SHARD_SIZE = 100000
    DEFAULT_CREATE_SHARD_TIMEOUT = 60
    DEFAULT_SAVE_WRITES_TIMEOUT = 60

    def __init__(self, conf, logger=None, pool_manager=None, **kwargs):
        super(ContainerSharding, self).__init__(
            conf, request_prefix="/container/sharding", logger=logger,
            pool_manager=pool_manager, **kwargs)

        # Make sure to use up-to-date information
        self.force_master = True

        self.admin = AdminClient(
            self.conf, pool_manager=self.pool_manager, logger=self.logger,
            **kwargs)
        self.container = ContainerClient(
            self.conf, pool_manager=self.pool_manager, logger=self.logger,
            **kwargs)
        self.create_shard_timeout = int_value(
            kwargs.get('create_shard_timeout'),
            self.DEFAULT_CREATE_SHARD_TIMEOUT)
        self.save_writes_timeout = int_value(
            kwargs.get('save_writes_timeout'),
            self.DEFAULT_SAVE_WRITES_TIMEOUT)

    def _make_params(self, account=None, reference=None, path=None,
                     cid=None, **kwargs):
        if cid:
            params = {'cid': cid}
        else:
            params = {'acct': account, 'ref': reference}
        if path:
            params.update({'path': path})
        return params

    def _meta_to_shard(self, meta):
        sys = meta['system']
        root_cid = sys.get(M2_PROP_SHARDING_ROOT)
        shard_lower = sys.get(M2_PROP_SHARDING_LOWER)
        shard_upper = sys.get(M2_PROP_SHARDING_UPPER)
        if not any([root_cid, shard_lower, shard_upper]):
            # Not a shard
            return None, None
        shard_account = sys.get(M2_PROP_ACCOUNT_NAME)
        shard_container = sys.get(M2_PROP_CONTAINER_NAME)
        if not all([root_cid, shard_account, shard_container, shard_lower,
                    shard_upper]):
            raise OioException('Missing shard information')
        if not shard_lower.startswith('>'):
            raise OioException('Lower malformed')
        if not shard_upper.startswith('<'):
            raise OioException('Upper malformed')
        shard = {
            'index': -1,
            'lower': shard_lower[1:],
            'upper': shard_upper[1:],
            'cid': cid_from_name(shard_account, shard_container),
            'metadata': None,
            'count': int_value(sys.get(M2_PROP_OBJECTS), 0)
        }
        return root_cid, shard

    def _shards_equal(self, shard1, shard2):
        return ('lower' in shard1 and 'lower' in shard2 and
                shard1['lower'] == shard2['lower'] and
                'upper' in shard1 and 'upper' in shard2 and
                shard1['upper'] == shard2['upper'] and
                'cid' in shard1 and 'cid' in shard2 and
                shard1['cid'].upper() == shard2['cid'].upper())

    def _sharding_in_progress(self, meta):
        sharding_state = int_value(
            meta['system'].get(M2_PROP_SHARDING_STATE), 0)
        return (sharding_state and
                sharding_state != EXISTING_SHARD_STATE_SHARDED and
                sharding_state != EXISTING_SHARD_STATE_ABORTED and
                sharding_state != NEW_SHARD_STATE_CLEANED_UP)

    def _check_shards(self, shards, are_new=False, partial=False, **kwargs):
        previous_shard = None
        delta = None
        for i, shard in enumerate(shards):
            shard = self._format_shard(shard, is_new=are_new, **kwargs)
            if partial:
                if delta is None:
                    delta = shard['index'] - i
            else:
                delta = 0
            if shard['index'] != i + delta:
                raise ValueError('Missing "index" %d' % i)

            if previous_shard is None:
                # first shard
                if not partial and shard['lower'] != '':
                    raise ValueError(
                        'Expected an empty "lower" for the first shard')
            elif shard['lower'] != previous_shard['upper']:
                raise ValueError(
                    'Expected the same "lower" as the "upper" '
                    'of the previous shard')

            # Send the shard when everything has been verified.
            # This is why it is necessary to send the previous one
            # and not the current.
            if previous_shard is not None:
                yield previous_shard
            previous_shard = shard

        if previous_shard is not None:
            # last shard
            if not partial and previous_shard['upper'] != '':
                raise ValueError(
                    'Expected an empty "upper" for the last shard')
            yield previous_shard

    def _format_shard(self, shard, is_new=False, **kwargs):
        if not isinstance(shard, dict):
            raise ValueError(
                'Expected an object to describe a shard range')
        formatted_shard = dict()

        shard_index = shard.get('index')
        if shard_index is None:
            raise ValueError('Expected an "index" in the shard range')
        try:
            shard_index = int(shard_index)
        except ValueError:
            raise ValueError('Expected a number for the "index"')
        if shard_index < 0:
            raise ValueError('Expected a positive number for the "index"')
        formatted_shard['index'] = shard_index

        shard_lower = shard.get('lower')
        if shard_lower is None:
            raise ValueError('Expected a "lower" in the shard range')
        if isinstance(shard_lower, bytes):
            shard_lower = shard_lower.decode('utf-8')
        elif not isinstance(shard_lower, str):
            raise ValueError('Expected a string for the "lower"')
        formatted_shard['lower'] = shard_lower

        shard_upper = shard.get('upper')
        if shard_upper is None:
            raise ValueError('Expected an "upper" in the shard range')
        if isinstance(shard_upper, bytes):
            shard_upper = shard_upper.decode('utf-8')
        elif not isinstance(shard_upper, str):
            raise ValueError('Expected a string for the "upper"')
        formatted_shard['upper'] = shard_upper

        if shard['lower'] != '' and shard['upper'] != '' \
                and shard['lower'] >= shard['upper']:
            raise ValueError('Expected an "upper" greater the "lower"')

        if not is_new:
            shard_cid = shard.get('cid')
            if shard_cid is None:
                raise ValueError('Expected a "cid" in the shard range')
            if isinstance(shard_cid, bytes):
                shard_cid = shard_cid.decode('utf-8')
            elif not isinstance(shard_cid, str):
                raise ValueError('Expected a string for the "cid"')
            if not is_hexa(shard_cid, size=STRLEN_CID):
                raise ValueError('Expected a container ID for the "cid"')
            formatted_shard['cid'] = shard_cid

        shard_metadata = shard.get('metadata')
        if shard_metadata is not None \
                and not isinstance(shard['metadata'], dict):
            raise ValueError('Expected a JSON object for the "metadata"')
        formatted_shard['metadata'] = shard_metadata

        shard_count = shard.get('count')
        if shard_count is None and shard_metadata:
            shard_count = shard_metadata.pop('count', None)
        if shard_count is not None:
            try:
                shard_count = int(shard_count)
            except ValueError:
                raise ValueError('Expected a number for the "count"')
            formatted_shard['count'] = shard_count

        return formatted_shard

    def format_shard(self, shard, **kwargs):
        if not isinstance(shard, dict):
            try:
                shard = json.loads(shard)
                if not isinstance(shard, dict):
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError('Expected shard range')
        return self._format_shard(shard, **kwargs)

    def format_shards(self, shards, are_new=False, **kwargs):
        if not isinstance(shards, list):
            try:
                shards = json.loads(shards)
                if not isinstance(shards, list):
                    raise ValueError()
            except (TypeError, ValueError):
                raise ValueError('Expected a list of shard ranges')
        formatted_shards = list()
        for shard in shards:
            formatted_shards.append(
                self._format_shard(shard, is_new=are_new, **kwargs))
        formatted_shards.sort(
            key=lambda formatted_shard: formatted_shard['index'])
        # Check all shards before returning the formatted shards
        return list(self._check_shards(
            formatted_shards, are_new=are_new, **kwargs))

    def _find_shards(self, shard, strategy, strategy_params=None, **kwargs):
        params = self._make_params(cid=shard['cid'], **kwargs)
        params['strategy'] = strategy
        resp, body = self._request('GET', '/find', params=params,
                                   json=strategy_params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)

        if not body.get('shard_ranges'):
            raise OioException('Missing found shards')
        return body

    def _find_shards_with_partition(self, shard, incomplete_shard=None,
                                    strategy_params=None, **kwargs):
        if strategy_params is None:
            strategy_params = dict()
        partition = strategy_params.get('partition')
        if not partition:
            partition = self.DEFAULT_PARTITION
        else:
            if isinstance(partition, str):
                partition = partition.split(',')
            partition = [float(part) for part in partition]
        threshold = int_value(strategy_params.get('threshold'),
                              self.DEFAULT_SHARD_SIZE)

        formatted_strategy_params = dict()
        formatted_strategy_params['partition'] = partition
        if threshold:
            formatted_strategy_params['threshold'] = threshold

        found_shards = self._find_shards(
            shard, 'shard-with-partition',
            strategy_params=formatted_strategy_params, **kwargs)
        return None, found_shards['shard_ranges']

    def _find_shards_with_size(self, shard, incomplete_shard=None,
                               strategy_params=None, **kwargs):
        first_shard_size = None
        shard_size = int_value(strategy_params.get('shard_size'),
                               self.DEFAULT_SHARD_SIZE)
        if incomplete_shard is not None:
            first_shard_size = incomplete_shard.get('available')

        formatted_strategy_params = dict()
        formatted_strategy_params['shard_size'] = shard_size
        if first_shard_size:
            formatted_strategy_params['first_shard_size'] = first_shard_size

        found_shards = self._find_shards(
            shard, 'shard-with-size',
            strategy_params=formatted_strategy_params, **kwargs)
        return shard_size, found_shards['shard_ranges']

    STRATEGIES = {
        'shard-with-partition': _find_shards_with_partition,
        'shard-with-size': _find_shards_with_size,
        'rebalance': _find_shards_with_size
    }

    def _find_formatted_shards(self, shard, strategy=None, index=0, **kwargs):
        if strategy is None:
            strategy = self.DEFAULT_STRATEGY

        find_shards = self.STRATEGIES.get(strategy)
        if find_shards is None:
            raise OioException('Unknown sharding strategy')
        max_shard_size, found_shards = find_shards(self, shard, **kwargs)

        found_formatted_shards = list()
        for found_shard in found_shards:
            found_shard['index'] = index
            index += 1
            found_formatted_shard = self._format_shard(
                found_shard, is_new=True, **kwargs)
            found_formatted_shards.append(found_formatted_shard)
        return max_shard_size, found_formatted_shards

    @ensure_request_id
    def find_shards(self, account, container, **kwargs):
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(account, container),
            'metadata': None
        }
        _, formatted_shards = self._find_formatted_shards(
            fake_shard, **kwargs)
        return self._check_shards(formatted_shards,
                                  are_new=True, partial=True, **kwargs)

    def _find_all_formatted_shards(self, root_account, root_container,
                                   strategy=None, **kwargs):
        no_shrinking = True
        if strategy is None:
            strategy = self.DEFAULT_STRATEGY
        if strategy == 'rebalance':
            no_shrinking = False

        current_shards = self.show_shards(root_account, root_container,
                                          **kwargs)

        incomplete_shard = None
        index = 0
        for current_shard in current_shards:
            # Find the possible new shards
            max_shard_size, found_shards = self._find_formatted_shards(
                current_shard, strategy=strategy, index=index,
                incomplete_shard=incomplete_shard, **kwargs)

            # If the last shard was too small,
            # merge this last shard with this first shard
            first_shard = found_shards[0]
            if incomplete_shard is not None:
                if incomplete_shard['upper'] != first_shard['lower']:
                    raise OioException('Shards do not follow one another')
                first_shard['lower'] = incomplete_shard['lower']
                first_shard['count'] = first_shard['count'] \
                    + incomplete_shard['count']

            # Return all found shards, except the last shard
            for found_shard in found_shards[:-1]:
                yield found_shard

            # If the last shard is the correct size,
            # return it immediately
            last_shard = found_shards[-1]
            if no_shrinking or max_shard_size is None \
                    or last_shard['count'] >= max_shard_size:
                index = last_shard['index'] + 1
                incomplete_shard = None
                yield last_shard
            else:
                index = last_shard['index']
                incomplete_shard = last_shard
                available = max_shard_size - incomplete_shard['count']
                if available > 0:
                    incomplete_shard['available'] = available

        if incomplete_shard is not None:
            yield incomplete_shard
            return
        if index > 0:
            return

        # Container not yet sharded
        current_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid_from_name(root_account, root_container),
            'metadata': None
        }
        _, found_shards = self._find_formatted_shards(
            current_shard, strategy=strategy, **kwargs)
        for found_shard in found_shards:
            yield found_shard

    @ensure_request_id
    def find_all_shards(self, root_account, root_container, **kwargs):
        formatted_shards = self._find_all_formatted_shards(
            root_account, root_container, **kwargs)
        return self._check_shards(formatted_shards, are_new=True, **kwargs)

    def _prepare_sharding(self, shard, action=None, **kwargs):
        """
        If merge:
        - Change the sharding state to indicate
          that the container is being merged.
        else:
        - Change the sharding state to indicate
          that the container is being sharded.
        - Create a queue to save all write on this container.
        - Create a copy meta2 database to handle this copy
          without disturbing the container.
        """
        params = self._make_params(cid=shard['cid'], **kwargs)
        if action:
            params['action'] = action
        resp, body = self._request('POST', '/prepare', params=params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)

        timestamp = int_value(body.get('timestamp'), None)
        if timestamp is not None:
            body['timestamp'] = timestamp
        else:
            raise OioException('Missing timestamp')
        return body

    def _create_shard(self, root_account, root_container, parent_shard,
                      shard, **kwargs):
        shard_account = '.shards_%s' % (root_account)
        shard_container = '%s-%s-%d-%d' % (
            root_container, parent_shard['cid'],
            parent_shard['sharding']['timestamp'],
            shard['index'])

        # Create shard container
        shard_info = shard.copy()
        shard_info['root'] = cid_from_name(root_account, root_container)
        shard_info['parent'] = parent_shard['cid']
        shard_info['timestamp'] = parent_shard['sharding']['timestamp']
        shard_info['master'] = parent_shard['sharding']['master']

        # Fill the shard info with the CID of the shard container
        # Even the request fails,
        # the CID will be used to attempt to delete this new shard.
        shard['cid'] = cid_from_name(shard_account, shard_container)

        params = self._make_params(account=shard_account,
                                   reference=shard_container, **kwargs)
        resp, body = self._request(
            'POST', '/create_shard', params=params, json=shard_info,
            timeout=self.create_shard_timeout, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _merge_shards(self, smaller_shard, bigger_shard, **kwargs):
        params = self._make_params(cid=bigger_shard['cid'], **kwargs)
        formatted_smaller_shard = self._format_shard(smaller_shard, **kwargs)
        metadata = formatted_smaller_shard.get('metadata') or dict()
        metadata['timestamp'] = smaller_shard['sharding']['timestamp']
        formatted_smaller_shard['metadata'] = metadata
        truncated = True
        while truncated:
            resp, body = self._request(
                'POST', '/merge', params=params,
                json=formatted_smaller_shard, **kwargs)
            if resp.status != 204:
                raise exceptions.from_response(resp, body)
            truncated = boolean_value(resp.getheader('x-oio-truncated'), False)

    def _update_new_shard(self, new_shard, queries, **kwargs):
        if not queries:
            return

        params = self._make_params(cid=new_shard['cid'], **kwargs)
        resp, body = self._request('POST', '/update_shard', params=params,
                                   json=queries, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _lock_shard(self, shard, **kwargs):
        params = self._make_params(cid=shard['cid'], **kwargs)
        resp, body = self._request('POST', '/lock', params=params, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _replace_shards(self, root_account, root_container, shards,
                        root_cid=None, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container,
                                   cid=root_cid, **kwargs)
        resp, body = self._request('POST', '/replace', params=params,
                                   json=shards, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _clean(self, shard, no_vacuum=False, attempts=1, **kwargs):
        params = self._make_params(cid=shard['cid'], **kwargs)
        truncated = True
        while truncated:
            for i in range(attempts):
                try:
                    resp, body = self._request(
                        'POST', '/clean', params=params, **kwargs)
                    if resp.status != 204:
                        raise exceptions.from_response(resp, body)
                    break
                except BadRequest:
                    raise
                except Exception as exc:
                    if i >= attempts - 1:
                        raise
                    self.logger.warning(
                        'Failed to clean the container (CID=%s), '
                        'retrying...: %s', shard['cid'], exc)
            truncated = boolean_value(resp.getheader('x-oio-truncated'), False)

        if not no_vacuum:
            try:
                self.admin.vacuum_base('meta2', cid=shard['cid'], **kwargs)
            except Exception as exc:
                self.logger.warning('Failed to vacuum container (CID=%s): %s',
                                    shard['cid'], exc)

    @ensure_request_id
    def clean_container(self, account, container, cid=None, **kwargs):
        fake_shard = {
            'index': -1,
            'lower': '',
            'upper': '',
            'cid': cid or cid_from_name(account, container),
            'metadata': None
        }
        self._clean(fake_shard, **kwargs)

    def _safe_clean(self, shard, **kwargs):
        try:
            self._clean(shard, attempts=3, **kwargs)
        except Exception as exc:
            self.logger.warning(
                'Failed to clean the container (CID=%s): %s',
                shard['cid'], exc)

    def _show_shards(self, root_account, root_container, root_cid=None,
                     limit=None, marker=None, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container,
                                   cid=root_cid, **kwargs)
        params.update({'max': limit, 'marker': marker})
        resp, body = self._request('GET', '/show', params=params, **kwargs)
        if resp.status != 200:
            raise exceptions.from_response(resp, body)
        body['truncated'] = true_value(
            resp.headers.get(HEADER_PREFIX + 'list-truncated'))
        marker_header = HEADER_PREFIX + 'list-marker'
        if marker_header in resp.headers:
            body['next_marker'] = unquote(resp.headers.get(marker_header))
        return body

    def _show_formatted_shards(self, root_account, root_container,
                               no_paging=True, **kwargs):
        shards = None
        if no_paging:
            shards = depaginate(
                self._show_shards,
                listing_key=lambda x: x['shard_ranges'],
                marker_key=lambda x: x.get('next_marker'),
                truncated_key=lambda x: x['truncated'],
                root_account=root_account,
                root_container=root_container,
                **kwargs)
        else:
            shards = self._show_shards(root_account, root_container,
                                       **kwargs)['shard_ranges']
        for i, shard in enumerate(shards):
            shard['index'] = i
            shard = self._format_shard(shard, **kwargs)
            yield shard

    @ensure_request_id
    def show_shards(self, root_account, root_container, **kwargs):
        formatted_shards = self._show_formatted_shards(
            root_account, root_container, **kwargs)
        partial = kwargs.get('marker') or not kwargs.get('no_paging')
        return self._check_shards(formatted_shards, partial=partial, **kwargs)

    def _abort_sharding(self, shard, attempts=1, **kwargs):
        for i in range(attempts):
            try:
                params = self._make_params(cid=shard['cid'], **kwargs)
                resp, body = self._request('POST', '/abort', params=params,
                                           **kwargs)
                if resp.status != 204:
                    raise exceptions.from_response(resp, body)
                break
            except Exception as exc:
                if i >= attempts - 1:
                    raise
                self.logger.warning(
                    'Failed to abort sharding (CID=%s), '
                    'retrying...: %s', shard['cid'], exc)

    def _safe_abort_sharding(self, shard, **kwargs):
        try:
            self._abort_sharding(shard, attempts=3, **kwargs)
            return True
        except Exception as exc:
            self.logger.error(
                'Failed to abort sharding (CID=%s): %s',
                shard['cid'], exc)
            return False

    def _shard_container(self, root_account, root_container,
                         parent_shard, new_shards, **kwargs):
        self.logger.info(
            'Sharding %s with %s', str(parent_shard), str(new_shards))
        parent_shard['sharding'] = None

        # Prepare the sharding for the container to shard
        # FIXME(adu): ServiceBusy or Timeout
        sharding_info = self._prepare_sharding(parent_shard, **kwargs)
        parent_shard['sharding'] = sharding_info

        # Create the new shards
        for new_shard in new_shards:
            self._create_shard(root_account, root_container, parent_shard,
                               new_shard, **kwargs)

        # Apply saved writes on the new shards in the background
        saved_writes_applicator = SavedWritesApplicator(
            self, parent_shard, new_shards, logger=self.logger, **kwargs)
        try:
            saved_writes_applicator.apply_in_background(**kwargs)
            saved_writes_applicator.wait_until_queue_is_almost_empty(
                timeout=self.save_writes_timeout, **kwargs)
            saved_writes_applicator.flush(**kwargs)

            # When the queue is empty, lock the container to shard
            self._lock_shard(parent_shard, **kwargs)
        except Exception:
            # Immediately close the applicator
            saved_writes_applicator.close(timeout=0, **kwargs)
            raise

        # When the queue is empty again,
        # remplace the shards in the root container
        if not saved_writes_applicator.close(**kwargs):
            raise OioException('New shards could not be updated correctly')
        # FIXME(adu): ServiceBusy or Timeout
        self._replace_shards(root_account, root_container, new_shards,
                             **kwargs)
        parent_shard.pop('sharding', None)

        cleaners = list()
        root_cid = cid_from_name(root_account, root_container)
        if parent_shard['cid'] == root_cid:
            # Clean up root container
            root_shard = {
                'cid': root_cid
            }
            cleaners.append(eventlet.spawn(
                self._safe_clean, root_shard, **kwargs))
        else:
            # Delete parent shard
            try:
                self.container.container_delete(
                    cid=parent_shard['cid'], force=True, **kwargs)
            except Exception as exc:
                # "Create" an orphan shard
                self.logger.warning(
                    'Failed to delete old parent shard (CID=%s): %s',
                    parent_shard['cid'], exc)

        # Clean up new shards
        for new_shard in new_shards:
            cleaners.append(eventlet.spawn(
                self._safe_clean, new_shard, **kwargs))
        for cleaner in cleaners:
            cleaner.wait()

    def _rollback_sharding(self, parent_shard, new_shards, **kwargs):
        if 'sharding' not in parent_shard:
            # Sharding is complete, but not everything has been cleaned up
            self.logger.error(
                'Failed to clean up at the end of the sharding (CID=%s)',
                parent_shard['cid'])
            return

        if parent_shard['sharding'] is None:
            # Sharding hasn't even started
            return

        self.logger.error(
            'Failed to shard container (CID=%s), aborting...',
            parent_shard['cid'])
        self._safe_abort_sharding(parent_shard, **kwargs)
        for new_shard in new_shards:
            if 'cid' not in new_shard:
                # Shard doesn't exist yet
                continue
            self.logger.info(
                'Deleting new shard (CID=%s)', new_shard['cid'])
            try:
                self.container.container_delete(
                    cid=new_shard['cid'], force=True, **kwargs)
            except Exception as exc:
                # "Create" an orphan shard
                self.logger.warning(
                    'Failed to delete new shard (CID=%s): %s',
                    new_shard['cid'], exc)

        # Drain beanstalk tube
        beanstalk_url = parent_shard['sharding']['queue']
        beanstalk_tube = parent_shard['cid'] + '.sharding-' \
            + str(parent_shard['sharding']['timestamp'])
        self.logger.info(
            'Drain beanstalk tube (URL=%s TUBE=%s)',
            beanstalk_url, beanstalk_tube)
        try:
            beanstalk = Beanstalk.from_url(beanstalk_url)
            beanstalk.drain_tube(beanstalk_tube)
        except Exception as exc:
            self.logger.warning(
                'Failed to drain the beanstalk tube (URL=%s TUBE=%s): %s',
                beanstalk_url, beanstalk_tube, exc)

    def _almost_safe_shard_container(self, root_account, root_container,
                                     parent_shard, new_shards, **kwargs):
        try:
            self._shard_container(root_account, root_container,
                                  parent_shard, new_shards, **kwargs)
        except Exception:
            try:
                self._rollback_sharding(parent_shard, new_shards, **kwargs)
            except Exception:
                self.logger.exception(
                    'Failed to rollback sharding (CID=%s)',
                    parent_shard['cid'])
            raise

    def _shard_container_by_dichotomy(self, root_account, root_container,
                                      parent_shard, new_shards,
                                      max_new_shards_per_op=2, **kwargs):
        new_shards_size = len(new_shards)
        if new_shards_size <= max_new_shards_per_op:
            self._almost_safe_shard_container(
                root_account, root_container, parent_shard, new_shards,
                **kwargs)
            return

        sub_new_shards_list = list()
        tmp_new_shards = list()
        start_index = 0
        end_index = 0
        for i in range(max_new_shards_per_op):
            end_index += new_shards_size // max_new_shards_per_op
            if i < new_shards_size % max_new_shards_per_op:
                end_index += 1
            sub_new_shards = new_shards[start_index:end_index]
            sub_new_shards_list.append(sub_new_shards)
            start_index = end_index

            tmp_parent_shard = None
            if len(sub_new_shards) == 1:
                tmp_parent_shard = sub_new_shards[0]
            else:
                tmp_parent_shard = sub_new_shards[0].copy()
                tmp_parent_shard['upper'] = sub_new_shards[-1]['upper']
            tmp_new_shards.append(tmp_parent_shard)

        self._almost_safe_shard_container(
            root_account, root_container, parent_shard, tmp_new_shards,
            **kwargs)

        for i in range(max_new_shards_per_op):
            sub_new_shards = sub_new_shards_list[i]
            tmp_parent_shard = tmp_new_shards[i]
            if len(sub_new_shards) == 1:
                # No sharding to do
                continue
            self._shard_container_by_dichotomy(
                root_account, root_container, tmp_parent_shard, sub_new_shards,
                max_new_shards_per_op=max_new_shards_per_op,
                **kwargs)

    @ensure_request_id
    def replace_shard(self, account, container, new_shards,
                      enable=False, **kwargs):
        meta = self.container.container_get_properties(
            account, container, **kwargs)

        sys = meta['system']
        if int_value(sys.get(M2_PROP_SHARDS), 0):
            raise ValueError('It is a root container')

        root_account = None
        root_container = None
        root_cid, current_shard = self._meta_to_shard(meta)
        if root_cid is None:
            # First sharding
            if not enable:
                raise ValueError(
                    'Sharding is not enabled for this container')
            root_account = account
            root_container = container
            current_shard = {
                'index': -1,
                'lower': '',
                'upper': '',
                'cid': cid_from_name(account, container),
                'metadata': None
            }
        else:
            root_meta = self.container.container_get_properties(
                cid=root_cid, **kwargs)
            root_sys = root_meta['system']
            root_account = root_sys.get(M2_PROP_ACCOUNT_NAME)
            root_container = root_sys.get(M2_PROP_CONTAINER_NAME)

        shards_for_sharding = list(self._check_shards(
            new_shards, are_new=True, partial=True, **kwargs))
        if not shards_for_sharding:
            raise OioException('Missing new shards')
        if shards_for_sharding[0]['lower'] != current_shard['lower']:
            raise OioException('Wrong first lower for the new shards')
        if shards_for_sharding[-1]['upper'] != current_shard['upper']:
            raise OioException('Wrong last upper for the new shards')
        if len(shards_for_sharding) == 1:
            # Shard doesn't change
            return False

        self._shard_container_by_dichotomy(
            root_account, root_container, current_shard, shards_for_sharding,
            **kwargs)
        return True

    def _sharding_replace_shards(self, root_account, root_container,
                                 current_shards, current_shard,
                                 new_shards, new_shard, **kwargs):
        tmp_new_shard = None
        shards_for_sharding = list()
        shards_for_sharding.append(new_shard)
        while True:
            try:
                new_shard = next(new_shards)
            except StopIteration:
                raise OioException('Should never happen')

            if current_shard['upper'] == new_shard['upper']:
                shards_for_sharding.append(new_shard)
                break
            elif current_shard['upper'] == '' \
                    or (new_shard['upper'] != '' and
                        current_shard['upper'] > new_shard['upper']):
                shards_for_sharding.append(new_shard)
            else:
                tmp_new_shard = new_shard.copy()
                tmp_new_shard['upper'] = current_shard['upper']
                shards_for_sharding.append(tmp_new_shard)
                break

        self._shard_container_by_dichotomy(
            root_account, root_container, current_shard, shards_for_sharding,
            **kwargs)

        if tmp_new_shard is None:
            # current_shard['upper'] == new_shard['upper']:
            if current_shard['upper'] == '':
                # all new shards have been created
                return None, None

            try:
                current_shard = next(current_shards)
            except StopIteration:
                raise OioException('Should never happen')
            try:
                new_shard = next(new_shards)
            except StopIteration:
                raise OioException('Should never happen')
        else:
            current_shard = tmp_new_shard
        return current_shard, new_shard

    def _shrinking_replace_shards(self, root_account, root_container,
                                  current_shards, current_shard,
                                  new_shards, new_shard, **kwargs):
        raise NotImplementedError('Shrinking not implemented')

    @ensure_request_id
    def replace_all_shards(self, root_account, root_container, new_shards,
                           **kwargs):
        current_shards = self.show_shards(
            root_account, root_container, **kwargs)
        new_shards = self._check_shards(new_shards, are_new=True, **kwargs)

        current_shard = None
        try:
            current_shard = next(current_shards)
        except StopIteration:
            raise ValueError(
                'No current shard for this container')
        new_shard = None
        try:
            new_shard = next(new_shards)
        except StopIteration:
            new_shard = {
                'index': -1,
                'lower': '',
                'upper': '',
                'cid': cid_from_name(root_account, root_container),
                'metadata': None
            }

        modified = False
        while current_shard is not None and new_shard is not None:
            # Sanity check
            if current_shard['lower'] != new_shard['lower']:
                raise OioException('Should never happen')

            if current_shard['upper'] == new_shard['upper']:
                # Shard doesn't change
                if current_shard['upper'] == '':
                    # All new shards have been created
                    current_shard = None
                    new_shard = None
                else:
                    try:
                        current_shard = next(current_shards)
                    except StopIteration:
                        raise OioException('Should never happen')
                    try:
                        new_shard = next(new_shards)
                    except StopIteration:
                        raise OioException('Should never happen')
                continue
            modified = True

            if current_shard['upper'] == '' \
                    or (new_shard['upper'] != '' and
                        current_shard['upper'] > new_shard['upper']):
                current_shard, new_shard = self._sharding_replace_shards(
                    root_account, root_container,
                    current_shards, current_shard,
                    new_shards, new_shard, **kwargs)
                # Sub-change is complete
                continue

            if new_shard['upper'] == '' \
                    or (current_shard['upper'] != '' and
                        current_shard['upper'] < new_shard['upper']):
                current_shard, new_shard = self._shrinking_replace_shards(
                    root_account, root_container,
                    current_shards, current_shard,
                    new_shards, new_shard, **kwargs)
                # Sub-change is complete
                continue

            raise OioException('Should never happen')
        return modified

    def _build_preceding_string(self, string):
        if not string:
            return string
        last_char_ord = ord(string[-1])
        new_last_char = None
        for i in range(last_char_ord - 1, -1, -1):
            try:
                # Some Unicode characters cannot be encoded in utf-8
                # (for example: chr(55296) = '\ud800').
                new_last_char = chr(i).encode('utf-8').decode('utf-8')
                break
            except UnicodeEncodeError:
                continue
        else:
            new_last_char = ''
        return string[:-1] + new_last_char

    @ensure_request_id
    def find_smaller_neighboring_shard(self, shard, root_cid=None, **kwargs):
        meta = self.container.container_get_properties(
            cid=shard['cid'], **kwargs)

        sys = meta['system']
        if int_value(sys.get(M2_PROP_SHARDS), 0):
            raise ValueError('It is a root container')

        if self._sharding_in_progress(meta):
            raise ValueError('Sharding already in progress')
        root_cid_, current_shard = self._meta_to_shard(meta)
        if root_cid_ is None:
            raise ValueError('Not a shard')
        elif not root_cid:
            root_cid = root_cid_
        elif root_cid_ != root_cid:
            raise ValueError('Root containers are different')
        if not self._shards_equal(shard, current_shard):
            raise ValueError(
                'Mismatch between current shard and given shard')

        # The marker is excluded, so we have to take the string just before.
        marker = self._build_preceding_string(current_shard['lower'])
        current_shards = list(self.show_shards(
            None, None, root_cid=root_cid, limit=3, no_paging=False,
            marker=marker, **kwargs))

        neighboring_shards = list()
        i = 0
        if current_shard['lower']:
            neighboring_shards.append(current_shards[i])
            i += 1
        if current_shards[i]['cid'] != current_shard['cid']:
            raise OioException('Possible orphan shard')
        i += 1
        if current_shard['upper']:
            neighboring_shards.append(current_shards[i])
            i += 1
        if i == 1:  # The one and last shard
            return current_shard, None

        smaller_shard = None
        for neighboring_shard in neighboring_shards:
            neighboring_shard_meta = self.container.container_get_properties(
                cid=neighboring_shard['cid'], **kwargs)
            if self._sharding_in_progress(neighboring_shard_meta):
                self.logger.info(
                    'Sharding in progress for neighboring shard %s' %
                    neighboring_shard['cid'])
                continue
            neighboring_shard_root_cid, neighboring_shard = \
                self._meta_to_shard(neighboring_shard_meta)
            if neighboring_shard_root_cid != root_cid:
                self.logger.warning(
                    'Shard %s does not belong to the root %s, '
                    'but is in its list of shards',
                    neighboring_shard['cid'], root_cid)
                continue
            if not smaller_shard \
                    or neighboring_shard['count'] < smaller_shard['count']:
                smaller_shard = neighboring_shard
        if not smaller_shard:
            raise OioException('No neighboring shard available')
        return current_shard, smaller_shard

    def _shrink_shards(self, root_cid, smaller_shard, bigger_shard, new_shard,
                       pre_vacuum=True, **kwargs):
        self.logger.info('Shrinking shards by merging %s and %s in %s',
                         str(smaller_shard), str(bigger_shard), str(new_shard))
        smaller_shard['sharding'] = None
        bigger_shard['sharding'] = None

        # Vacuum the smaller shard
        if pre_vacuum:
            self.admin.vacuum_base('meta2', cid=smaller_shard['cid'], **kwargs)

        # Prepare shrinking on smaller shard
        # FIXME(adu): ServiceBusy or Timeout
        shrinking_info = self._prepare_sharding(smaller_shard, **kwargs)
        smaller_shard['sharding'] = shrinking_info
        # Prepare shrinking on bigger shard or root
        # FIXME(adu): ServiceBusy or Timeout
        shrinking_info = self._prepare_sharding(
            bigger_shard, action='merge', **kwargs)
        bigger_shard['sharding'] = shrinking_info

        # Copy the meta2 database from the master of smaller shard
        # to the master of bigger shard
        if (smaller_shard['sharding']['master']
                != bigger_shard['sharding']['master']):
            self.admin.copy_base_from(
                'meta2', cid=smaller_shard['cid'],
                svc_from=smaller_shard['sharding']['master'],
                svc_to=bigger_shard['sharding']['master'],
                suffix='sharding-%d' % smaller_shard['sharding']['timestamp'],
                **kwargs)

        # Merge the copy in the bigger shard
        self._merge_shards(smaller_shard, bigger_shard, **kwargs)

        # Apply saved writes on the new merged shard in the background
        saved_writes_applicator = SavedWritesApplicator(
            self, smaller_shard, [new_shard], logger=self.logger, **kwargs)
        try:
            saved_writes_applicator.apply_in_background(**kwargs)
            saved_writes_applicator.wait_until_queue_is_almost_empty(**kwargs)
            saved_writes_applicator.flush(**kwargs)

            # When the queue is empty, lock the container to shard
            self._lock_shard(smaller_shard, **kwargs)
        except Exception:
            # Immediately close the applicator
            saved_writes_applicator.close(timeout=0, **kwargs)
            raise

        # When the queue is empty again,
        # update the lower and the upper for the merged shard
        # remplace the shards in the root container
        if not saved_writes_applicator.close(**kwargs):
            raise OioException('New shards could not be updated correctly')
        # TODO change upper and lower for merged shard
        # FIXME(adu): ServiceBusy or Timeout
        self._replace_shards(None, None, [new_shard],
                             root_cid=root_cid, **kwargs)
        smaller_shard_info = smaller_shard.pop('sharding', None)
        bigger_shard_info = bigger_shard.pop('sharding', None)

        # Delete old smaller shard
        try:
            self.container.container_delete(
                cid=smaller_shard['cid'], force=True, **kwargs)
        except Exception as exc:
            # "Create" an orphan shard
            self.logger.warning(
                'Failed to delete old smaller shard (CID=%s): %s',
                smaller_shard['cid'], exc)

        # Clean new shard to recompute stats
        self._safe_clean(new_shard, no_vacuum=True, **kwargs)

        # Delete the copy
        if (smaller_shard_info['master']
                != bigger_shard_info['master']):
            try:
                self.admin.remove_base(
                    'meta2', cid=smaller_shard['cid'],
                    service_id=bigger_shard_info['master'],
                    suffix='sharding-%d' % smaller_shard_info['timestamp'],
                    **kwargs)
            except Exception as exc:
                self.logger.warning(
                    'Failed to delete the copy (CID=%s): %s',
                    smaller_shard['cid'], exc)

    def _rollback_shrinking(self, smaller_shard, bigger_shard, new_shard,
                            **kwargs):
        if 'sharding' not in smaller_shard and 'sharding' not in bigger_shard:
            # Shrinking is complete, but not everything has been cleaned up
            self.logger.error(
                'Failed to clean up at the end of the shrinking '
                '(smaller CID=%s ; bigger CID=%s)',
                smaller_shard['cid'], bigger_shard['cid'])
            return

        if smaller_shard['sharding'] is None \
                and bigger_shard['sharding'] is None:
            # Shrinking hasn't even started
            return

        self.logger.error(
            'Failed to shrink shards (smaller CID=%s ; bigger CID=%s), '
            'aborting...', smaller_shard['cid'], bigger_shard['cid'])
        if smaller_shard['sharding'] is not None:
            self._safe_abort_sharding(smaller_shard, **kwargs)
        if bigger_shard['sharding'] is not None:
            if self._safe_abort_sharding(bigger_shard, **kwargs):
                # If the abort didn't work, do not clean up the shard,
                # otherwise the merge will be considered successful
                # (from the point of view of this shard only).
                self._safe_clean(new_shard, **kwargs)

        # Delete the copy
        if (smaller_shard['sharding'] is not None
                and bigger_shard['sharding'] is not None
                and smaller_shard['sharding']['master']
                != bigger_shard['sharding']['master']):
            try:
                self.admin.remove_base(
                    'meta2', cid=smaller_shard['cid'],
                    service_id=bigger_shard['sharding']['master'],
                    suffix='sharding-%d'
                    % smaller_shard['sharding']['timestamp'],
                    **kwargs)
            except Exception as exc:
                self.logger.warning(
                    'Failed to delete the copy (CID=%s): %s',
                    smaller_shard['cid'], exc)

        if smaller_shard['sharding'] is not None:
            # Drain beanstalk tube
            beanstalk_url = smaller_shard['sharding']['queue']
            beanstalk_tube = smaller_shard['cid'] + '.sharding-' \
                + str(smaller_shard['sharding']['timestamp'])
            self.logger.info(
                'Drain beanstalk tube (URL=%s TUBE=%s)',
                beanstalk_url, beanstalk_tube)
            try:
                beanstalk = Beanstalk.from_url(beanstalk_url)
                beanstalk.drain_tube(beanstalk_tube)
            except Exception as exc:
                self.logger.warning(
                    'Failed to drain the beanstalk tube (URL=%s TUBE=%s): %s',
                    beanstalk_url, beanstalk_tube, exc)

    def _almost_safe_shrink_shards(self, root_cid, smaller_shard, bigger_shard,
                                   new_shard, **kwargs):
        try:
            self._shrink_shards(root_cid, smaller_shard, bigger_shard,
                                new_shard, **kwargs)
        except Exception:
            try:
                self._rollback_shrinking(smaller_shard, bigger_shard,
                                         new_shard, **kwargs)
            except Exception:
                self.logger.exception(
                    'Failed to rollback shrinking '
                    '(smaller CID=%s ; bigger CID=%s)',
                    smaller_shard['cid'], bigger_shard['cid'])
            raise

    @ensure_request_id
    def shrink_shards(self, shards_to_merge, root_cid=None, **kwargs):
        if not shards_to_merge:  # No shard to shrink
            return False
        if len(shards_to_merge) > 2:
            raise NotImplementedError()
        # Check and format
        shards = list()
        for shard in shards_to_merge:
            meta = self.container.container_get_properties(
                cid=shard['cid'], **kwargs)
            sys = meta['system']
            if int_value(sys.get(M2_PROP_SHARDS), 0):
                raise ValueError('It is a root container')
            root_cid_, shard_ = self._meta_to_shard(meta)
            if root_cid_ is None:
                raise ValueError('Not a shard')
            if root_cid is None:
                root_cid = root_cid_
            elif root_cid_ != root_cid:
                raise ValueError('Root containers are different')
            if not self._shards_equal(shard, shard_):
                raise ValueError(
                    'Mismatch between current shard(s) and given shard(s)')
            # The shard obtained by the metadata contains more information
            shard = shard_
            shard_list = list(self.show_shards(
                None, None, root_cid=root_cid, limit=1, no_paging=False,
                marker=shard['lower'], **kwargs))
            if not shard_list or not self._shards_equal(shard_list[0], shard):
                raise ValueError('Shard %s not in root %s' %
                                 (shard['cid'], root_cid))
            shards.append(shard)
        shards.sort(key=lambda s: s['lower'])
        for i, shard in enumerate(shards):
            shard['index'] = i
        shards = list(self._check_shards(shards, partial=True))
        if len(shards) == 1:  # Possible merge the one and last shard in root
            if shards[0]['lower'] or shards[0]['upper']:
                raise ValueError("Not the one and last shard")

        # Select the smaller shard
        smaller_shard = None
        bigger_shard = None
        new_shard = None
        if len(shards) == 1:  # Merge the one and last shard in root
            smaller_shard = shards[0]
            bigger_shard = self._format_shard({
                'index': 0,
                'lower': '',
                'upper': '',
                'cid': root_cid,
                'metadata': None,
                'count': 0
            })
            new_shard = self._format_shard(bigger_shard)
            new_shard['count'] = shards[0]['count']
        elif shards[0]['count'] < shards[1]['count']:
            smaller_shard = shards[0]
            bigger_shard = shards[1]
            new_shard = self._format_shard(bigger_shard)
            new_shard['lower'] = shards[0]['lower']
            new_shard['count'] += shards[0]['count']
        else:
            smaller_shard = shards[1]
            bigger_shard = shards[0]
            new_shard = self._format_shard(bigger_shard)
            new_shard['upper'] = shards[1]['upper']
            new_shard['count'] += shards[1]['count']

        self._almost_safe_shrink_shards(root_cid, smaller_shard, bigger_shard,
                                        new_shard, **kwargs)
        return True
