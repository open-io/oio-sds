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

import time
from urllib.parse import unquote

from oio.common import exceptions
from oio.common.client import ProxyClient
from oio.common.constants import HEADER_PREFIX, M2_PROP_ACCOUNT_NAME, \
    M2_PROP_CONTAINER_NAME, M2_PROP_SHARDS, M2_PROP_SHARDING_ROOT, \
    M2_PROP_SHARDING_LOWER, M2_PROP_SHARDING_UPPER, STRLEN_CID
from oio.common.easy_value import int_value, is_hexa, true_value
from oio.common.exceptions import OioException
from oio.common.json import json
from oio.common.utils import cid_from_name, depaginate
from oio.container.client import ContainerClient


class ContainerSharding(ProxyClient):

    def __init__(self, conf, logger=None, pool_manager=None, **kwargs):
        super(ContainerSharding, self).__init__(
            conf, request_prefix="/container/sharding", logger=logger,
            pool_manager=pool_manager, **kwargs)

        # Make sure to use up-to-date information
        self.force_master = True

        self.container = ContainerClient(
            self.conf, pool_manager=self.pool_manager, logger=self.logger,
            **kwargs)

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
            'metadata': None
        }
        return root_cid, shard

    def _check_shards(self, shards, are_new=False, partial=False, **kwargs):
        previous_shard = None
        for i, shard in enumerate(shards):
            shard = self._format_shard(shard, is_new=are_new, **kwargs)
            if shard['index'] != i:
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

        return formatted_shard

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

    def _create_shard(self, root_account, root_container, parent_shard,
                      shard, **kwargs):
        timestamp = int(time.time() * 1e6)
        shard_account = '.shards_%s' % (root_account)
        shard_container = '%s-%s-%d-%d' % (
            root_container, parent_shard['cid'], timestamp, shard['index'])

        # Create shard container
        shard_info = shard.copy()
        shard_info['root'] = cid_from_name(root_account, root_container)
        shard_info['parent'] = parent_shard['cid']
        params = self._make_params(account=shard_account,
                                   reference=shard_container, **kwargs)
        resp, body = self._request('POST', '/create_shard', params=params,
                                   json=shard_info, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

        # Fill the shard info with the CID of the shard container
        shard['cid'] = cid_from_name(shard_account, shard_container)

    def _replace_shards(self, root_account, root_container, shards, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container, **kwargs)
        resp, body = self._request('POST', '/replace', params=params,
                                   json=shards, **kwargs)
        if resp.status != 204:
            raise exceptions.from_response(resp, body)

    def _show_shards(self, root_account, root_container, limit=None,
                     marker=None, **kwargs):
        params = self._make_params(account=root_account,
                                   reference=root_container, **kwargs)
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

    def _show_formatted_shards(self, root_account, root_container, **kwargs):
        shards = depaginate(
            self._show_shards,
            listing_key=lambda x: x['shard_ranges'],
            marker_key=lambda x: x.get('next_marker'),
            truncated_key=lambda x: x['truncated'],
            root_account=root_account,
            root_container=root_container,
            **kwargs)
        for i, shard in enumerate(shards):
            shard['index'] = i
            shard = self._format_shard(shard, **kwargs)
            yield shard

    def show_shards(self, root_account, root_container, **kwargs):
        formatted_shards = self._show_formatted_shards(
            root_account, root_container, **kwargs)
        return self._check_shards(formatted_shards, **kwargs)

    def _shard_container(self, root_account, root_container,
                         parent_shard, new_shards, **kwargs):
        self.logger.info(
            'Sharding %s with %s', str(parent_shard), str(new_shards))

        # TODO(adu) Prepare the sharding for the container to shard

        # Create the new shards
        for new_shard in new_shards:
            self._create_shard(root_account, root_container, parent_shard,
                               new_shard, **kwargs)

        # TODO(adu) Apply saved writes on the new shards in the background

        # TODO(adu) When the queue is empty, lock the container to shard

        # Remplace the shards in the root container
        self._replace_shards(root_account, root_container, new_shards,
                             **kwargs)

        root_cid = cid_from_name(root_account, root_container)
        if parent_shard['cid'] == root_cid:
            # TODO(adu) Clean up root container
            pass
        else:
            # TODO(adu) Delete parent shard
            pass

        # TODO(adu) Clean up new shards

    def _almost_safe_shard_container(self, root_account, root_container,
                                     parent_shard, new_shards, **kwargs):
        try:
            self._shard_container(root_account, root_container,
                                  parent_shard, new_shards, **kwargs)
        except Exception:
            self.logger.exception('Failed to shard container')
            # TODO(adu) Rollback sharding
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

    def replace_shard(self, account, container, new_shards,
                      enable=False, **kwargs):
        meta = self.container.container_get_properties(
            account, container, **kwargs)

        sys = meta['system']
        if int_value(sys.get(M2_PROP_SHARDS), 0):
            raise OioException('It is a root container')

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
