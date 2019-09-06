# Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
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


from datetime import datetime
from string import hexdigits

from oio.blob.utils import check_volume, read_chunk_metadata
from oio.common.constants import STRLEN_CHUNKID, CHUNK_SUFFIX_PENDING
from oio.common.easy_value import int_value
from oio.common.exceptions import Conflict, NotFound
from oio.common.green import ratelimit, time
from oio.common.utils import paths_gen
from oio.container.client import ContainerClient


class BlobRegistrator(object):
    DEFAULT_CHUNKS_PER_SECOND = 30
    DEFAULT_REPORT_INTERVAL = 3600
    BEAN_TYPES = ('alias', 'header', 'chunk')

    def __init__(self, conf, logger, volume, container_ids):
        self.conf = conf
        self.logger = logger
        self.volume = volume
        self.volume_ns, self.volume_id = check_volume(self.volume)
        self.container_ids = container_ids or list()
        self.container_ids = [container_id.upper()
                              for container_id in self.container_ids]

        self.namespace = self.conf['namespace']
        if self.namespace != self.volume_ns:
            raise ValueError(
                'Namespace (%s) mismatch with volume namespace (%s)',
                self.namespace, self.volume_ns)

        # action
        self.action_name = self.conf['action'].lower()
        if (self.action_name == 'insert'):
            self.action = self._insert_bean
        elif (self.action_name == 'update'):
            self.action = self._update_bean
        elif (self.action_name == 'check'):
            self.action = self._check_bean
        else:
            raise ValueError('Unknown action (%s)', self.action_name)

        # speed
        self.chunks_run_time = 0
        self.max_chunks_per_second = int_value(
            self.conf.get('chunks_per_second'),
            self.DEFAULT_CHUNKS_PER_SECOND)

        # counters
        self.chunks_processed = 0
        self.chunk_errors = 0
        self.beans_processed = dict()
        self.bean_successes = dict()
        self.bean_already_exists = dict()
        self.bean_orphans = dict()
        self.bean_errors = dict()
        for bean_type in self.BEAN_TYPES:
            self.beans_processed[bean_type] = 0
            self.bean_successes[bean_type] = 0
            self.bean_already_exists[bean_type] = 0
            self.bean_orphans[bean_type] = 0
            self.bean_errors[bean_type] = 0

        # report
        self.start_time = 0
        self.last_report = 0
        self.report_interval = int_value(
            conf.get('report_interval'),
            self.DEFAULT_REPORT_INTERVAL)

        self.client = ContainerClient(
            {'namespace': self.namespace}, logger=self.logger)
        self.ctime = int(time.time())

    def _beans_from_meta(self, meta):
        return \
            [{
                'type': 'alias',
                'name': meta['content_path'],
                'version': int(meta['content_version']),
                'ctime': self.ctime,
                'mtime': self.ctime,
                'deleted': False,
                'header': meta['content_id']
            }, {
                'type': 'header',
                'id': meta['content_id'],
                'size': 0,
                'ctime': self.ctime,
                'mtime': self.ctime,
                'policy': meta['content_policy'],
                'chunk-method': meta['content_chunkmethod'],
                'mime-type': 'application/octet-stream'
            }, {
                'type': 'chunk',
                'id': 'http://' + self.volume_id + '/' + meta['chunk_id'],
                'hash': meta.get('metachunk_hash') or meta['chunk_hash'],
                'size': int(meta['chunk_size']),
                'ctime': self.ctime,
                'pos': meta['chunk_pos'],
                'content': meta['content_id']
            }]

    def _check_bean(self, meta, bean):
        raise Exception("CHECK not yet implemented")

    def _insert_bean(self, meta, bean):
        self.client.container_raw_insert(bean, cid=meta['container_id'])

    def _update_bean(self, meta, bean):
        self.client.container_raw_update(
            [bean], [bean], cid=meta['container_id'])

    def _get_report(self, status, end_time):
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        report = (
            '%(status)s volume=%(volume)s '
            'start_time=%(start_time)s %(total_time).2fs '
            'last_report=%(last_report)s %(time_since_last_report).2fs '
            'chunks_processed=%(chunks_processed)d '
            '%(chunks_processed_rate).2f/s '
            'chunk_errors=%(chunk_errors)d '
            '%(chunk_errors_rate).2f%% ' % {
                'status': status,
                'volume': self.volume_id,
                'start_time': datetime.fromtimestamp(
                    int(self.start_time)).isoformat(),
                'total_time': total_time,
                'last_report': datetime.fromtimestamp(
                    int(self.last_report)).isoformat(),
                'time_since_last_report': time_since_last_report,
                'chunks_processed': self.chunks_processed,
                'chunks_processed_rate':
                    self.chunks_processed / total_time,
                'chunk_errors': self.chunk_errors,
                'chunk_errors_rate':
                    100 * self.chunk_errors
                    / float(self.chunks_processed or 1),
            })
        for bean_type in self.BEAN_TYPES:
            report = (
                '%(report)s '
                'bean_%(bean_type)s_processed=%(beans_processed)d '
                '%(beans_processed_rate).2f/s '
                'bean_%(bean_type)s_successes=%(bean_successes)d '
                '%(bean_successes_rate).2f%% '
                'bean_%(bean_type)s_already_exists=%(bean_already_exists)d '
                '%(bean_already_exists_rate).2f%% '
                'bean_%(bean_type)s_orphans=%(bean_orphans)d '
                '%(bean_orphans_rate).2f%% '
                'bean_%(bean_type)s_errors=%(bean_errors)d '
                '%(bean_errors_rate).2f%%' % {
                    'report': report,
                    'bean_type': bean_type,
                    'beans_processed': self.beans_processed[bean_type],
                    'beans_processed_rate':
                        self.beans_processed[bean_type]
                        / total_time,
                    'bean_successes': self.bean_successes[bean_type],
                    'bean_successes_rate':
                        100 * self.bean_successes[bean_type]
                        / float(self.beans_processed[bean_type] or 1),
                    'bean_already_exists': self.bean_already_exists[bean_type],
                    'bean_already_exists_rate':
                        100 * self.bean_already_exists[bean_type]
                        / float(self.beans_processed[bean_type] or 1),
                    'bean_orphans': self.bean_orphans[bean_type],
                    'bean_orphans_rate':
                        100 * self.bean_orphans[bean_type]
                        / float(self.beans_processed[bean_type] or 1),
                    'bean_errors': self.bean_errors[bean_type],
                    'bean_errors_rate':
                        100 * self.bean_errors[bean_type]
                        / float(self.beans_processed[bean_type] or 1)
                })
        return report

    def log_report(self, status, force=False):
        end_time = time.time()
        if force or (end_time - self.last_report >= self.report_interval):
            self.logger.info(self._get_report(status, end_time))
            self.last_report = end_time

    def pass_volume(self):
        self.start_time = self.last_report = time.time()
        self.log_report('START', force=True)

        paths = paths_gen(self.volume)
        for path in paths:
            try:
                self.pass_chunk_file(path)
                self.chunks_processed += 1
            except Exception as exc:
                self.logger.error(
                    'Failed to pass chunk file (chunk_file=%s): %s',
                    path, exc)
                self.chunk_errors += 1

            self.log_report('RUN')
            self.chunks_run_time = ratelimit(
                self.chunks_run_time, self.max_chunks_per_second)

        self.log_report('DONE', force=True)
        return self.chunk_errors == 0 \
            and all(errors == 0 for errors in self.bean_errors.values())

    def pass_chunk_file(self, path):
        chunk_id = path.rsplit('/', 1)[-1]
        if len(chunk_id) != STRLEN_CHUNKID:
            if chunk_id.endswith(CHUNK_SUFFIX_PENDING):
                self.logger.info('Skipping pending chunk %s', path)
            else:
                self.logger.warn('WARN Not a chunk %s', path)
            return
        for char in chunk_id:
            if char not in hexdigits:
                self.logger.warn('WARN Not a chunk %s', path)
                return

        with open(path) as f:
            meta, _ = read_chunk_metadata(f, chunk_id)
            if self.container_ids \
                    and meta['container_id'] in self.container_ids:
                self.logger.debug(
                    'Skipping chunk file (container_id=%s content_path=%s '
                    'content_version=%s content_id=%s chunk_id=%s '
                    'chunk_pos=%s)', meta['container_id'],
                    meta['content_path'], meta['content_version'],
                    meta['content_id'], meta['chunk_id'], meta['chunk_pos'])
                return

            beans = self._beans_from_meta(meta)
            for bean in beans:
                try:
                    self.pass_bean(meta, bean)
                except Exception as exc:
                    self.logger.error(
                        'Failed to pass chunk file (container_id=%s '
                        'content_path=%s content_version=%s content_id=%s '
                        'chunk_id=%s chunk_pos=%s): %s', meta['container_id'],
                        meta['content_path'], meta['content_version'],
                        meta['content_id'], meta['chunk_id'],
                        meta['chunk_pos'], exc)
                    self.bean_errors[bean['type']] = \
                        self.bean_errors[bean['type']] + 1

    def pass_bean(self, meta, bean):
        try:
            self.beans_processed[bean['type']] = \
                self.beans_processed[bean['type']] + 1
            self.action(meta, bean)
            self.logger.debug(
                'Passed %s (container_id=%s content_path=%s '
                'content_version=%s content_id=%s chunk_id=%s chunk_pos=%s)',
                bean['type'], meta['container_id'], meta['content_path'],
                meta['content_version'], meta['content_id'],
                meta['chunk_id'], meta['chunk_pos'])
            self.bean_successes[bean['type']] = \
                self.bean_successes[bean['type']] + 1
        except Conflict as exc:
            self.logger.info(
                'Already exists %s (container_id=%s content_path=%s '
                'content_version=%s content_id=%s chunk_id=%s chunk_pos=%s): '
                '%s', bean['type'], meta['container_id'], meta['content_path'],
                meta['content_version'], meta['content_id'],
                meta['chunk_id'], meta['chunk_pos'], exc)
            self.bean_already_exists[bean['type']] = \
                self.bean_already_exists[bean['type']] + 1
        except NotFound as exc:
            self.logger.info(
                'Orphan %s (container_id=%s content_path=%s '
                'content_version=%s content_id=%s chunk_id=%s chunk_pos=%s): '
                '%s', bean['type'], meta['container_id'], meta['content_path'],
                meta['content_version'], meta['content_id'],
                meta['chunk_id'], meta['chunk_pos'], exc)
            self.bean_orphans[bean['type']] = \
                self.bean_orphans[bean['type']] + 1
        except Exception as exc:
            self.logger.error(
                'Failed to pass %s (container_id=%s content_path=%s '
                'content_version=%s content_id=%s chunk_id=%s chunk_pos=%s): '
                '%s', bean['type'], meta['container_id'], meta['content_path'],
                meta['content_version'], meta['content_id'],
                meta['chunk_id'], meta['chunk_pos'], exc)
            self.bean_errors[bean['type']] = \
                self.bean_errors[bean['type']] + 1
