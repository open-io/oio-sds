# Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS
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

from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker
from oio.common import exceptions
from oio.common.fullpath import encode_fullpath
from oio.common.json import json
from oio.content.factory import ContentFactory
from oio.event.beanstalk import BeanstalkdListener

# TODO(FVE): move to a relevant module
CONTENT_PERFECTIBLE = 'storage.content.perfectible'
DEFAULT_IMPROVER_TUBE = 'oio-improve'


class BlobImprover(Rebuilder):
    """
    Move chunks of objects declared as "perfectible",
    if possible to improve them (increased distance between chunks or
    better hosting service).
    """

    supported_events = (CONTENT_PERFECTIBLE, )

    def __init__(self, conf, logger, beanstalkd_addr, **kwargs):
        super(BlobImprover, self).__init__(conf, logger, volume=None, **kwargs)
        self.content_factory = ContentFactory(self.conf, logger=self.logger)
        beanstalkd_tube = self.conf.get('beanstalkd_tube',
                                        DEFAULT_IMPROVER_TUBE)
        self.listener = BeanstalkdListener(beanstalkd_addr, beanstalkd_tube,
                                           self.logger, **kwargs)

    def _event_from_job(self, job_id, data, **kwargs):
        # pylint: disable=no-member
        event = json.loads(data)
        type_ = event.get('event')
        if type_ not in self.__class__.supported_events:
            msg = 'Discarding event %s (type=%s)' % (
                event.get('job_id'), type_)
            self.logger.info(msg)
            raise exceptions.ExplicitBury(msg)
        yield event

    def _create_worker(self, **kwargs):
        return BlobImproverWorker(self, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        events = self.listener.fetch_jobs(self._event_from_job, **kwargs)
        for event in events:
            queue.put(event)

    def _item_to_string(self, item, **kwargs):
        url = item['url']
        fullpath = encode_fullpath(
            url['account'], url['user'], url['path'],
            url.get('version'), url['content'])
        # TODO(FVE): maybe tell some numbers about chunks
        if item.get('event') == CONTENT_PERFECTIBLE:
            return 'perfectible object %s' % (fullpath, )
        else:
            return 'object %s' % (fullpath, )

    def _get_report(self, status, end_time, counters, **kwargs):
        items_processed, errors, total_items_processed, total_errors = counters
        time_since_last_report = (end_time - self.last_report) or 0.00001
        total_time = (end_time - self.start_time) or 0.00001
        return ('%(status)s volume=%(volume)s '
                'last_report=%(last_report)s %(time_since_last_report).2fs '
                'chunks=%(chunks)d %(chunks_rate).2f/s '
                'errors=%(errors)d %(errors_rate).2f%% '
                'start_time=%(start_time)s %(total_time).2fs '
                'total_chunks=%(total_chunks)d '
                '%(total_chunks_rate).2f/s '
                'total_errors=%(total_errors)d %(total_errors_rate).2f%%' % {
                    'status': status,
                    'volume': self.volume,
                    'last_report': datetime.fromtimestamp(
                        int(self.last_report)).isoformat(),
                    'time_since_last_report': time_since_last_report,
                    'chunks': items_processed,
                    'chunks_rate':
                        items_processed / time_since_last_report,
                    'errors': errors,
                    'errors_rate':
                        100 * errors / float(items_processed or 1),
                    'start_time': datetime.fromtimestamp(
                        int(self.start_time)).isoformat(),
                    'total_time': total_time,
                    'total_chunks': total_items_processed,
                    'total_chunks_rate':
                        total_items_processed / total_time,
                    'total_errors': total_errors,
                    'total_errors_rate': 100 * total_errors /
                        float(total_items_processed or 1)
                })


class BlobImproverWorker(RebuilderWorker):

    def __init__(self, rebuilder, **kwargs):
        super(BlobImproverWorker, self).__init__(rebuilder, **kwargs)

    @property
    def content_factory(self):
        return self.rebuilder.content_factory

    def move_perfectible_from_event(self, event, dry_run=False, **kwargs):
        """
        Move one or more "perfectible" chunks described in a
        "storage.content.perfectible" event.
        """
        url = event['url']
        # There are chances that the set of chunks of the object has
        # changed between the time the event has been emitted and now.
        # It seems a good idea to reload the object metadata and compare.
        content = self.content_factory.get(url['id'], url['content'],
                                           account=url.get('account'),
                                           container_name=url.get('user'))
        fullpath = encode_fullpath(url['account'], url['user'], url['path'],
                                   url.get('version'), url['content'])
        for chunk in event['data']['chunks']:
            found = content.chunks.filter(url=chunk['id']).one()
            if not found:
                raise exceptions.PreconditionFailed(
                    "Chunk %s not found in %s" % (chunk['id'], fullpath))
            # Chunk quality information is not saved along with object
            # metadata, thus we must fill it now.
            found.quality = chunk['quality']

        moveable = dict()
        for chunk in content.chunks:
            imperfections = chunk.imperfections
            n_imp = len(imperfections)
            if n_imp > 0:
                moveable.setdefault(n_imp, list()).append(chunk)

        moves = list()
        errors = list()
        for n_imperfections, chunks in moveable.items():
            self.logger.debug("Chunks with %d imperfections: %s",
                              n_imperfections, chunks)
            for chunk in chunks:
                try:
                    src = str(chunk.url)
                    self.logger.debug("Working on %s: %s",
                                      src, chunk.imperfections)
                    dst = content.move_chunk(chunk, check_quality=True,
                                             dry_run=dry_run, **kwargs)
                    self.logger.debug("%s replaced by %s", src, dst['url'])
                    moves.append((src, dst))
                except exceptions.OioException as err:
                    self.logger.warn("Could not improve %s: %s", chunk, err)
                    errors.append(err)
        return moves, errors

    def _rebuild_one(self, item, **kwargs):
        moves, errors = self.move_perfectible_from_event(item, **kwargs)
        if errors:
            if not moves:
                raise exceptions.FaultyChunk(
                    'Could not improve any chunk: %s', errors)
            else:
                self.logger.info(
                    'Some chunks of %s have not been improved: %s',
                    self.rebuilder._item_to_string(item), errors)
        else:
            for move in moves:
                self.logger.debug('%s moved to %s', move[0], move[1])
