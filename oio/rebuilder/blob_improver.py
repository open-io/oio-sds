# Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS
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

from oio.common import exceptions
from oio.common.easy_value import int_value
from oio.common.fullpath import encode_fullpath
from oio.common.green import sleep
from oio.common.json import json
from oio.common.utils import request_id
from oio.content.factory import ContentFactory
from oio.event.beanstalk import BeanstalkdListener, BeanstalkdSender
from oio.event.evob import EventTypes
from oio.rebuilder.rebuilder import Rebuilder, RebuilderWorker

DEFAULT_IMPROVER_TUBE = 'oio-improve'


class BlobImprover(Rebuilder):
    """
    Move chunks of objects declared as "perfectible",
    if possible to improve them (increased distance between chunks or
    better hosting service).
    """

    supported_events = (EventTypes.CONTENT_PERFECTIBLE, )

    def __init__(self, conf, logger, beanstalkd_addr, **kwargs):
        super(BlobImprover, self).__init__(conf, logger, volume=None, **kwargs)
        self.content_factory = ContentFactory(self.conf, logger=self.logger)
        beanstalkd_tube = self.conf.get('beanstalkd_tube',
                                        DEFAULT_IMPROVER_TUBE)
        self.listener = BeanstalkdListener(beanstalkd_addr, beanstalkd_tube,
                                           self.logger, **kwargs)
        self.sender = BeanstalkdSender(beanstalkd_addr, beanstalkd_tube,
                                       self.logger, **kwargs)
        self.retry_delay = int_value(self.conf.get('retry_delay'), 30)
        self.reqid_prefix = 'blob-impr-'

    def exit_gracefully(self, signum, frame):
        super(BlobImprover, self).exit_gracefully(signum, frame)
        self.listener.running = False

    def _event_from_job(self, job_id, data, **kwargs):
        """Decode a JSON string into an event dictionary."""
        # pylint: disable=no-member
        event = json.loads(data)
        type_ = event.get('event')
        # Bury events that should not be there
        if type_ not in self.__class__.supported_events:
            msg = 'Discarding event %s (type=%s)' % (
                event.get('job_id'), type_)
            self.logger.info(msg)
            raise exceptions.ExplicitBury(msg)
        yield event

    def _create_worker(self, **kwargs):
        return BlobImproverWorker(self, **kwargs)

    def _fill_queue(self, queue, **kwargs):
        max_events = kwargs.get('max_events')
        sent_events = 0
        # Do not block more than 2 seconds
        events = self.listener.fetch_jobs(self._event_from_job,
                                          reserve_timeout=2, **kwargs)
        for event in events:
            queue.put(event)
            sent_events += 1
            if max_events > 0 and sent_events >= max_events:
                self.logger.info('Max events (%d) reached, exiting',
                                 max_events)
                break
            if not self.running:
                break
        events.close()

    def _read_retry_queue(self, queue, **kwargs):
        while True:
            # Reschedule jobs we were not able to handle.
            item = queue.get()
            sent = False
            while not sent:
                sent = self.sender.send_job(json.dumps(item),
                                            delay=self.retry_delay)
                if not sent:
                    sleep(1.0)
            self.sender.job_done()
            queue.task_done()

    def _item_to_string(self, item, **kwargs):
        try:
            url = item['url']
            fullpath = encode_fullpath(
                url['account'], url['user'], url['path'],
                url.get('version', 1), url['content'])
            # TODO(FVE): maybe tell some numbers about chunks
            if item.get('event') == EventTypes.CONTENT_PERFECTIBLE:
                return 'perfectible object %s' % (fullpath, )
            else:
                return 'object %s' % (fullpath, )
        except (KeyError, ValueError) as err:
            return '<unknown item> ({0})'.format(repr(err))

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

    def move_perfectible_from_event(self, event, dry_run=False,
                                    max_attempts=3, **kwargs):
        """
        Move one or more "perfectible" chunks described in a
        "storage.content.perfectible" event.
        """
        url = event['url']
        reqid = request_id(self.rebuilder.reqid_prefix)
        descr = self.rebuilder._item_to_string(event)
        self.logger.info('Working on %s (reqid=%s)', descr, reqid)
        # There are chances that the set of chunks of the object has
        # changed between the time the event has been emitted and now.
        # It seems a good idea to reload the object metadata and compare.
        content = self.content_factory.get(url['id'], url['content'],
                                           account=url.get('account'),
                                           container_name=url.get('user'),
                                           reqid=reqid)
        for chunk in event['data']['chunks']:
            found = content.chunks.filter(url=chunk['id']).one()
            if not found:
                raise exceptions.PreconditionFailed(
                    "Chunk %s not found in %s" % (chunk['id'], descr))
            # Chunk quality information is not saved along with object
            # metadata, thus we must fill it now.
            found.quality = chunk['quality']

        moveable = [chunk for chunk in content.chunks
                    if chunk.imperfections]
        moveable.sort(key=lambda x: x.imperfections)

        moves = list()
        errors = list()

        if not moveable:
            self.logger.info('Nothing to do for %s', descr)
            return moves, errors

        for chunk in moveable:
            try:
                src = str(chunk.url)
                # Must do a copy or bad things will happen.
                raw_src = dict(chunk.raw())
                self.logger.debug("Working on %s: %s",
                                  src, chunk.imperfections)
                # TODO(FVE): try to improve all chunks of a metachunk
                # in a single pass
                dst = content.move_chunk(chunk, check_quality=True,
                                         dry_run=dry_run, reqid=reqid,
                                         max_attempts=max_attempts,
                                         **kwargs)
                self.logger.debug("%s replaced by %s", src, dst['url'])
                moves.append((raw_src, dst))
            except exceptions.OioException as err:
                self.logger.warn("Could not improve %s: %s", chunk, err)
                errors.append(err)
        return moves, errors

    def _rebuild_one(self, item, dry_run=False, move_attempts=3, **kwargs):
        moves, errors = self.move_perfectible_from_event(
            item, dry_run=dry_run, max_attempts=move_attempts, **kwargs)
        if errors:
            if not moves:
                # Later we may want to limit attempts.
                item['attempts'] = item.get('attempts', 0) + 1
                raise exceptions.RetryLater(
                    item, 'Could not improve any chunk: %s' % errors)
            else:
                self.logger.info(
                    'Some chunks of %s have not been improved: %s',
                    self.rebuilder._item_to_string(item), errors)
                # TODO(FVE): build a new event, send it back
        else:
            # TODO(FVE): if there are no moves, should we reschedule?
            for move in moves:
                self.logger.debug('%s%s moved to %s',
                                  'dry-run: ' if dry_run else '',
                                  move[0], move[1])
        if dry_run:
            raise exceptions.RetryLater(item, 'Rescheduled after dry-run')
