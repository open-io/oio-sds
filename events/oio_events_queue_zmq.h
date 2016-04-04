/*
OpenIO SDS event queue
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef OIO_SDS__sqlx__oio_events_queue_zmq_h
# define OIO_SDS__sqlx__oio_events_queue_zmq_h 1

struct oio_events_queue_s;

/* Creates an agent-based event queue, with the default maximum number
   of events "not yet acknowledged". */
GError * oio_events_queue_factory__create_zmq (const char *zurl,
		 struct oio_events_queue_s **out);

#endif /*OIO_SDS__sqlx__oio_events_queue_zmq_h*/
