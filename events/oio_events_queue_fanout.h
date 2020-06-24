/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/
#ifndef OIO_SDS__sqlx__oio_events_queue_fanout_h
# define OIO_SDS__sqlx__oio_events_queue_fanout_h 1

struct oio_events_queue_s;

/* Spreads the events over multiple output queues. */
GError * oio_events_queue_factory__create_fanout (
		struct oio_events_queue_s **subv, guint sublen,
		struct oio_events_queue_s **out);

#endif /*OIO_SDS__sqlx__oio_events_queue_fanout_h*/
