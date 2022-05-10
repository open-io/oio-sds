/*
OpenIO SDS event queue
Copyright (C) 2016-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2022 OVH SAS

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
#ifndef OIO_SDS__sqlx__oio_events_queue_beanstalkd_h
# define OIO_SDS__sqlx__oio_events_queue_beanstalkd_h 1

struct oio_events_queue_s;

/* Creates an event queue based on beanstalkd, with the default maximum number
 * of events "not yet acknowledged". */
GError * oio_events_queue_factory__create_beanstalkd (
		const char *endpoint, const char *tube,
		struct oio_events_queue_s **out);

#endif /*OIO_SDS__sqlx__oio_events_queue_beanstalkd_h*/
