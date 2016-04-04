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
#ifndef OIO_SDS__sqlx__oio_events_queue_beanstalkd_h
# define OIO_SDS__sqlx__oio_events_queue_beanstalkd_h 1

# ifndef  OIO_EVT_BEANSTALKD_DEFAULT_PRIO
#  define OIO_EVT_BEANSTALKD_DEFAULT_PRIO   ((guint)(1<<31))
# endif

# ifndef  OIO_EVT_BEANSTALKD_DEFAULT_DELAY
#  define OIO_EVT_BEANSTALKD_DEFAULT_DELAY  0
# endif

# ifndef  OIO_EVT_BEANSTALKD_DEFAULT_TTR
#  define OIO_EVT_BEANSTALKD_DEFAULT_TTR    120
# endif

struct oio_events_queue_s;

/* Creates an event queue based on beanstalkd, with the default maximum number
   of events "not yet acknowledged". */
GError * oio_events_queue_factory__create_beanstalkd (const char *endpoint,
		struct oio_events_queue_s **out);

#endif /*OIO_SDS__sqlx__oio_events_queue_beanstalkd_h*/
