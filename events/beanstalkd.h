/*
OpenIO SDS event queue
Copyright (C) 2021 OVH SAS

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

#ifndef OIO_SDS__event__beanstalkd_h
# define OIO_SDS__event__beanstalkd_h 1

#include <glib.h>

#define BEANSTALKD_PREFIX "beanstalk://"

struct beanstalkd_s
{
	gchar *endpoint;
	gchar *tube;
	gint fd;
};

GError *beanstalkd_factory(const gchar *endpoint, const gchar *tube,
		struct beanstalkd_s **out);

GError *beanstalkd_reconnect(struct beanstalkd_s *beanstalkd);

GError *beanstalkd_use_tube(struct beanstalkd_s *beanstalkd,
		const gchar *tube);

GError *beanstalkd_put_job(struct beanstalkd_s *beanstalkd, void *msg,
		size_t msglen);

GError *beanstalkd_get_stats(struct beanstalkd_s *beanstalkd, gchar ***out);

void beanstalkd_destroy(struct beanstalkd_s *beanstalkd);

#endif /*OIO_SDS__event__beanstalkd_h*/
