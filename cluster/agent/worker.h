/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _WORKER_H
#define _WORKER_H

#include <sys/time.h>
#include <glib.h>

#define CLEAR_WORKER_DATA(d) if (d) {\
	if ((d)->buffer) { g_free((d)->buffer); (d)->buffer = NULL; }\
	(d)->buffer_size = (d)->done = 0; }

typedef struct worker_data_s worker_data_t;
typedef struct worker_s worker_t;

typedef int (*worker_func_f)(worker_t *worker, GError **error);
typedef void (*worker_clean_f)(worker_t *worker);

struct worker_data_s {
	int fd;
	long sock_timeout;
	void *buffer;
	guint32 buffer_size;
	guint32 done;
	void *session;
	gboolean size_64;
};

struct worker_s {
	worker_func_f func;
	worker_clean_f clean;
	worker_data_t data;
	long timeout;
	struct timeval timestamp;
};

int agent_worker_default_func( worker_t *worker, GError **error );

void agent_worker_default_cleaner( worker_t *worker );

#endif		/* _WORKER_H */
