/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./io_scheduler.h"
#include "./task_scheduler.h"

#define EPOLL_TIMEOUT 1000
#define MAX_EVENTS 64

static int epfd;
static gboolean stopped = TRUE;
static GSList *workers = NULL;
static gint64 first_timeout = 0;

static gint64 _now () { return g_get_monotonic_time () / 1000; }

static void
abort_worker(worker_t *worker)
{
	remove_fd_from_io_scheduler(worker, NULL);
	if (worker->clean)
		worker->clean(worker);
	g_free(worker);
}

int
init_io_scheduler(GError ** error)
{
	stopped = FALSE;

	epfd = epoll_create(MAX_EVENTS);
	if (epfd < 0) {
		GSETERROR(error, "Failed to create epoll fd : %s", strerror(errno));
		return (0);
	}

	/* Initialize the task scheduler */
	init_task_scheduler();
	return (1);
}

static gboolean
worker_has_timeout (worker_t *w)
{
	return w->timeout.activity > 0 || w->timeout.startup > 0;
}

static gint64
worker_get_timeout (worker_t *w)
{
	gint64 timeout_startup = G_MAXINT64;
	if (w->timeout.startup > 0)
		timeout_startup = w->timepoint.startup + (w->timeout.startup * 1000);

	gint64 timeout_activity = G_MAXINT64;
	if (w->timeout.activity > 0)
		timeout_activity = w->timepoint.activity + (w->timeout.activity * 1000);

	return MIN(timeout_activity,timeout_startup);
}

static gint64
worker_first_timeout (void)
{
	gint64 next = G_MAXINT64;
	for (GSList *l = workers; l ;l=l->next) {
		worker_t *w = (worker_t *) l->data;
		if (w) {
			gint64 n = worker_get_timeout(w);
			next = MIN(next, n);
		}
	}
	return next;
}

static gint64
time_to_next_timed_out_worker(gint64 now)
{
	if (now >= first_timeout)
		first_timeout = worker_first_timeout();
	return (first_timeout < now) ? 0 : (first_timeout - now);
}

static void
worker_set_last_activity (worker_t *w, gint64 when)
{
	if (!w->timepoint.startup)
		w->timepoint.startup = when;
	w->timepoint.activity = when;

	gint64 timeout = worker_get_timeout (w);
	first_timeout = MIN(first_timeout,timeout);
}

static long
_delay(void)
{
	gint64 now = _now();
	gint64 d0 = time_to_next_timed_out_worker(now);
	gint64 d1 = time_to_next_timed_out_task(now);
	d0 = MIN(d0, d1);
	return CLAMP(d0, 10, 5000);
}

static gboolean
_workers_abort_timedout (gint64 now)
{
	GSList *to_abort = NULL;

	for (GSList *l=workers; l ;l=l->next) {
		worker_t *w = l->data;
		if (!worker_has_timeout(w))
			continue;
		gint64 timeout = worker_get_timeout (w);
		if (timeout <= now) {
			to_abort = g_slist_prepend (to_abort, w);
			GRID_WARN("Worker %p timeout (idle since %"G_GINT64_FORMAT"ms,"
					" started since %"G_GINT64_FORMAT"ms)", w,
					now - w->timepoint.activity,
					now - w->timepoint.startup);
		}
	}

	gboolean rc = (to_abort != NULL);
	for (GSList *l=to_abort; l ;l=l->next)
		abort_worker(l->data);
	g_slist_free (to_abort);
	return rc;
}

void
launch_io_scheduler(void)
{
	struct epoll_event events[MAX_EVENTS];

	INFO("Launching IO scheduler");

	while (!stopped) {

		gboolean anything_aborted = FALSE;
		int rc = epoll_wait(epfd, events, MAX_EVENTS, _delay());

		if (rc < 0) {
			if (errno != EINTR)
				ERROR("Polling failed : %s", strerror(errno));
		}
		else if (rc > 0) {

			for (int i = 0; i < rc; i++) {

				worker_t *worker = (worker_t *) events[i].data.ptr;

				/* Check if an error occured */
				if (events[i].events & (EPOLLHUP|EPOLLERR)) {
					int sock_err = socket_get_errcode(worker->data.fd);
					ERROR("An error occured on fd [%d], closing connection : %s",
							worker->data.fd, strerror(sock_err));
					abort_worker(worker);
					anything_aborted = TRUE;
				}
				else {
					GError *local_error = NULL;
					worker_set_last_activity(worker, _now());

					TRACE("Executing worker of fd [%d]", worker->data.fd);
					if (!(worker->func(worker, &local_error))) {
						anything_aborted = TRUE;
						if (local_error)
							ERROR("Failed to execute worker : %s", gerror_get_message(local_error));
						abort_worker(worker);
					}

					if (local_error)
						g_clear_error(&local_error);
				}
			}
		}

		gint64 now = _now();
		exec_tasks(now);
		anything_aborted |= _workers_abort_timedout (now);

		if (anything_aborted)
			first_timeout = worker_first_timeout ();
	}

	INFO("IO scheduler stopped.");
}

void
stop_io_scheduler(void)
{
	if (!stopped) 
		INFO("Stopping IO scheduler...");
	stopped = TRUE;
}

int
add_fd_to_io_scheduler(worker_t * worker, __uint32_t events, GError ** error)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));

	ev.events = events;
	ev.data.ptr = worker;

	TRACE("Adding fd %i to polling of events %u", worker->data.fd, events);

	if (0 > epoll_ctl(epfd, EPOLL_CTL_ADD, worker->data.fd, &ev)) {
		GSETERROR(error, "Failed to add fd to epoll pool : %s", strerror(errno));
		return (0);
	}

	worker_set_last_activity (worker, _now());
	workers = g_slist_prepend(workers, worker);
	return (1);
}

int
change_fd_events_in_io_scheduler(worker_t * worker, __uint32_t events, GError ** error)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.events = events;
	ev.data.ptr = worker;

	if (0 > epoll_ctl(epfd, EPOLL_CTL_MOD, worker->data.fd, &ev)) {
		GSETERROR(error, "Failed to add fd to epoll pool : %s", strerror(errno));
		return (0);
	}

	worker_set_last_activity (worker, _now());
	return (1);
}

int
remove_fd_from_io_scheduler(worker_t * w, GError ** error)
{
	(void) error;
	worker_data_t *data = &(w->data);
	workers = g_slist_remove(workers, w);
	metautils_pclose (&(data->fd));
	return (1);
}

