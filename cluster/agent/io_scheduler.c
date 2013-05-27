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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.agent.io_scheduler"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <sys/time.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils.h>

#include "./agent.h"
#include "./io_scheduler.h"
#include "./task_scheduler.h"

#define EPOLL_TIMEOUT 1000
#define MAX_EVENTS 64

static void check_worker_timeout(gpointer data, gpointer user_data);
static glong time_to_next_timed_out_worker(void);

static int epfd;
static gboolean stopped = TRUE;
static GSList *workers = NULL;

void
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

int
launch_io_scheduler(GError ** error)
{
	struct epoll_event events[MAX_EVENTS];
	int rc, i;
	long delay_next_task, delay_next_worker, delay_final;

	INFO("Launching IO scheduler");
	(void)error;

#ifdef AGENT_HYPERSPEED_MULTIVITAMINE
# define TIME_SCALE 100
#else
# define TIME_SCALE 1000
#endif
	while (!stopped) {
		memset(events, '\0', sizeof(events));
		delay_next_worker = time_to_next_timed_out_worker();
		delay_next_task = get_time_to_next_task_schedule();
		delay_final = MIN(delay_next_task,delay_next_worker);

		errno = 0;
		rc = epoll_wait(epfd, events, MAX_EVENTS, delay_final <= 0 ? 0 : TIME_SCALE * delay_final);

		if (rc < 0) {
			if (errno != EINTR)
				ERROR("Polling failed : %s", strerror(errno));
		}
		else if (rc > 0) {

			for (i = 0; i < rc; i++) {

				worker_t *worker = (worker_t *) events[i].data.ptr;

				/* Check if an error occured */
				if (events[i].events & EPOLLHUP || events[i].events & EPOLLERR) {
					int sock_err = sock_get_error(worker->data.fd);

					ERROR("An error occured on fd [%d], closing connection : %s", worker->data.fd, strerror(sock_err));

					abort_worker(worker);
				}
				else {
					GError *local_error = NULL;

					gettimeofday(&(worker->timestamp), NULL);

					TRACE("Executing worker of fd [%d]", worker->data.fd);
					if (!(worker->func(worker, &local_error))) {
						if (local_error) {
							ERROR("Failed to execute worker : %s", gerror_get_message(local_error));
							ERROR("Closing connection");
						}
						abort_worker(worker);
					}

					if (local_error)
						g_clear_error(&local_error);
				}
			}
		}

		exec_tasks();
		g_slist_foreach(workers, check_worker_timeout, NULL);
	}

	INFO("IO scheduler stopped.");
	return (1);
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

	/* Set timestamp to worker */
	memset(&(worker->timestamp), 0, sizeof(struct timeval));
	if (0 > gettimeofday(&(worker->timestamp), NULL))
		ERROR("Failed to set timestamp in worker");

	/* Append worker to the list */
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

	/* Set timestamp to worker */
	memset(&(worker->timestamp), 0, sizeof(struct timeval));
	if (0 > gettimeofday(&(worker->timestamp), NULL))
		ERROR("Failed to set timestamp in worker");

	return (1);
}

int
remove_fd_from_io_scheduler(worker_t * worker, GError ** error)
{
	worker_data_t *data;
	
	TRACE_POSITION();

	data = &(worker->data);
	TRACE("Closing fd %d", data->fd);
	workers = g_slist_remove(workers, worker);

	if (0 > epoll_ctl(epfd, EPOLL_CTL_DEL, data->fd, NULL)) {
		GSETERROR(error, "Failed to remove fd from epoll pool : %s", strerror(errno));
		return (0);
	}

	close(data->fd);
	return (1);
}

void
check_worker_timeout(gpointer data, gpointer user_data)
{
	worker_t *worker = (worker_t *) data;
	struct timeval tv, elapsed, timeout;

	(void)user_data;
	memset(&tv, 0, sizeof(struct timeval));
	memset(&elapsed, 0, sizeof(struct timeval));
	memset(&timeout, 0, sizeof(struct timeval));

	if (worker == NULL || worker->timeout == 0)
		return;

	timeout.tv_sec = (worker->timeout) / 1000;
	timeout.tv_usec = 1000 * (worker->timeout % 1000);

	if (0 > gettimeofday(&tv, NULL))
		return;

	timersub(&tv, &(worker->timestamp), &elapsed);

	if (timercmp(&elapsed, &timeout, >)) {
		WARN("Worker %p timeout", worker);
		abort_worker(worker);
	}
}

glong
time_to_next_timed_out_worker(void)
{
	GSList *list = NULL;
	worker_t *worker = NULL;
	long shortest = G_MAXLONG;
	struct timeval tv, elapsed, timeout, rest;

	memset(&tv, 0, sizeof(struct timeval));

	if (0 > gettimeofday(&tv, NULL))
		return (shortest);

	for (list = workers; list && list->data; list = list->next) {
		worker = (worker_t *) list->data;

		if (worker->timeout == 0)
			continue;

		memset(&timeout, 0, sizeof(struct timeval));
		memset(&elapsed, 0, sizeof(struct timeval));
		memset(&rest, 0, sizeof(struct timeval));

		timeout.tv_sec = (worker->timeout) / 1000;
		timeout.tv_usec = 1000 * (worker->timeout % 1000);
		
		timersub(&tv, &(worker->timestamp), &elapsed);
		timersub(&timeout, &elapsed, &rest);

		if (rest.tv_sec < shortest)
			shortest = rest.tv_sec;

	}

	return ((shortest < 1) ? 1 : shortest);
}
