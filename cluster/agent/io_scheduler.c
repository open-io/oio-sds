#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.io_scheduler"
#endif

#include <sys/time.h>
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

static void check_worker_timeout(gpointer data, gpointer user_data);
static glong time_to_next_timed_out_worker(void);

static int epfd;
static gboolean stopped = TRUE;
static GSList *workers = NULL;

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

static inline long
_delay(void)
{
	register long d0 = time_to_next_timed_out_worker();
	register long d1 = get_time_to_next_task_schedule();
	d0 = MACRO_MIN(d0, d1);
	return 1000 * MACRO_MAX(0, d0);
}

void
launch_io_scheduler(void)
{
	struct epoll_event events[MAX_EVENTS];

	INFO("Launching IO scheduler");

	while (!stopped) {

		memset(events, 0, sizeof(events));
		errno = 0;
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
					int sock_err = sock_get_error(worker->data.fd);
					ERROR("An error occured on fd [%d], closing connection : %s",
							worker->data.fd, strerror(sock_err));
					abort_worker(worker);
				}
				else {
					GError *local_error = NULL;

					gettimeofday(&(worker->timestamp), NULL);

					TRACE("Executing worker of fd [%d]", worker->data.fd);
					if (!(worker->func(worker, &local_error))) {
						if (local_error) {
							ERROR("Failed to execute worker : %s", gerror_get_message(local_error));
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
	(void) error;
	worker_data_t *data = &(worker->data);
	workers = g_slist_remove(workers, worker);
	metautils_pclose(&(data->fd));
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
		WARN("Worker %p timeout (elapsed %ldms)", worker,
				elapsed.tv_sec * 1000 + elapsed.tv_usec / 1000);
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
