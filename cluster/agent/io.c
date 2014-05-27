#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.io"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <metautils/lib/metautils.h>

#include "./io.h"


/*
	This io reporting uses the 10th field in /proc/diskstats which is the time (in ms) spent doing IO.
	The result is reversed to give a % of time not doing IO.
*/

#define PROC_DISKSTATS "/proc/diskstats"
#define SCAN_TEMPLATE "%s %%*u %%*u %%*u %%*u %%*u %%*u %%*u %%*u %%*u %%lu"

static unsigned long parse_proc_diskstats(char *device);

void
io_init(io_t * io, const char *device)
{
	io->device_name = strdup(device);
	gettimeofday(&(io->last_time), NULL);
	io->io_time = parse_proc_diskstats(io->device_name);
}

int
get_free_io(io_t * io)
{
	struct timeval now, sub;
	unsigned long io_time = 0;
	double per_io;

	gettimeofday(&now, NULL);
	io_time = parse_proc_diskstats(io->device_name);

	timersub(&now, &(io->last_time), &sub);
	per_io = (double) ((io_time - io->io_time) * 1000) / (double) (sub.tv_usec + 1000000 * (sub.tv_sec));

	io->io_time = io_time;
	io->last_time = now;

	return (100 - (per_io * 100));
}

static unsigned long
parse_proc_diskstats(char *device)
{
	int fd;
	unsigned long io_time = 0;
	char scan[256];
	char buff[1025];
	char *to_scan = NULL;

	snprintf(scan, sizeof(scan), SCAN_TEMPLATE, device);

	fd = open(PROC_DISKSTATS, O_RDONLY);
	if (fd < 0) {
		ERROR("<%s> Failed to open %s : %s", __FUNCTION__, PROC_DISKSTATS, strerror(errno));
		return (0);
	}

	memset(buff, 0x00, sizeof(buff));
	read(fd, buff, sizeof(buff) - 1);

	to_scan = strstr(buff, device);
	if (to_scan == NULL) {
		ERROR("<%s> Device not found in %s", __FUNCTION__, PROC_DISKSTATS);
		return (0);
	}

	sscanf(to_scan, scan, &io_time);

	return (io_time);
}
