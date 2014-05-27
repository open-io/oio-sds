#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.cpu"
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/time.h>
#include <asm/param.h>

#include <metautils/lib/metautils.h>

#include "./cpu.h"

#define _PROC_STAT "/proc/stat"

static unsigned long parse_proc_stat(); 

void cpu_init(cpu_t *cpu) {
	gettimeofday(&(cpu->last_time), NULL);
	cpu->idle = parse_proc_stat();
}

int get_cpu_idle(cpu_t *cpu) {
	struct timeval now, sub;
	unsigned long idle = 0;
	double per_idle;

	gettimeofday(&now, NULL);
	idle = parse_proc_stat();

	timersub(&now, &(cpu->last_time), &sub);
	per_idle = (double)((idle - cpu->idle) * 1000000/HZ) / (double)(sub.tv_usec + 1000000*(sub.tv_sec));

	cpu->idle = idle;
	cpu->last_time = now;

	return(per_idle*100);
}

static unsigned long parse_proc_stat() {
	FILE *file = NULL;
	unsigned long user, nice, system, idle;

	file = fopen(_PROC_STAT, "r");
	if (file == NULL) {
		ERROR("<%s> Failed to open /proc/stat : %s", __FUNCTION__, strerror(errno));
		return(0);
	}

	fscanf(file, "cpu  %lu %lu %lu %lu", &user, &nice, &system, &idle);

	return(idle);
}
