#ifndef _CPU_H
#define _CPU_H

#include <sys/time.h>

typedef struct cpu_s {
	unsigned long idle;
	struct timeval last_time;
} cpu_t;

/**
  *	Init cpu reporting
 */
void cpu_init(cpu_t *cpu);

/**
  *	Return the CPU idle percent
  *
  *	@param cpu the cpu_t struct
  *
  *	@return the cpu idle in percent or -1 if error or unavailable
 */
int get_cpu_idle(cpu_t *cpu);

#endif	/* _CPU_H */
