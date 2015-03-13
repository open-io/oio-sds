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

#ifndef OIO_SDS__cluster__agent__cpu_h
# define OIO_SDS__cluster__agent__cpu_h 1

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

#endif /*OIO_SDS__cluster__agent__cpu_h*/