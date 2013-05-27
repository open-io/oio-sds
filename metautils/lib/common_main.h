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

/**
 * @file common_main.h
 * Simple features set to unify all the dfeatures common to all grid
 * processes: logging, daemonizing, configuring, pidfile writing, etc.
 */

#ifndef GRID__COMMON_MAIN_H
# define GRID__COMMON_MAIN_H 1

/**
 *
 */
struct grid_main_option_s {
	const char *name;
	enum {
		OT_BOOL=1,
		OT_INT,
		OT_INT64,
		OT_DOUBLE,
		OT_TIME,
		OT_STRING,
		OT_LIST
	} type;
	union {
		gboolean *b;
		gint *i;
		gint64 *i64;
		gdouble *d;
		time_t *t;
		GString **str;
		GSList **lst;
	} data;
	const char *descr;
};

/**
 * Stops the execution of the processus
 */
void grid_main_stop(void);

/**
 * Tests if the processus execution has been stopped
 * @return
 */
gboolean grid_main_is_running(void);

/**
 * Returns an array of extra options managed by the current process.
 *
 * Define your own to manage options. Carefully set an empty option
 * as the last element of the array.
 *
 * MANDATORY, NOT PROVIDED BY DEFAULT
 */
struct grid_main_callbacks {
	struct grid_main_option_s * (*options) (void);
	void (*action) (void);
	void (*set_defaults) (void);
	void (*specific_fini) (void);
	gboolean (*configure) (int argc, char **argv);
	const char * (*usage) (void);
	void (*specific_stop) (void);
};

/**
 * @param argc
 * @param argv
 * @param callbacks
 * @return
 */
int grid_main(int argc, char ** argv,
		struct grid_main_callbacks * callbacks);

/**
 * @param argc
 * @param argv
 * @param callbacks
 * @return
 */
int grid_main_cli(int argc, char ** argv,
		struct grid_main_callbacks * callbacks);

#endif
