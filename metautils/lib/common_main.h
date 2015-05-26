/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__metautils__lib__common_main_h
# define OIO_SDS__metautils__lib__common_main_h 1

# include <glib/gtypes.h>

/**
 * @defgroup metautils_main Common Main
 * @ingroup metautils
 * @{
 */

#define HC_PROC_INIT(argv,LVL) do { \
	grid_main_srand(); \
	grid_main_set_prgname(argv[0]); \
	logger_lazy_init (); \
	logger_init_level(LVL); \
	g_log_set_default_handler(logger_stderr, NULL); \
} while (0)

#define HC_TEST_INIT(argc,argv) do { \
	grid_main_srand(); \
	g_test_init (&argc, &argv, NULL); \
	grid_main_set_prgname(argv[0]); \
	logger_lazy_init (); \
	logger_init_level(GRID_LOGLVL_INFO); \
	logger_init_level_from_env("G_DEBUG_LEVEL"); \
	g_log_set_default_handler(logger_stderr, NULL); \
} while (0)

/**
 *
 */
struct grid_main_option_s {
	const char *name;
	enum {
		OT_BOOL=1,
		OT_INT,
		OT_UINT,
		OT_INT64,
		OT_DOUBLE,
		OT_TIME,
		OT_STRING,
		OT_LIST
	} type;
	union {
		gboolean *b;
		guint *u;
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

/** Uses sigprocmask to block a lot of signals */
void metautils_ignore_signals(void);

/** Stops the execution of the processus */
void grid_main_stop(void);

/** Tests if the processus execution has been stopped */
gboolean grid_main_is_running(void);

/** Calls this a the main routine for a non-deamonizable program */
int grid_main(int argc, char ** argv, struct grid_main_callbacks *cb);

/** Calls this a the main routine for a non-deamonizable program */
int grid_main_cli(int argc, char ** argv, struct grid_main_callbacks *cb);

/** Sets the result code of grid_main() and grid_main_cli() */
void grid_main_set_status(int rc);

/** Use this to set the name of the current command, this let the HC API
 * apply the same filter on it (e.g. keep the basename) */
void grid_main_set_prgname(const gchar *cmd);

void grid_main_srand(void);

#endif /*OIO_SDS__metautils__lib__common_main_h*/
