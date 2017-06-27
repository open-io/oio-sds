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

#include "metautils_macros.h"
#include "metatypes.h"
#include <glib.h>

#define HC_PROC_INIT(argv,LVL) do { \
	grid_main_srand(); \
	grid_main_set_prgname(argv[0]); \
	oio_log_lazy_init (); \
	oio_log_init_level(LVL); \
	g_log_set_default_handler(oio_log_stderr, NULL); \
	oio_ext_set_random_reqid (); \
} while (0)

enum oio_main_option_type_e {
	OT_BOOL=1,
	OT_INT,
	OT_UINT,
	OT_INT64,
	OT_DOUBLE,
	OT_TIME,
	OT_STRING,
	OT_LIST
};

union oio_main_option_value_u {
	/* Never used in facts, some IDE (e.g. CLion) are bad at checking
	 * initializations of unions, and consider only the first choice. All
	 * the choices are pointers, so authorizing a <void*> as first choice
	 * will make the IDE happy, even if unused anywhere. */
	void *any;
	gboolean *b;
	gint *i;
	guint *u;
	gint64 *i64;
	gdouble *d;
	time_t *t;
	GString **str;
	GSList **lst;
};

struct grid_main_option_s
{
	const char *name;
	enum oio_main_option_type_e type;
	union oio_main_option_value_u data;
	const char *descr;
};

extern char syslog_id[64];
extern char udp_target[STRLEN_ADDRINFO];

/** Has the SIGHUP been raised */
extern volatile gboolean main_signal_SIGHUP;

/**
 * Returns an array of extra options managed by the current process.
 *
 * Define your own to manage options. Carefully set an empty option
 * as the last element of the array.
 *
 * MANDATORY, NOT PROVIDED BY DEFAULT
 */
struct grid_main_callbacks
{
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

void logger_udp_open (const char *target);

/* Activate syslog logging */
void logger_syslog_open (void);

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
