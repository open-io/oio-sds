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

#ifndef __SRV_TIMER_H__
# define __SRV_TIMER_H__

#include <glib.h>

typedef void (*srvtimer_f) (gpointer udata);

gboolean srvtimer_register_regular (const char *name, srvtimer_f fire,
	srvtimer_f close, gpointer udata, guint64 freq);

void srvtimer_init (void);

void srvtimer_fini (void);

void srvtimer_fire (guint64 ticks);

#endif /*__SRV_TIMER_H__*/
