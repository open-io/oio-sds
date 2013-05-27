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

#ifndef _EVENT_H_
#define _EVENT_H_

#define SPOOLDIR "/GRID/common/spool"

typedef struct spooldir_stat_s {
	guint32 nb_evt;
	guint32 total_age;
	guint32 oldest;
} spooldir_stat_t;

gboolean stat_events(spooldir_stat_t *spstat, const gchar *dir);

GSList* list_ns(const gchar * dir);

#endif	/* _EVENT_H_ */
