/*
OpenIO SDS vns-agent
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

#ifndef OIO_SDS__vns_agent__lib__vns_agent_internals_h
# define OIO_SDS__vns_agent__lib__vns_agent_internals_h 1

# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include <stdarg.h>
# include <string.h>
# include <errno.h>
# include <signal.h>
# include <time.h>
# include <netdb.h>
# include <sys/types.h>
# include <sys/time.h>

# include <math.h>

# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>
# include <cluster/lib/gridcluster.h>

# include <lib/vns_agent.h>

struct vns_agent_handle_s
{
	namespace_info_t ns_info;
	GHashTable *vns_space_used;
	get_namespace_info_f get_namespace_info;
};

typedef struct vns_agent_handle_s vns_agent_handle_t;

extern struct vns_agent_handle_s *vns_agent_handle;

#endif /*OIO_SDS__vns_agent__lib__vns_agent_internals_h*/