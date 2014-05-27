#ifndef __VNS_AGENT_INTERNALS_H__
# define __VNS_AGENT_INTERNALS_H__

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

# include <remote/vns_agent_remote.h>
# include <lib/vns_agent.h>

struct vns_agent_handle_s
{
	namespace_info_t ns_info;
	GHashTable *vns_space_used;
	get_namespace_info_f get_namespace_info;
};

typedef struct vns_agent_handle_s vns_agent_handle_t;

extern struct vns_agent_handle_s *vns_agent_handle;

#endif /*__VNS_AGENT_INTERNALS_H__*/
