#ifndef HC_policycheck_repair_h
# define HC_policycheck_repair_h 1

#include <glib.h>
#include <meta2v2/meta2_utils.h>

struct hc_url_s;
struct hc_resolver_s;
struct grid_lbpool_s;
struct namespace_info_s;
struct m2v2_check_s;

struct policy_check_s
{
	struct hc_url_s *url;
	struct hc_resolver_s *resolver;
	struct grid_lbpool_s *lbpool;
	struct namespace_info_s *nsinfo;
	gboolean check_only;

	struct m2v2_check_s *check;
	gchar **m2urlv;
};

struct chunk_location_s
{
	m2v2_chunk_pair_t *chunk_pair;
	gchar *location;
};

GError* policy_check_and_repair(struct policy_check_s *pc);

GError* policy_load_beans(struct policy_check_s *pc);

#endif
