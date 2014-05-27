#include "meta2_mover_internals.h"
#include <cluster/lib/gridcluster.h>

static time_t meta2_last_update = 0L;
static GSList *list_of_meta2 = NULL;
static GSList *meta2_pointer = NULL;

static guint
count_valid_meta2(GSList *list, guint max, const addr_info_t *avoid)
{
	guint count;
	GSList *l;

	for (count=0,l=list; l ;l=l->next) {
		struct service_info_s *si = l->data;
		if (si->score.value == 0)
			return count;
		if (0 == memcmp(avoid, &(si->addr), sizeof(addr_info_t))) {
			/* Skip the source */
			continue;
		}
		if (++count >= max)
			return count;
	}
	return count;
}

static gboolean
conscience_load_meta2(const gchar * ns_name)
{
	GError *err = NULL;
	GSList *new_services = NULL;

	INFO("Reloading the META2 list");

	new_services = list_namespace_services(ns_name, "meta2", &err);
	if (!new_services && err) {
		if (err) {
			ERROR("reload error : %s", gerror_get_message(err));
			g_error_free(err);
		}
		return FALSE;
	}

	meta2_mover_clean_services();
	meta2_pointer = list_of_meta2 = g_slist_sort(new_services, service_info_sort_by_score);
	meta2_last_update = time(NULL);

	DEBUG("Received %u META2", g_slist_length(list_of_meta2));
	return TRUE;
}

const service_info_t*
get_available_meta2_from_conscience(const gchar * ns_name, const addr_info_t *avoid)
{
	time_t now;
	service_info_t *result;

	now = time(0);
	if (!list_of_meta2 || now > (meta2_last_update+interval_update_services))
		(void) conscience_load_meta2(ns_name);

	if (count_valid_meta2(list_of_meta2, 3, avoid) < 1) {
		DEBUG("count_valid test failed, break without getting available volume from conscience");
		return NULL;
	}

	for (;;) {

		if (!meta2_pointer) /* reset the list */
			meta2_pointer = list_of_meta2;

		result = meta2_pointer->data;

		if (result->score.value <= 0) {
			/* End of available services, reset the list. The test with
			 * cout_valid ensures there is at least one RAWX */
			meta2_pointer = list_of_meta2;
			continue;
		}

		meta2_pointer = meta2_pointer->next;

		if (0 != memcmp(avoid, &(result->addr), sizeof(addr_info_t))) {
			/* Keep the current RAWX if available and different from the source */
			return result;
		}
	}

	return NULL;
}

void
meta2_mover_clean_services(void)
{
	if (list_of_meta2) {
		g_slist_foreach(list_of_meta2, service_info_gclean, NULL);
		g_slist_free(list_of_meta2);
		list_of_meta2 = NULL;
	}
}

