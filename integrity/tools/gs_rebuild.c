#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs_rebuild"
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

#include "./repair.h"
#include "../lib/chunk_db.h"

#define BROKEN_PATTERN "[.0-9]+:[0-9]+:([^:]+):([^:]*):.*"

struct broken_element_s {
	gchar str_cid[STRLEN_CONTAINERID+1];
	gchar *str_path;
};

static gchar ns_name[LIMIT_LENGTH_NSNAME] = "";

static time_t sleep_inter_refresh = 1000L;

static GHashTable *ht_broken = NULL;

// m2v1_list declared in libintegrity
GSList *m2v1_list = NULL;

/* ------------------------------------------------------------------------- */

static time_t
timer_get_elapsed_millis(GTimer *timer)
{
	time_t t;
	gdouble d;

	if (!timer)
		return 0L;

	d = 1000.0 * g_timer_elapsed(timer, NULL);
	t = d;

	return t;
}

static void
sleep_between_refreshs(void)
{
	time_t elapsed = 0;
	GTimer *timer;

	timer = g_timer_new();

	do {
		usleep(1000 * (sleep_inter_refresh - elapsed));
		elapsed = timer_get_elapsed_millis(timer);
	} while (grid_main_is_running() && sleep_inter_refresh >= elapsed);

	g_timer_destroy(timer);
}

/* ------------------------------------------------------------------------- */

static void
service_info_free_gslist(GSList **pList)
{
	if (!pList || !*pList)
		return;
	g_slist_foreach(*pList, service_info_gclean, NULL);
	g_slist_free(*pList);
	*pList = NULL;
}

static void
service_info_trace_gslist(GSList *list, const gchar *tag)
{
	GSList *l;
	struct service_info_s *si;

	if (!TRACE_ENABLED()) {
		(void) tag;
		return;
	}
	for (l=list; l ;l=l->next) {
		if (!(si = l->data))
			TRACE("%s NULL", tag);
		else {
			gchar *str = service_info_to_string(si);
			TRACE("%s%s", tag, str);
			g_free(str);
		}
	}
}

static gboolean
service_is_rawx(struct service_info_s *si)
{
	if (!si)
		return FALSE;
	if (g_ascii_strncasecmp(si->type, "rawx", sizeof(si->type)))
		return FALSE;
	if (g_ascii_strncasecmp(si->ns_name, ns_name, sizeof(si->ns_name)))
		return FALSE;
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static void
broken_element_gclean(gpointer d, gpointer ignored)
{
	struct broken_element_s *broken;
	(void) ignored;
	if (NULL != (broken = d)) {
		if (broken->str_path)
			g_free(broken->str_path);
		g_free(broken);
	}
}

static void
broken_element_clean_gslist(GSList **pList)
{
	if (!pList || !*pList)
		return;
	g_slist_foreach(*pList, broken_element_gclean, NULL);
	g_slist_free(*pList);
	*pList = NULL;
}

static struct broken_element_s*
broken_element_dup(struct broken_element_s *orig)
{
	struct broken_element_s *copy;
	copy = g_memdup(orig, sizeof(*orig));
	if (orig->str_path)
		copy->str_path = g_strdup(orig->str_path);
	return copy;
}

static gchar *
broken_element_get_key(struct broken_element_s *broken)
{
	if (broken->str_path)
		return g_strconcat(broken->str_cid, ":", broken->str_path, NULL);
	return g_strdup(broken->str_cid);
}

static void
holder_dump(GHashTable *ht, const gchar *tag)
{
	GHashTableIter iter;
	gpointer k, v;

	if (!TRACE_ENABLED()) {
		(void) tag;
		return;
	}

	TRACE("%sBroken elements holder ++++++++", tag);
	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v))
		TRACE("%s%s", tag, (gchar*)k);
}

static GHashTable*
holder_new(void)
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
}

static void
_holder_save_content(GHashTable *ht, struct broken_element_s *broken)
{
	gchar *str_key;

	if (!broken)
		return;

	str_key = broken_element_get_key(broken);
	g_hash_table_insert(ht, str_key, str_key);
}

static void
_holder_save_container(GHashTable *ht, struct broken_element_s *broken)
{
	struct broken_element_s fake;
	gchar *str_key;

	if (!broken)
		return;

	memcpy(&fake, broken, sizeof(fake));
	fake.str_path = NULL;

	str_key = broken_element_get_key(&fake);
	g_hash_table_insert(ht, str_key, str_key);
}

static void
holder_forget(struct broken_element_s *broken)
{
	gchar *str_key;

	if (!broken)
		return ;

	str_key = broken_element_get_key(broken);
	g_hash_table_remove(ht_broken, str_key);
	g_free(str_key);
}

static GHashTable*
holder_keep_new(GSList *all, GSList **result)
{
	GHashTable *ht_new;
	GSList *l, *list_new = NULL;

	*result = NULL;
	ht_new = holder_new();
	for (l=all; l ;l=l->next) {
		struct broken_element_s *broken = l->data;


		/* Shortcut: whole container already broken? */
		if (g_hash_table_lookup(ht_broken, broken->str_cid)) {
			_holder_save_container(ht_new, broken);
			TRACE("agent told [%s:%s], but container already broken in old elements",
				broken->str_cid, broken->str_path);
			continue;
		}
		if (g_hash_table_lookup(ht_new, broken->str_cid)) {
			TRACE("agent told [%s:%s], but container already broken in new elements",
				broken->str_cid, broken->str_path);
			continue;
		}

		/* Now manage this particular element */
		gchar *str_key = broken_element_get_key(broken);
		if (broken->str_path) {
			if (g_hash_table_lookup(ht_broken, str_key)) {
				_holder_save_content(ht_new, broken);
				TRACE("agent told [%s] but already known in old elements", str_key);
			}
			else if (g_hash_table_lookup(ht_new, str_key)) {
				TRACE("agent told [%s] but already known in new elements", str_key);
			}
			else {
				list_new = g_slist_prepend(list_new, broken_element_dup(broken));
				_holder_save_content(ht_new, broken);
				GRID_DEBUG("New broken content stored [%s]", str_key);
			}
		}
		else {
			list_new = g_slist_prepend(list_new, broken_element_dup(broken));
			_holder_save_container(ht_new, broken);
			GRID_DEBUG("New broken container stored [%s]", str_key);
		}
		g_free(str_key);
	}

	/* Save the list and return the old hash_table */
	GHashTable *tmp = ht_broken;
	ht_broken = ht_new;
	*result = list_new;
	return tmp;
}

/* -------------------------------------------------------------------------- */

static gchar*
rawx_get_volume(struct service_info_s *si)
{
	gchar volname[1024];
	struct service_tag_s *tag;

	if (!si->tags)
		return g_strdup("/");

	tag = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_VOL);
	if (!tag)
		return g_strdup("/");

	if (!service_tag_get_value_string(tag, volname, sizeof(volname), NULL))
		return g_strdup("/");

	return g_strdup(volname);
}

static gs_grid_storage_t*
get_grid_client(GError **err)
{
	gs_error_t *gserr = NULL;
	gs_grid_storage_t *gs_client = NULL;

	gs_client = gs_grid_storage_init2(ns_name, 60000, 60000, &gserr);
	if (!gs_client) {
		GSETCODE(err, gs_error_get_code(gserr), "%s", gs_error_get_message(gserr));
		gs_error_free(gserr);
		return NULL;
	}

	gs_grid_storage_set_timeout(gs_client, GS_TO_RAWX_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_RAWX_OP, 90000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M0_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M0_OP, 90000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M1_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M1_OP, 90000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M2_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_M2_OP, 90000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_MCD_CNX, 30000, NULL);
	gs_grid_storage_set_timeout(gs_client, GS_TO_MCD_OP, 90000, NULL);

	return gs_client;
}

static gboolean
manage_broken_element_for_rawx(gs_grid_storage_t *gs_client, struct broken_element_s *broken, struct service_info_s *si)
{
	gboolean rc;
	gchar *vol_root = NULL;
	GSList *l, *list_of_chunks = NULL;
	GError *error_local = NULL;

	vol_root = rawx_get_volume(si);
	if (broken->str_path)
		rc = get_content_chunks(vol_root, broken->str_cid, broken->str_path, &list_of_chunks, &error_local);
	else
		rc = get_container_chunks(vol_root, broken->str_cid, &list_of_chunks, &error_local);

	if (!rc) {
		GRID_ERROR("Cannot get information about [%s:%s] in [%s] : %s",
				broken->str_cid, broken->str_path, vol_root,
				gerror_get_message(error_local));
		goto label_exit;
	}

	if (!list_of_chunks) {
		GRID_DEBUG("No information available about [%s:%s] in [%s]",
				broken->str_cid, broken->str_path, vol_root);
		goto label_exit;
	}

	GRID_DEBUG("Repairing [%s:%s] for [%s]",
			broken->str_cid, broken->str_path, vol_root);
	rc = TRUE;
	for (l=list_of_chunks; l ;l=l->next) {
		gchar *path = l->data;

		if (meta2_repair_from_rawx(path, vol_root, &(si->addr), gs_client, &error_local)) {
			if (error_local)
				GRID_INFO("Repaired the reference of [%s], but some errors occured : %s",
					path, gerror_get_message(error_local));
			else
				GRID_INFO("Repaired the reference of [%s]", path);
		}
		else {
			rc = FALSE;
			GRID_INFO("Could not repair the reference of [%s] : %s",
					path, gerror_get_message(error_local));
		}
		if (error_local)
			g_clear_error(&error_local);
	}
	g_slist_foreach(list_of_chunks, g_free1, NULL);
	g_slist_free(list_of_chunks);

label_exit:
	g_free(vol_root);
	if (error_local)
		g_clear_error(&error_local);
	return rc;
}

static GSList*
get_rawx_services(GError **err)
{
	GSList *local_services;

	local_services = list_local_services(err);
	if (!local_services) {
		if (err && *err)
			GSETERROR(err, "Cannot list local services");
		return NULL;
	}

	if (DEBUG_ENABLED())
		GRID_DEBUG("Found [%u] services on this host", g_slist_length(local_services));

	GSList *result = NULL;
	GSList *l;
	for (l=local_services; l ;l=l->next) {
		struct service_info_s *si, *copy;

		if (!(si = l->data))
			continue;

		if (service_is_rawx(si)) {
			copy = service_info_dup(si);
			result = g_slist_prepend(result, copy);
		}
	}

	service_info_free_gslist(&local_services);
	return result;
}

static GSList*
get_broken_containers(GError **err)
{
	GSList *all_broken, *l, *result = NULL;
	GRegex *regex;

	all_broken = fetch_erroneous_containers(ns_name, err);
	if (!all_broken) {
		if (err && *err)
			GSETERROR(err, "No broken elements could be fetch");
		else
			GRID_DEBUG("No broken elements from the conscience");
		return NULL;
	}

	regex = g_regex_new(BROKEN_PATTERN, G_REGEX_CASELESS, 0, err);
	if (!regex) {
		GSETERROR(err, "Invalid RegEx for broken elements : '%s'", BROKEN_PATTERN);
		goto label_exit;
	}

	for (l=all_broken; l ;l=l->next) {
		gchar *str, *str_cid, *str_path;
		struct broken_element_s local;
		GMatchInfo *mi = NULL;

		if (!(str = l->data))
			continue;

		if (g_regex_match(regex, str, 0, &mi)) {
			str_cid = g_match_info_fetch(mi, 1);
			str_path = g_match_info_fetch(mi, 2);

			bzero(&local, sizeof(local));
			g_strlcpy(local.str_cid, str_cid, sizeof(local.str_cid)-1);
			local.str_path = str_path && *str_path ? g_strdup(str_path) : NULL;
			result = g_slist_prepend(result, g_memdup(&local, sizeof(local)));

			if (str_cid)
				g_free(str_cid);
			if (str_path)
				g_free(str_path);
		}
		g_match_info_free(mi);
	}

	g_regex_unref(regex);
label_exit:
	g_slist_foreach(all_broken, g_free1, NULL);
	g_slist_free(all_broken);
	return result;
}

static gboolean
manage_new_broken_elements(GSList *list_new)
{
	container_id_t cid;
	GSList *list_of_rawx;
	GSList *l_broken, *l_rawx;
	GError *local_error;
	gs_grid_storage_t *gs_client;
	struct broken_element_s *broken;

	local_error = NULL;
	gs_client = get_grid_client(&local_error);
	if (!gs_client) {
		GRID_ERROR("Cannot get the GridClient : %s", gerror_get_message(local_error));
		g_clear_error(&local_error);
		return FALSE;
	}

	local_error = NULL;
	list_of_rawx = get_rawx_services(&local_error);
	if (!list_of_rawx) {
		gs_grid_storage_free(gs_client);
		if (!local_error)
			GRID_DEBUG("No RAWX on this host!");
		else {
			GRID_ERROR("Could not get the local RAWX from the gridagent : %s",
					gerror_get_message(local_error));
			g_clear_error(&local_error);
		}
		return FALSE;
	}

	GRID_INFO("Found [%u] RAWX for [%s] on this host", g_slist_length(list_of_rawx), ns_name);
	service_info_trace_gslist(list_of_rawx, "local rawx : ");

	for (l_broken=list_new; l_broken ;l_broken=l_broken->next) {

		broken = l_broken->data;

		for (l_rawx=list_of_rawx; l_rawx ;l_rawx=l_rawx->next) {
			(void) manage_broken_element_for_rawx(gs_client, broken, l_rawx->data);
		}

		if (!container_id_hex2bin(broken->str_cid, strlen(broken->str_cid), &cid, &local_error)) {
			GRID_ERROR("Cannot parse the container_id : %s", gerror_get_message(local_error));
			continue;
		}

		for (l_rawx=list_of_rawx; l_rawx ;l_rawx=l_rawx->next) {
			local_error = NULL;
			if (!fixed_erroneous_content(ns_name, cid, &local_error, broken->str_path)) {
				holder_forget(broken);
				GRID_ERROR("Cannot notify the conscience that [%s]:[%s] has been repaired : %s",
						broken->str_cid, broken->str_path, gerror_get_message(local_error));
			}
			if (local_error)
				g_clear_error(&local_error);
		}
	}

	if (local_error)
		g_clear_error(&local_error);
	service_info_free_gslist(&list_of_rawx);
	gs_grid_storage_free(gs_client);
	return TRUE;
}

static void
main_action_one_loop(void)
{
	GError *local_error = NULL;
	GSList *list_broken, *list_new;
	GHashTable *ht_previous;

	GRID_DEBUG("Getting the broken elements for NS=[%s]", ns_name);

	/* Read the broken elements from the gridagent */
	list_broken = get_broken_containers(&local_error);
	if (!list_broken) {
		if (local_error) {
			GRID_ERROR("Could not get the broken elements from the conscience : %s",
				gerror_get_message(local_error));
			g_error_free(local_error);
		}
		else {
			GRID_DEBUG("No broken elements got from the conscience");
			g_hash_table_remove_all(ht_broken);
		}
		return;
	}
	if (DEBUG_ENABLED())
		GRID_DEBUG("Got [%u] broken elements from the gridagent", g_slist_length(list_broken));

	/* Keep only those not yet considered as broken */
	ht_previous = holder_keep_new(list_broken, &list_new);
	broken_element_clean_gslist(&list_broken);

	holder_dump(ht_previous, "old> ");
	holder_dump(ht_broken, "new> ");

	/* Now manage those elements */
	if (!list_new)
		g_hash_table_destroy(ht_previous);
	else {
		GRID_INFO("About to recover [%u] new broken elements", g_slist_length(list_new));
		if (manage_new_broken_elements(list_new)) {
			GRID_INFO("Tried to recover the [%u] broken elements", g_slist_length(list_new));
			/* commit the changes to  */
			g_hash_table_destroy(ht_previous);
		}
		else {
			GRID_INFO("No RAWX found, rollback on broken elements");
			g_hash_table_destroy(ht_broken);
			ht_broken = ht_previous;
		}
		broken_element_clean_gslist(&list_new);
	}
}

/* ------------------------------------------------------------------------- */

static void
main_set_defaults(void)
{
	ht_broken = NULL;
	bzero(ns_name, sizeof(ns_name));
}

static gboolean
main_configure(int argc, char **args)
{
	ht_broken = holder_new();

	if (argc != 1) {
		GRID_ERROR("Missing namespace argument");
		return FALSE;
	}

	if (sizeof(ns_name) <= g_strlcpy(ns_name, args[0], sizeof(ns_name)-1)) {
		GRID_ERROR("Namespace name too long");
		return FALSE;
	}

	return TRUE;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (ht_broken) {
		g_hash_table_destroy(ht_broken);
		ht_broken = NULL;
	}
}

static void
main_action(void)
{
	main_action_one_loop();
	while (grid_main_is_running()) {
		sleep_between_refreshs();
		main_action_one_loop();
	}
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] =
		"\tExpected argument: NAMESPACE\n"
		"\t ... with NAMESPACE a namespace name declared in /etc/gridstorage.conf\n"
		;
	return xtra_usage;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

