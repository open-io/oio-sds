/*
OpenIO SDS cluster
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

static void
usage(void)
{
	g_printerr("Usage: gridcluster [OPTION]... <NAMESPACE>...\n\n");
	g_printerr("  %-20s\t%s\n", "--clear-services SERVICE    ", "Clear all local RAWX reference in cluster.");
	g_printerr("  %-20s\t%s\n", "--full,                     ", "Show full services.");
	g_printerr("  %-20s\t%s\n", "--lb-config,                ", "Prints to stdout the namespace LB configuration ");
	g_printerr("  %-20s\t%s\n", "--local-cfg,              -A", "Prints to stdout the namespaces configuration values locally configured");
	g_printerr("  %-20s\t%s\n", "--local-ns,               -L", "Prints to stdout the namespaces locally configured");
	g_printerr("  %-20s\t%s\n", "--local-srv               -l", "List local services monitored on this server.");
	g_printerr("  %-20s\t%s\n", "--local-tasks,            -t", "List internal tasks scheduled on this server.");
	g_printerr("  %-20s\t%s\n", "--raw,                    -r", "Output in parsable mode.");
	g_printerr("  %-20s\t%s\n", "--service <service desc>, -S", "Select service described by desc.");
	g_printerr("  %-20s\t%s\n", "--set-score <[0..100]>      ", "Set and lock score for the service specified by -S.");
	g_printerr("  %-20s\t%s\n", "--unlock-score              ", "Unlock score for the service specified by -S.");
	g_printerr("  %-20s\t%s\n", "--verbose,                -v", "Increases the verbosity");
}

static void
print_formatted_hashtable(GHashTable *ht, const gchar *name)
{
	if (!ht)
		return;

	GList *lk = g_hash_table_get_keys (ht);
	lk = g_list_sort (lk, (GCompareFunc) g_ascii_strcasecmp);
	for (GList *l=lk; l ;l=l->next) {
		const gchar *key = l->data;
		GByteArray *value = g_hash_table_lookup (ht, key);
		g_print("%20s : %s = %.*s\n", name, key, value->len, (gchar*)(value->data));
	}
	g_list_free(lk);
}

static void
print_formated_namespace(namespace_info_t * ns)
{
	g_print("\n");
	g_print("NAMESPACE INFORMATION\n");
	g_print("\n");
	g_print("%20s : %s\n", "Name", ns->name);
	g_print("%20s : %"G_GINT64_FORMAT" bytes\n", "Chunk size", ns->chunk_size);

	print_formatted_hashtable(ns->options, "Option");
	print_formatted_hashtable(ns->storage_policy, "Storage Policy");
	print_formatted_hashtable(ns->storage_class, "Storage Class");
	print_formatted_hashtable(ns->data_security, "Data Security");
	print_formatted_hashtable(ns->data_treatments, "Data Treatments");

	GError *err = NULL;
	GSList *types = NULL;
	if (NULL != (err = conscience_get_types (ns->name, &types)))
		g_clear_error (&err);

	/* dump the directory load-balancing configuration */
	gchar *cfg = gridcluster_get_service_update_policy(ns);
	if (!cfg) {
		g_printerr("Invalid NSINFO\n");
	} else {
		struct service_update_policies_s *pol = service_update_policies_create();
		err = service_update_reconfigure(pol, cfg);
		g_free(cfg); cfg=NULL;

		if (err) {
			g_printerr("Invalid namespace configuration : (%d) %s\n",
					err->code, err->message);
			service_update_policies_destroy(pol);
			g_clear_error(&err);
			return;
		} else {
			char *tmp = NULL;
			tmp = service_update_policies_dump(pol);
			g_print("%20s : %s\n", "LB(srv)", tmp);
			g_free(tmp);

			for (GSList *l=types; l ;l=l->next) {
				const char *srvtype = l->data;
				guint count = service_howmany_replicas(pol, srvtype);
				guint dist = service_howmany_distance(pol, srvtype);
				g_print("%20s : %s -> %s|%u|%u\n", "", srvtype,
						service_update_policy_to_string(
							service_howto_update (pol, srvtype)),
						count ? count : 1, dist ? dist : 1);
			}
		}
		service_update_policies_destroy(pol);
	}

	/* dump the rawx load-balancing for the meta2 */
	struct grid_lbpool_s *glp = grid_lbpool_create (ns->name);
	grid_lbpool_reconfigure (glp, ns);
	gboolean first = TRUE;
	void _dump (const char *srvtype) {
		struct grid_lb_iterator_s *it = grid_lbpool_ensure_iterator (glp, srvtype);
		GString *gs = grid_lb_iterator_to_string (it);
		g_print("%20s : %s=%s\n", first ? "LB(meta2)" : "", srvtype, gs->str);
		g_string_free (gs, TRUE);
		first = FALSE;
	}
	if (!types) {
		_dump (NAME_SRVTYPE_RAWX);
	} else for (GSList *l=types; l ;l=l->next) {
		_dump (l->data);
	}

	g_slist_free_full (types, g_free);
	grid_lbpool_destroy (glp);
	g_print("\n");
}

static void
print_formated_services(const gchar * type, GSList * services,
	gboolean show_internals)
{
	if(services && 0 < g_slist_length(services)) {

		gboolean init = FALSE;
		for (GSList *l = services; l; l = l->next) {
			struct service_info_s *si = l->data;
			if(!si)
				continue;
			if(show_internals || !service_info_is_internal(si)) {
				if(!init) {
					g_print("\n-- %s --\n", type);
					init = TRUE;
				}
				char str_score[32];
				char str_addr[STRLEN_ADDRINFO];

				grid_addrinfo_to_string(&(si->addr), str_addr, sizeof(str_addr));
				g_snprintf(str_score, sizeof(str_score), "%d", si->score.value);
				g_print("%20s\t%20s\n", str_addr, str_score);
			}
		}
	}
}

static void
print_raw_services(const gchar * ns, const gchar * type, GSList * services,
	gboolean show_internals)
{
	GSList *l;

	if (!services)
		return;
	for (l = services; l; l = l->next) {
		struct service_info_s *si;
		char str_score[32];
		char str_addr[STRLEN_ADDRINFO];

		si = l->data;
		if (!si)
			continue;
		if(show_internals || !service_info_is_internal(si)) {
			grid_addrinfo_to_string(&(si->addr), str_addr, sizeof(str_addr));
			g_snprintf(str_score, sizeof(str_score), "%d", si->score.value);
			g_print("%s|%s|%s|score=%d", ns ? ns : si->ns_name,
					type ? type : si->type, str_addr, si->score.value);
			if (si->tags) {
				int i, max;
				struct service_tag_s *tag;
				gchar str_tag_value[256];

				for (i = 0, max = si->tags->len; i < max; i++) {
					tag = g_ptr_array_index(si->tags, i);
					service_tag_to_string(tag, str_tag_value,
							sizeof(str_tag_value));
					g_print("|%s=%s", tag->name, str_tag_value);
				}
			}
			g_print("\n");
		}
	}
}

static void
raw_print_list_task(GSList * tasks)
{
	GSList *le = NULL;
	struct task_s *task;

	for (le = tasks; le && le->data; le = le->next) {
		task = (struct task_s *) le->data;

		g_print("%s|%"G_GINT64_FORMAT"|%s\n", task->id, task->period, task->busy ? "running" : "waiting");
	}
}

static GError *
set_service_score(const char *service_desc, int score)
{
	gchar **tokens = g_strsplit(service_desc, "|", 4);
	if (!tokens)
		return NEWERROR(CODE_INTERNAL_ERROR, "split failed (OOM?)");
	STRINGV_STACKIFY(tokens);
	if (g_strv_length(tokens) < 3)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid service description");

	gchar *cs = gridcluster_get_conscience(tokens[0]);
	STRING_STACKIFY (cs);
	if (!cs)
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Unknown namespace %s", tokens[0]);

	struct service_info_s *si = g_malloc0(sizeof(struct service_info_s));
	g_strlcpy(si->ns_name, tokens[0], sizeof(si->ns_name));
	g_strlcpy(si->type, tokens[1], sizeof(si->type));
	si->score.value = score;
	si->score.timestamp = time(0);

	if (!grid_string_to_addrinfo(tokens[2], &si->addr)) {
		service_info_clean (si);
		return NEWERROR(CODE_BAD_REQUEST, "Invalid service address %s", tokens[2]);
	}

	GSList *list = g_slist_prepend(NULL, si);
	GError *err = conscience_remote_push_services(cs, list);
	g_slist_free(list);
	if (err)
		g_prefix_error(&err, "Registration failed: ");
	service_info_clean (si);
	return err;
}

static void
enable_debug(void)
{
	gchar *str_enable;

	str_enable = getenv("GS_DEBUG_ENABLE");
	if (!str_enable)
		return;
}

int
main(int argc, char **argv)
{
	int rc = -1;
	gchar *namespace = NULL;
	gboolean has_allcfg = FALSE;
	gboolean has_nslist = FALSE;
	gboolean has_show_internals = FALSE;
	gboolean has_raw = FALSE;
	gboolean has_clear_services = FALSE;
	gboolean has_list = FALSE;
	gboolean has_set_score = FALSE;
	gboolean has_unlock_score = FALSE;
	gboolean has_service = FALSE;
	gboolean has_list_task = FALSE;
	gboolean has_flag_full = FALSE;
	int c = 0;
	int option_index = 0;
	int score = -1;
	char service_desc[512], cid_str[128];
	namespace_info_t *ns = NULL;
	GError *error = NULL;
	static struct option long_options[] = {
		/* long options only */
		{"set-score",      1, 0, 4},
		{"unlock-score",   0, 0, 5},
		{"full",           0, 0, 7},

		/* both long and short */
		{"config",         0, 0, 'c'},
		{"clear-services", 1, 0, 'C'},
		{"service",        1, 0, 'S'},
		{"local-cfg",      0, 0, 'A'},
		{"local-ns",       0, 0, 'L'},
		{"local-srv",      0, 0, 'l'},
		{"local-tasks",    0, 0, 't'},
		{"show",           0, 0, 's'},
		{"show-internals", 0, 0, 'a'},
		{"raw",            0, 0, 'r'},
		{"help",           0, 0, 'h'},
		{"verbose",        0, 0, 'v'},
		{0, 0, 0, 0}
	};

	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);

	memset(service_desc, '\0', sizeof(service_desc));
	memset(cid_str, 0x00, sizeof(cid_str));
	enable_debug();

	while ((c = getopt_long(argc, argv, "ALsvaltrC:S:h", long_options, &option_index)) > -1) {

		switch (c) {
			case 'A':
				has_allcfg = TRUE;
				break;
			case 'L':
				has_nslist = TRUE;
				break;
			case 'C':
				if (!optarg) {
					g_printerr("The option '-C' requires an argument. Try %s -h\n", argv[0]);
					abort();
				}
				g_strlcpy(service_desc, optarg, sizeof(service_desc)-1);
				has_clear_services = TRUE;
				break;
			case 4:
				has_set_score = TRUE;
				score = atoi(optarg);
				break;
			case 5:
				has_set_score = TRUE;
				has_unlock_score = TRUE;
				break;
			case 7:
				has_flag_full = TRUE;
				break;
			case 'S':
				has_service = TRUE;
				if (!optarg) {
					g_printerr("The option '-S' requires an argument. Try %s -h\n", argv[0]);
					abort();
				}
				g_strlcpy(service_desc, optarg, sizeof(service_desc));
				break;
			case 'l':
				has_list = TRUE;
				break;
			case 't':
				has_list_task = TRUE;
				break;
			case 'r':
				has_raw = TRUE;
				break;
			case 'v':
				oio_log_verbose();
				break;
			case 'a':
				has_show_internals = TRUE;
				break;
			case 'h':
				rc = 0;
			case '?':
			case 0:
			default:
				usage();
				goto exit_label;
		}
	}

	if (has_allcfg) {
		GHashTable *ht_cfg = oio_cfg_parse();
		GHashTableIter iter;
		gpointer k, v;
		g_hash_table_iter_init(&iter, ht_cfg);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_print("%s=%s\n", (gchar*)k, (gchar*)v);
		g_hash_table_destroy(ht_cfg);
		goto success_label;
	}

	if (has_nslist) {
		gchar **pns, **allns;
		allns = oio_cfg_list_ns();
		for (pns=allns; *pns ;pns++)
			g_print("%s\n",*pns);
		g_strfreev(allns);
		goto success_label;
	}

	if (!has_list && !has_set_score && !has_list_task) {
		namespace = argv[argc - 1];
		if (argc < 2 || namespace == NULL) {
			g_printerr("\nNo namespace specified in args, aborting.\n\n");
			usage();
			goto exit_label;
		}

		error = conscience_get_namespace(namespace, &ns);
		if (ns == NULL) {
			g_printerr("Failed to get namespace info :\n");
			g_printerr("%s\n", error->message);
			goto exit_label;
		}
	}

	if (has_clear_services) {

		if (NULL != (error = conscience_remove_services(namespace, service_desc))) {
			g_printerr("Failed to send clear order to cluster for ns='%s' and service='%s' :\n", namespace,
					service_desc);
			g_printerr("%s\n", error->message);
			goto exit_label;
		}
		else {
			g_print("CLEAR order successfully sent to cluster for ns='%s' and service='%s'.\n", namespace,
					service_desc);
		}

	}
	else if (has_list) {

		GSList *services = list_local_services(&error);

		if (services == NULL && error) {
			g_printerr("Failed to get service list\n");
			g_printerr("%s\n", error->message);
			goto exit_label;
		}

		print_raw_services(NULL, NULL, services, has_show_internals);
		g_slist_free_full (services, (GDestroyNotify)service_info_clean);

	}
	else if (has_list_task) {

		GSList *tasks = list_tasks(&error);

		if (tasks == NULL && error) {
			g_printerr("Failed to get task list \n");
			g_printerr("%s\n", error->message);
			goto exit_label;
		}

		raw_print_list_task(tasks);

	}
	else if (has_set_score) {

		if (!has_service) {
			g_printerr("No service specified.\n");
			g_printerr("Please, use the -S option to specify a service.\n");
			goto exit_label;
		}

		score = CLAMP(score, SCORE_DOWN, SCORE_MAX);
		error = set_service_score(service_desc, has_unlock_score ? SCORE_UNLOCK : score);
		if (error) {
			g_printerr("Failed to set score of service [%s] :\n", service_desc);
			g_printerr("%s\n", error->message);
			goto exit_label;
		}

		if (has_unlock_score)
			g_print("Service [%s] score has been successfully unlocked\n", service_desc);
		else
			g_print("Score of service [%s] has been successfully locked to %d\n", service_desc, score);

	}
	else {

		if (!has_raw)
			print_formated_namespace(ns);

		gchar *csurl = gridcluster_get_conscience(namespace);
		STRING_STACKIFY(csurl);
		if (!csurl) {
			g_printerr("No conscience address known for [%s]\n", namespace);
			goto exit_label;
		}
		GSList *services_types = NULL;
		error = conscience_get_types (namespace, &services_types);

		if (error) {
				g_printerr("Failed to get the services list: %s\n", gerror_get_message(error));
				goto exit_label;
		} else if (!services_types) {
			g_print("No service type known in namespace=%s\n", namespace);
		} else {
			for (GSList *st = services_types; st; st = st->next) {
				GSList *list_services = NULL;
				gchar *str_type = st->data;

				/* Generate the list */
				if (!has_flag_full || !has_raw) {
					error = conscience_get_services (namespace, str_type, &list_services);
				} else {
					error = conscience_remote_get_services(csurl, str_type, TRUE, &list_services);
				}

				/* Dump the list */
				if (error && !list_services) {
					g_printerr("No service known for namespace %s and service"
							" type %s : %s\n",
							namespace, str_type, gerror_get_message(error));
				}
				else {
					if (has_raw)
						print_raw_services(namespace, str_type, list_services,
								has_show_internals);
					else
						print_formated_services(str_type, list_services,
								has_show_internals);
				}

				if (error)
					g_clear_error(&error);

				/* Clean the list */
				if (list_services) {
					g_slist_foreach(list_services, service_info_gclean, NULL);
					g_slist_free(list_services);
					list_services = NULL;
				}
			}
			g_slist_free_full (services_types, g_free);
		}
	}

success_label:
	rc = 0;
exit_label:
	if (ns)
		namespace_info_free(ns);
	if (error)
		g_clear_error(&error);
	return rc;
}
