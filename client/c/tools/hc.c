#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "../lib/gs_internals.h"
#include "../lib/hc.h"
#include "./gs_tools.h"

#ifndef FREEP
# define FREEP(F,P) do { if (!(P)) return; F(P); (P) = NULL; } while (0)
#endif

/* Globals */
int optind, opterr, optopt;
struct hc_url_s *url = NULL;
static gchar *action = NULL;
static gchar **action_args = NULL;
static int action_result = 0;

/* Options */
static gboolean flag_xml = FALSE;
static gboolean flag_info = FALSE;
static gboolean flag_hardrestore = FALSE;
#define VERSIONING_NS_DEFAULT_VALUE -2
static gint64 versioning = VERSIONING_NS_DEFAULT_VALUE;
static GString * sys_metadata = NULL;
static GString * stgpol = NULL;
static GString * copy_source = NULL;
int flag_verbose = 0;
int flag_help = 0;
int flag_quiet = 0;
int flag_force =0;
int flag_flush = 0;
int flag_autocreate = 0;
static int flag_cache = 0;

typedef gboolean (*action_func)(const gs_grid_storage_t *hc);
typedef void (*help_func)(void);

/* ------------------- Internals functions ------------------- */

static void
__display_friendly_error(gs_error_t *error) {

	/* debug info */
	if(!error || !error->msg) {
		g_printerr("Action 'hc %s' failed, but no error specified.", action);
		return;
	}

	GRID_DEBUG("Technical error (code %d) message:", error->code);
	GRID_DEBUG(error->msg);

	g_printerr("\nERROR: ");

	switch(error->code) {
		case 0:
			g_printerr("%s\n", error->msg);
			break;
		case CODE_BAD_REQUEST:
			g_printerr("The server doesn't recognize the request. Be sure to use a compatible client\n");
			break;
		case CODE_NOT_ALLOWED:
			g_printerr("Operation not allowed\n");
			break;
		case CODE_CONTENT_NOTFOUND:
			g_printerr("Content [%s] not found in container [%s]\n",
					copy_source != NULL? copy_source->str : hc_url_get(url, HCURL_PATH),
					hc_url_get(url, HCURL_REFERENCE));
			break;
		case CODE_CONTENT_EXISTS:
			g_printerr("Content [%s] already exists in container [%s]\n",
					hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_REFERENCE));
			break;
		case CODE_CONTAINER_NOTFOUND:
		case CODE_CONTAINER_CLOSED:
			g_printerr("Container [%s] not found in namespace [%s].\n",
					hc_url_get(url, HCURL_REFERENCE), hc_url_get(url, HCURL_NS));
			break;
		case CODE_CONTAINER_EXISTS:
			g_printerr("Container [%s] already exists in namespace [%s].\n",
					hc_url_get(url, HCURL_REFERENCE), hc_url_get(url, HCURL_NS));
			break;
		case CODE_CONTAINER_NOTEMPTY:
			g_printerr("Container [%s] not empty [%s].\n", hc_url_get(url, HCURL_REFERENCE),
					hc_url_get(url, HCURL_NS));
			break;
		case CODE_CONTAINER_FULL:
			g_printerr("Quota of container [%s] has been reached.\n",
					hc_url_get(url, HCURL_WHOLE));
			break;
		case CODE_NAMESPACE_FULL:
			if (hc_url_has(url, HCURL_NSVIRT)) {
				g_printerr("Quota of namespace [%s%s] has been reached.\n",
						hc_url_get(url, HCURL_NSPHYS), hc_url_get(url, HCURL_NSVIRT));
			} else {
				g_printerr("Quota of namespace [%s] has been reached.\n",
						hc_url_get(url, HCURL_NSPHYS));
			}
			break;
		case CODE_CONTAINER_PROP_NOTFOUND:
			g_printerr("This kind of service is not managed by your Honeycomb namespace.\n");
			break;
		case CODE_CONTENT_PROP_NOTFOUND:
			g_printerr("No more service of this type available. Please ensure your services are correctly started.\n");
			break;
		case CODE_POLICY_NOT_SUPPORTED:
			g_printerr("This storage policy is not managed by namespace %s.\n",
					hc_url_get(url, HCURL_NSPHYS));
			break;
		case CODE_POLICY_NOT_SATISFIABLE:
			g_printerr("The storage policy could not be satisfied by namespace. %s\n",
					hc_url_get(url, HCURL_NSPHYS));
			break;
		case CODE_SNAPSHOT_NOTFOUND:
			g_printerr("Snapshot '%s' not found\n",
					hc_url_get(url, HCURL_SNAPORVERS));
			break;
		case CODE_SNAPSHOT_EXISTS:
			g_printerr("Snapshot '%s' already exists\n",
					hc_url_get(url, HCURL_SNAPORVERS));
			break;
		case 500:
		default:
			if(!flag_verbose) {
				g_printerr("Unexpected server error, please run action with -v option for more informations.\n");
			}
			return;
	}

	g_printerr("\n");

	if(!flag_verbose) {
		g_printerr("(Run action with -v option for technical details.)\n");
	}
}

static void
__dump_props(gchar **s)
{
	guint i;
	if (!s)
		return;
	if (!flag_xml) {
		for (i = 0; i < g_strv_length(s); i++) {
			if (s[i])
				g_print("   [%s]\n", s[i]);
		}
	} else {
		g_print("XML output not yet implemented for properties\n");
		for (i = 0; i < g_strv_length(s); i++) {
			if (s[i])
				g_print("   [%s]\n", s[i]);
		}
	}
}

static void
__dump_services(gchar **s)
{
	guint i;
	if (!s)
		return;
	if (!flag_xml) {
		for (i = 0; i < g_strv_length(s); i++) {
			if (s[i])
				g_print("   [%s]\n", s[i]);
		}
	}
	else {
		g_print("<services>\n");
		for (i = 0; i < g_strv_length(s); i++) {
			if (NULL == s[i])
				continue;
			struct meta1_service_url_s *m1url;
			if (!(m1url = meta1_unpack_url(s[i])))
				g_print("<!-- Invalid %s -->\n", s[i]);
			else {
				g_print(" <service>\n");
				g_print("  <seq>%"G_GINT64_FORMAT"</seq>\n", m1url->seq);
				g_print("  <type>%s</type>\n", m1url->srvtype);
				g_print("  <host>%s</host>\n", m1url->host);
				g_print("  <args>%s</args>\n", m1url->args);
				g_print(" </service>\n");
				g_free(m1url);
			}
		}
		g_print("</services>\n");
	}
}


/* ---------------------------- Actions ----------------------------- */

static gboolean
func_put(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if(hc_url_has(url, HCURL_PATH)) {
		if (NULL != copy_source) {
			/* copy content */
			e = hc_func_copy_content(hc, url, copy_source->str);
		} else {
			/* Content upload */
			if(g_strv_length(action_args) < 1) {
				g_printerr("Missing argument\n");
				help_put();
				return FALSE;
			}

			e = hc_put_content(hc, url,
					action_args[0],
					(stgpol) ? stgpol->str : NULL,
					(sys_metadata-> len > 0) ? sys_metadata->str : NULL,
					flag_autocreate);

		}
	} else {
		/* container creation */
		static gchar s[128];
		memset(s, 0, sizeof(s));
		if (VERSIONING_NS_DEFAULT_VALUE < versioning)
			g_snprintf(s, sizeof(s), "%"G_GINT64_FORMAT, versioning);
		e = hc_create_container(hc, url,
				(NULL != stgpol) ? stgpol->str : NULL,
				(VERSIONING_NS_DEFAULT_VALUE < versioning) ? s : NULL);
	}

	if (NULL != e) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	return TRUE;
}

static gboolean
func_append(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if(hc_url_has(url, HCURL_PATH)) {
		/* Content upload */
		if(g_strv_length(action_args) < 1) {
			g_printerr("Missing argument\n");
			help_append();
			return FALSE;
		}
		gchar *lp = action_args[0];

		e = hc_append_content(hc, url, lp);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}
	} else {
		g_printerr("Content path is needed\n");
		help_append();
		return FALSE;
	}
	return TRUE;
}

static gboolean
func_get(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if(hc_url_has(url, HCURL_PATH)) {
		/* download a content */
		gchar *local_path = action_args[0];

		e = hc_get_content(hc, url, local_path, flag_force, flag_cache, (stgpol) ? stgpol->str : NULL);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}
	} else {
		/* list a container */
		gchar *result = NULL;
		e = hc_list_contents(hc, url, flag_xml, flag_info, &result);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}

		g_print("%s", result);
		g_free(result);
	}

	return TRUE;
}

static gboolean
func_delete(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if(hc_url_has(url, HCURL_PATH)) {
		/* content delete */
		e = hc_delete_content(hc, url);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}
		GRID_INFO("Content [%s] deleted from namespace.\n",
				hc_url_get(url, HCURL_WHOLE));
	} else {
		e = hc_delete_container(hc, url, flag_force, flag_flush);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}
		GRID_INFO("Container [%s] deleted from namespace [%s].\n",
				hc_url_get(url, HCURL_REFERENCE), hc_url_get(url, HCURL_NS));
	}

	return TRUE;
}

static gboolean
func_stgpol(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gchar *sp = NULL;

	if(g_strv_length(action_args) >= 1) {
		sp = action_args[0];
	}

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);
	if (NULL != c) {
		if (sp == NULL) {
			//////////////////////////////////////////////
			//display de storage policy of container

			struct loc_context_s *lc = NULL;
			char* value;
			gboolean status = FALSE;

			lc = loc_context_init_retry(hc, url, NULL);
			if (lc) {
				value = loc_context_getstgpol_to_string(lc, hc_url_has(url, HCURL_PATH));
				if (value != NULL) {
					g_print("%s\n", value);
					status = TRUE;
				} else {
					g_printerr("Unknown \"%s\" property", GS_CONTAINER_PROPERTY_STORAGE_POLICY);
				}
			} else {
				g_printerr("Cannot load container data ");
			}

			return status;
		}

		//////////////////////////////////////////////
		// save new storage policy
		if(hc_url_has(url, HCURL_PATH)) {
			/* policy to a content */
			if((!hc_set_content_storage_policy(c, hc_url_get(url, HCURL_PATH), sp, &e))) {
				__display_friendly_error(e);
			} else {
				GRID_DEBUG("Storage policy %s set to content %s/%s\n" , sp, hc_url_get(url, HCURL_REFERENCE),
						hc_url_get(url, HCURL_PATH));
			}
		} else {
			/* policy to a container */
			if((e = hc_set_container_storage_policy(c, sp))) {
				__display_friendly_error(e);
			} else {
				GRID_DEBUG("Storage policy %s set to container %s\n" , sp, hc_url_get(url, HCURL_REFERENCE));
			}
		}
		gs_container_free(c);
		if(NULL != e) {
			gs_error_free(e);
			return FALSE;
		}
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);

	return FALSE;
}

static gboolean
func_info(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	char *r = NULL;

	e = hc_object_info(hc, url, flag_xml, &r);
	if (NULL != e) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	// r may container '%' character, so cannot be used as format
	g_print("%s", r);

	g_free(r);

	return TRUE;
}

static gboolean
func_srvlist(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	char **services = NULL;

	e = hc_list_reference_services(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0], &services);
	if (NULL != e) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	if (!services) {
		gchar *tab[] = {NULL};

		if (action_args[0])
			g_printerr("No service [%s] linked to container [%s].\n", action_args[0], hc_url_get(url, HCURL_REFERENCE));
		else
			g_printerr("No service linked to container [%s].\n", hc_url_get(url, HCURL_REFERENCE));
		__dump_services(tab);
	}
	else {
		if (action_args[0])
			g_printerr("Container [%s], services [%s] linked:\n", hc_url_get(url, HCURL_REFERENCE), action_args[0]);
		else
			g_printerr("Container [%s], all services linked:\n", hc_url_get(url, HCURL_REFERENCE));

		__dump_services(services);
	}

	g_strfreev(services);
	return TRUE;
}

static gboolean
func_srvlink(gs_grid_storage_t *hc)
{
	gs_error_t *e;
	char **urlv = NULL;

	if (g_strv_length(action_args) != 1) {
		help_srvlink();
		return FALSE;
	}

	e = hc_link_service_to_reference(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0], &urlv);
	if (NULL != e) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	g_printerr("Service [%s] linked to reference [%s]\n", urlv[0], hc_url_get(url, HCURL_REFERENCE));

	g_strfreev(urlv);
	return TRUE;
}

static gboolean
func_srvunlink(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;

	if (g_strv_length(action_args) != 1) {
		help_srvunlink();
		return FALSE;
	}

	if (!(e = hc_unlink_reference_service(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0]))) {
		GRID_DEBUG("Services [%s] unlinked from reference [%s]\n", action_args[0], hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}	

	__display_friendly_error(e);
	gs_error_free(e);
	return FALSE;
}

static gboolean
func_srvpoll(gs_grid_storage_t *hc)
{
	char *u = NULL;
	gs_error_t *e;

	if (g_strv_length(action_args) != 1) {
		help_srvpoll();
		return FALSE;
	}

	if (!(e = hc_poll_service(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0], &u))) {
		char *urlv[2] = {NULL,NULL};
		urlv[0] = u;
		__dump_services(urlv);
		free(u);
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);
	return FALSE;
}

static gboolean
func_srvforce(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) != 1) {
		help_srvforce();
		return FALSE;
	}

	if (NULL != (e = hc_force_service(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0]))) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	GRID_DEBUG("Service [%s] forced for reference [%s]\n", action_args[0], hc_url_get(url, HCURL_REFERENCE));
	return TRUE;
}

static gboolean
func_srvconfig(gs_grid_storage_t *hc)
{
	gs_error_t *e;

	if (g_strv_length(action_args) != 2) {
		help_srvconfig();
		return FALSE;
	}

	if (!(e = hc_configure_service(hc, hc_url_get(url, HCURL_REFERENCE), action_args[0]))) {
		GRID_DEBUG("Service [%s] reconfigured for reference [%s]\n",
				action_args[0], hc_url_get(url, HCURL_REFERENCE));
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);
	return FALSE;
}

static gboolean
func_propset(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gboolean container = !hc_url_has(url, HCURL_PATH);

	if(g_strv_length(action_args) < 2) {
		g_printerr("Missing argument\n");
		help_propset();
		return FALSE;
	}


	if (! (e = hc_func_set_property(hc, url, (char **)action_args))) {
		g_print("Properties have been set to %s %s\n",
				container? "container" : "content", hc_url_get(url, HCURL_WHOLE));
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);
	return FALSE;

}

static gboolean
func_propget(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gboolean status = FALSE;
	gchar **result = NULL;

	e = hc_func_get_content_properties(hc, url,&result);
	if ( e != NULL ) {
		goto end_propget;
	}

	g_print("Listing container properties:\n");
	__dump_props(result);
	g_print("%d properties found matching search criteria\n", g_strv_length(result));

	status = TRUE;

end_propget:

	if(result) {
		g_strfreev(result);
	}


	return status;
}

static gboolean
func_propdel(gs_grid_storage_t *hc)
{
	gs_error_t *local_error = NULL;
	gboolean status = FALSE;

	if(g_strv_length(action_args) < 1) {
		g_printerr("Missing argument\n");
		help_propdel();
		return FALSE;
	}

	local_error = hc_func_delete_property(hc, url, action_args);
	if (NULL != local_error) {
		__display_friendly_error(local_error);
		goto end_propdel;
	}
	g_print("Properties removed\n");

	status = TRUE;

end_propdel:

	if(local_error) {
		gs_error_free(local_error);
	}

	return status;
}

static gboolean
func_quota(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;

	if(g_strv_length(action_args) < 1) {
		g_printerr("Missing argument\n");
		help_quota();
		return FALSE;
	}

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);

	if(NULL != c) {
		e = hc_set_container_quota(c, action_args[0]);
		gs_container_free(c);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}

		g_print("Quota applied to [%s]\n", hc_url_get(url, HCURL_WHOLE));
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);

	return FALSE;
}

static gboolean
func_version(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gint64 i64_versionning;
	gchar *endptr;

	if(g_strv_length(action_args) < 1) {
		g_printerr("Missing argument\n");
		help_version();
		return FALSE;
	}

	i64_versionning = g_ascii_strtoll(action_args[0], &endptr, 10);
	if('\0' != *endptr) {
		g_printerr("Version must be an integer\n");
		help_version();
		return FALSE;
	}

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);

	if(NULL != c) {
		if (VERSIONING_NS_DEFAULT_VALUE >= i64_versionning) {
			e = hc_del_container_versioning(c);
		}
		else {
			e = hc_set_container_versioning(c, action_args[0]);
		}
		gs_container_free(c);
		if(NULL != e) {
			__display_friendly_error(e);
			gs_error_free(e);
			return FALSE;
		}

		g_print("Versioning applied to [%s]\n", hc_url_get(url, HCURL_WHOLE));
		return TRUE;
	}

	__display_friendly_error(e);
	gs_error_free(e);

	return FALSE;
}

static gboolean
func_snaplist(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	gchar *result = NULL;
	e = hc_func_list_snapshots(hc, url, flag_xml, flag_info, &result);
	if (e != NULL) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	}

	g_print("%s", result);
	g_free(result);
	return TRUE;
}

static gboolean
func_snaptake(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	e = hc_func_take_snapshot(hc, url);
	if (e != NULL) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	} else if (!flag_quiet) {
		g_print("Snapshot taken\n");
	}
	return TRUE;
}

static gboolean
func_snapdel(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	e = hc_func_delete_snapshot(hc, url);
	if (e != NULL) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	} else if (!flag_quiet) {
		g_print("Snapshot deleted\n");
	}
	return TRUE;
}

static gboolean
func_snaprestore(gs_grid_storage_t *hc)
{
	gs_error_t *e = NULL;
	e = hc_func_restore_snapshot(hc, url, flag_hardrestore);
	if (e != NULL) {
		__display_friendly_error(e);
		gs_error_free(e);
		return FALSE;
	} else if (!flag_quiet) {
		g_print("Snapshot restored\n");
	}
	return TRUE;
}

/* ---------------------------------------- */

struct action_s {
	const gchar *name;
	gboolean (*job) (gs_grid_storage_t *hc);
};

struct help_s {
	const gchar *name;
	void (*help) (void);
};

static struct action_s actions[] = {
	{"put",       func_put},
	{"get",       func_get},
	{"delete",    func_delete},
	{"append",    func_append},
	{"info",      func_info},
	{"stgpol",    func_stgpol},
	{"srvlink",   func_srvlink},
	{"srvlist",   func_srvlist},
	{"srvunlink", func_srvunlink},
	{"srvpoll",   func_srvpoll},
	{"srvforce",  func_srvforce},
	{"srvconfig", func_srvconfig},
	{"propset",   func_propset},
	{"propget",   func_propget},
	{"propdel",   func_propdel},
	{"quota",     func_quota},
	{"version",   func_version},
	{"snaplist",  func_snaplist},
	{"snaptake",  func_snaptake},
	{"snapdel",   func_snapdel},
	{"snaprestore", func_snaprestore},
	{NULL,        NULL},
};

static struct help_s helps[] = {
	{"put",       help_put},
	{"get",       help_get},
	{"delete",    help_delete},
	{"append",    help_append},
	{"info",      help_info},
	{"stgpol",    help_stgpol},
	{"srvlist",   help_srvlist},
	{"srvlink",   help_srvlink},
	{"srvunlink", help_srvunlink},
	{"srvpoll",   help_srvpoll},
	{"srvforce",  help_srvforce},
	{"srvconfig", help_srvconfig},
	{"propset",   help_propset},
	{"propget",   help_propget},
	{"propdel",   help_propdel},
	{"quota",     help_quota},
	{"version",   help_version},
	{"snaplist",  help_snaplist},
	{"snaptake",  help_snaptake},
	{"snapdel",   help_snapdel},
	{"snaprestore", help_snaprestore},
	{NULL,        NULL},
};

static gboolean
_call_action(gs_grid_storage_t *hc)
{
	struct action_s *paction;
        gboolean result = TRUE;

	for (paction=actions; paction->name ;paction++) {
		if (0 != g_ascii_strcasecmp(paction->name, action))
			continue;
		if (!paction->job(hc)) {
			GRID_DEBUG("Action error");
			result = FALSE;
		}
		grid_main_stop();
		return result;
	}

	g_printerr("Unknown action [%s]\n", action);
	return FALSE;
}

static gboolean
_call_help(const gchar *a)
{
	struct help_s *phelp;

	for (phelp=helps; phelp->name ;phelp++) {
		if (!g_ascii_strcasecmp(phelp->name, a)) {
			phelp->help();
			return TRUE;
		}
	}

	g_printerr("Help section not found for [%s]\n", a);
	return FALSE;
}

static void
hc_action(void)
{
	if(url) {
		gs_error_t *hc_error = NULL;
		gs_grid_storage_t *hc;

		hc = gs_grid_storage_init(hc_url_get(url, HCURL_NS), &hc_error);

		if (!hc) {
			g_printerr("Failed to load namespace [%s]: %s\n"
					"Please ensure /etc/gridstorage.conf.d/%s file exists.\n"
					"If not, please contact your Honeycomb namespace administrator.\n",
					hc_url_get(url, HCURL_NS), hc_error->msg, hc_url_get(url, HCURL_NS));
			action_result = -1;
			return;
		}

		if (!_call_action(hc))
			 action_result = -1;

		gs_grid_storage_free(hc);
        }
}

static struct grid_main_option_s *
hc_get_options(void)
{
static struct grid_main_option_s hcdir_options[] = {
		{ "OutputXML", OT_BOOL, {.b = &flag_xml},
			"Write XML instead of the default key=value output"},
		{ "Cache", OT_BOOL, {.b = &flag_cache},
			"Download content from metaCD (Only used with GET action)"},
		{ "Force", OT_BOOL, {.b = &flag_force},
			"Force the action to success"},
        { "Flush", OT_BOOL, {.b = &flag_flush},
            "Flush the action to success"},	
		{ "Autocreate", OT_BOOL, {.b = &flag_autocreate},
			"Ask for container autocreation while uploading a content (Only used with PUT action)"},
		{ "StoragePolicy", OT_STRING, {.str = &stgpol},
			"Specificy the storage policy while creating a container or uploading a content (Only used with PUT action)"},
		{ "ShowInfo", OT_BOOL, {.b = &flag_info},
			"Show informations about each content (Only used with GET action on a container)"},
		{ "ActivateVersioning", OT_INT64, {.i64 = &versioning},
			"Activate content versioning (for PUT action):\n\t\t  N<-1 -> namespace default value, N=-1 -> unlimited, N=0 -> disabled, N>0 -> maximum N versions"},
		{ "CopySource", OT_STRING, {.str = &copy_source},
			"Specify the source of a content copy operation (URL or just path).\n"
			"This option is only available on PUT operation on content, "
			"and if present, convert the upload operation to a copy operation.\n"
			"Copy doesn't need any input data and doesn't duplicate any data, "
			"It just creates a new content entry using in place data of another content."},
		{ "HardRestore", OT_BOOL, {.b = &flag_hardrestore},
			"Erase contents and snapshots more recent than the snapshot being restored"},
		{ NULL, 0, {.i=0}, NULL}
	};

	return hcdir_options;
}

static void
hc_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	url = NULL;
	action = NULL;
	action_args = NULL;
}

static void
hc_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	FREEP(g_free, action);
	FREEP(g_strfreev, action_args);
	if (NULL != url) {
		hc_url_clean(url);
		url = NULL;
	}
	if (NULL != sys_metadata)
		g_string_free(sys_metadata, TRUE);
	if (NULL != stgpol)
		g_string_free(stgpol, TRUE);
}

static void
hc_specific_stop(void)
{
	/* no op */
}


static const gchar *
hc_usage(void)
{
	return "<command> [<args>]\n\n"
		"The available hc commands are:\n"
		"\tput\t\tCreate a container or upload a content\n"
		"\tget\t\tList a container or download a content\n"
		"\tdelete\t\tDestroy a container or delete a content\n"
		"\tappend\t\tAppend data to a content\n"
		"\tinfo\t\tShow informations about a container or a content\n"
		"\n"
		"\tquota\t\tManage the quota of a container\n"
		"\tstgpol\t\tManage the storage policy of a container or a content\n"
		"\tversion\t\tManage the versioning policy of a container\n"
		"\n"
		"\tsrvlink\t\tAssociate a reference to a specified service type\n"
		"\tsrvlist\t\tList services associated to a reference\n"
		"\tsrvunlink\tDissociate a service from a reference\n"
		"\tsrvpoll\t\tLike 'link' but tells the directory to force the election of a new service even if a service is still available\n"
		"\tsrvforce\t\tLinks to the reference a service explicitely described, beyong all load-balancing mechanics\n"
		"\tsrvconfig\tChanges the argument of a service linked to a reference.\n"
		"\n"
		"\tpropget\t\tGet the/some properties associated to a given content\n"
		"\tpropset\t\tAssociates a property to a content\n"
		"\tpropdel\t\tDissociates (deletes) a property for a given content\n"
		"\n"
		"\tsnaptake\tTake a snapshot of a container\n"
		"\tsnapdel\t\tDelete a snapshot\n"
		"\tsnaprestore\tRestore a snapshot or a content from a snapshot\n"
		"\tsnaplist\tList snapshots of a container\n"
		"\n"
		"See 'hc help <command>' for more information on a specific command.\n\n";
}

static gboolean
hc_configure(int argc, char **argv)
{
	GRID_DEBUG("Configuration");

	if (argc < 1) {
		g_printerr("Invalid arguments number\n");
		return FALSE;
	}

	action = g_strdup(argv[0]);

	if (!g_ascii_strcasecmp(action, "help")) {
		grid_main_stop();
		if (argc >= 2) {
			/* TODO: Man page */
			return _call_help(argv[1]);
		}
		g_print("usage: %s %s", g_get_prgname(), hc_usage());
		return TRUE;
	}

	if (argc == 1) {
		/* no args with input cmd (if != "help") ==> errors */
		_call_help(argv[0]);
		return FALSE;
	}

	if (!(url = hc_url_init(argv[1]))) {
		g_printerr("Invalid URL : %s\n", argv[1]);
		return FALSE;
	}

	// if no content is given, but we have a local_path, set content to basename(local_path)
	if (!hc_url_has(url, HCURL_PATH) && argv[2] && 0 == g_ascii_strcasecmp(action, "put")) {
		hc_url_set(url, HCURL_PATH, g_path_get_basename(argv[2]));
	}

	/* prepare sys_metadata */
	sys_metadata = g_string_new("");

	action_args = g_strdupv(argv+2);
	return TRUE;
}

static struct grid_main_callbacks hcdir_callbacks =
{
	.options = hc_get_options,
	.action = hc_action,
	.set_defaults = hc_set_defaults,
	.specific_fini = hc_specific_fini,
	.configure = hc_configure,
	.usage = hc_usage,
	.specific_stop = hc_specific_stop,
};

int
main(int argc, char **args)
{
	int result = 0;

	g_setenv("GS_DEBUG_GLIB2", "1", TRUE);
	action_result = 0;

	result = grid_main_cli(argc, args, &hcdir_callbacks);
	if (result != 0)
		action_result = result;

	return action_result;
}
