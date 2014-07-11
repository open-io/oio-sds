#include "./gs_internals.h"
#include "./solr_utils.h"

extern gboolean
set_solr_service(gs_grid_storage_t *grid, const gchar *container_name, const gchar *new_solr_service)
{
	struct gs_container_location_s *loc = NULL;
	struct metacnx_ctx_s *ctx = NULL;
	container_id_t cid;
	gs_error_t *error = NULL;
	GError *gerror = NULL;
	GByteArray *new_value;
	GSList *list_of_services;
	service_info_t *si;
	score_t score = {50, time(NULL)};

	if (!container_name) {
		DEBUG("No container specified. Exiting.");
		return FALSE;
	}

	if (new_solr_service) {
		/* build new service info */
		si = (service_info_t*) malloc(sizeof(service_info_t));
		if (si == NULL) {
			g_printerr("Error allocating memory for service_info creation\n");
			return FALSE;
		}
		strcpy(si->ns_name, gs_get_namespace(grid));
		strcpy(si->type, "solr");
		if (!l4_address_init_with_url(&si->addr, new_solr_service, &gerror)) {
			g_printerr("Error creating addr_info from field [%s]. Error: [%s]\n",
					new_solr_service, gerror != NULL ? gerror->message : "unknown error");
			g_error_free(gerror);
			free(si);
			return FALSE;
		}
		si->score = score;
		si->tags = NULL;

		list_of_services = g_slist_prepend(NULL, si);
		new_value = service_info_marshall_gba(list_of_services, &gerror);
		free(si);
		si = NULL;
	} else {
		DEBUG("No service specified -> deleting existing service.");
		new_value = (GByteArray*) malloc(sizeof(GByteArray));
		new_value->data = (void*) "";
		new_value->len = 1;
	}

	DEBUG("Setting solr service to [%s] for container [%s].", new_solr_service ? new_solr_service : "", container_name);

	/* Locate container */
	loc = gs_locate_container_by_name(grid, container_name, &error);
	if (loc == NULL || loc->m2_url == NULL) {
		g_printerr("Failed to locate container [%s] in namespace: %s\n", container_name, gs_error_get_message(error));
		gs_error_free(error);
		goto error;
	}

	/* Create connexion to meta2 */
	ctx = metacnx_create(&gerror);
	if (ctx == NULL) {
		g_print("Failed to create metacnx_ctx : %s\n", gerror->message);
		g_clear_error(&gerror);
		goto error;
	}
	ctx->flags = METACNX_FLAGMASK_KEEPALIVE;
	ctx->timeout.cnx = 30000;
	ctx->timeout.req = 30000;
	if (!metacnx_init_with_url(ctx, loc->m2_url[0], &gerror)) {
		g_print("Failed to init ctx with url [%s] : %s\n", loc->m2_url[0], gerror->message);
		g_clear_error(&gerror);
		goto error;
	}
	if (!metacnx_open(ctx, &gerror)) {
		g_print("Failed to open ctx : %s\n", gerror->message);
		g_clear_error(&gerror);
		goto error;
	}

	/* set solr in container */
	meta1_name2hash(cid, gs_get_full_vns(grid), container_name);

	if (!meta2raw_remote_set_admin_entry(ctx, &gerror, cid, "service_solr", new_value->data, new_value->len)) {
		g_print("Failed to set solr service to new service [%s]: %s\n", new_solr_service ? new_solr_service : "", gerror->message);
		g_clear_error(&gerror);
		goto error;
	}

	metacnx_close(ctx);
	metacnx_destroy(ctx);

	gs_container_location_free(loc);

	return TRUE;

error:
	if (loc != NULL)
		gs_container_location_free(loc);
	if (ctx != NULL) {
		metacnx_close(ctx);
		metacnx_destroy(ctx);
	}
	if (new_value) {
		if (new_solr_service) {
			g_byte_array_free(new_value, TRUE);
		} else {
			free(new_value);
		}
		new_value = NULL;
	}

	return FALSE;
}

