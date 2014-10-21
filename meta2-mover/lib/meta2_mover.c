#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2-mover"
#endif

#include <stdio.h>

#include <grid_client.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <meta1v2/meta1_remote.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>
#include <sqliterepo/sqlx_remote.h>

#include "meta2_mover.h"
#include "meta2_mover_internals.h"
#include "meta2_mover.h"

/* Global variables */
time_t interval_update_services = 60L;
time_t to_step = 30;
time_t to_all = 60;

struct cid_move_s
{
	struct xaddr_s m1;

	struct xaddr_s src;
	struct meta1_service_url_s *src_url;

	struct xaddr_s dst;
	struct meta1_service_url_s *dst_url;

	gboolean v2;
};

static gboolean
_is_meta2v2(const gchar *ns_name, GSList *meta2, const char *url)
{
	struct service_info_s si;
	gchar **url_split = NULL;
	gboolean result = FALSE;

	int si_equal(gconstpointer si1, gconstpointer si2) {
		return service_info_equal_v2(si1, si2) ? 0 : 1;
	}

	memset(&si, '\0', sizeof(struct service_info_s));
	g_strlcpy(si.ns_name, ns_name, sizeof(si.ns_name));
	g_strlcpy(si.type, "meta2", sizeof(si.type));
	DEBUG("Checkin' if source is m2v2 [%s]", url);

	url_split = g_strsplit(url, ":", 2);
	if (url_split && g_strv_length(url_split) == 2 &&
			service_info_set_address(&si, url_split[0], atoi(url_split[1]), NULL)) {
		GSList *si_found = g_slist_find_custom(meta2, &si, si_equal);
		if  (si_found && si_found->data) {
			DEBUG("service found, checking tag");
			result = (0 == g_ascii_strcasecmp(
						service_info_get_tag_value(si_found->data, "tag.type", "m2v1"),
						"m2v2"));
		}
	}
	DEBUG("service is %s", result ? "m2v2" : "m2v1");
	g_strfreev(url_split);
	return result;
}

static void
_disable_container(struct xcid_s *scid, struct xaddr_s *addr)
{
        GError *err = NULL;
        int attempts, code;

        INFO("Disabling on %s", addr->str);

        for (attempts = 5 ; ; --attempts) {

                if (attempts <= 0) {
                        WARN("Source disabling: Too many attempts");
                        break;
                }

                if (meta2_remote_container_disable_disabled(&(addr->cnx), scid->cid, &err)) {
                        DEBUG("Disabled the source container, (%d attempts remaining) ...", attempts);
                        break;
                }

                code = gerror_get_code(err);
                if (code == CODE_CONTAINER_DISABLED) { /* already */
                        DEBUG("Disabled the source container, (%d attempts remaining) ...", attempts);
                        g_clear_error(&err);
                        break;
                }

                ERROR("Failed to disable the source container: (%d) %s", code, gerror_get_message(err));
                if (err)
                        g_clear_error(&err);
        }
}

static void
_enable_container(struct xcid_s *scid, struct xaddr_s *addr)
{
	GError *err = NULL;
	int attempts, code;
	const int max_attempts = 5;

	INFO("Enabling on %s", addr->str);

	for (attempts = max_attempts; ; --attempts) {

		if (attempts <= 0) {
			ERROR("Enabling error on %s: Too many attempts", addr->str);
			break;
		}
		if (meta2_remote_container_set_flag(&(addr->addr), 30000,
					&err, scid->cid, 0x00000000))
		{
			INFO("Enabling success on %s: now enabled", addr->str);
			return;
		}

		code = gerror_get_code(err);
		WARN("Enabling error on %s: (%d) %s", addr->str, code, gerror_get_message(err));
		if (err)
			g_clear_error(&err);
		if (code == CODE_NETWORK_ERROR) {
			// We've seen source meta2 restart after memory allocation
			// failure, when moving huge bases.
			INFO("Will wait %ds before retrying (meta2 restart?)",
					max_attempts - attempts + 2);
			sleep(max_attempts - attempts + 2);
		}
	}
}

static GError*
_step4_REENABLES(gs_grid_storage_t *ns_client,
                struct xcid_s *scid, struct cid_move_s *move)
{
        (void) ns_client;
        g_assert(scid != NULL);
        g_assert(move != NULL);

        _disable_container(scid, &(move->src));
        _enable_container(scid, &(move->dst));

        return NULL;
}

static GError*
_step3_CHANGE_REFS(gs_grid_storage_t *ns_client,
                struct xcid_s *scid, struct cid_move_s *move)
{
        gboolean rc;
        GError *err = NULL;

        g_assert(scid != NULL);
        g_assert(move != NULL);

        INFO("Unlink SRC [%"G_GINT64_FORMAT"|%s]",
                        move->src_url->seq, move->src_url->host);

        rc = meta1v2_remote_unlink_one_service(&(move->m1.addr), &err,
                        gs_get_namespace(ns_client), scid->cid, "meta2",
                        to_step, to_all, NULL, move->src_url->seq);

        if (!rc) {
                g_prefix_error(&err, "Unref error: ");
                return err;
        }

        /* next step, no ROLLBACK to the reference changing */
        return _step4_REENABLES(ns_client, scid, move);
}

static void
_cid_move_init(struct cid_move_s *move)
{
	memset(move, 0, sizeof(struct cid_move_s));
	metacnx_clear(&(move->src.cnx));
	metacnx_clear(&(move->dst.cnx));
}

static void
_cid_move_destroy(struct cid_move_s *move, gboolean content_only)
{
	if (!move)
		return;

	if (move->src_url) {
		g_free(move->src_url);
		move->src_url = NULL;
	}
	metacnx_clear(&(move->src.cnx));

	if (move->dst_url) {
		g_free(move->dst_url);
		move->dst_url = NULL;
	}
	metacnx_clear(&(move->dst.cnx));

	if (!content_only)
		g_free(move);
}

static GError*
meta2_mover_locate_destination(gs_grid_storage_t * ns_client,
		struct xcid_s *scid, struct cid_move_s *move,
		const gchar* meta2_addr, gboolean forcing_ip)
{
	GError *err = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	gboolean _poll(void)
	{
		gchar **ps, **result = NULL;
		gchar tmp[256];
		memset(tmp, '\0', 256);
		g_snprintf(tmp, 256, "meta2%s%s",
				(!meta2_addr && !move->v2) ? "" : ";",
				(!meta2_addr) ? ((move->v2)? "tag.type=m2v2" : "") :
				((move->v2) ? "tag.type=m2v2" : meta2_addr));
		DEBUG("Ask for service polling with params [%s]", tmp);
		result = meta1v2_remote_poll_reference_service(&(move->m1.addr),
				&err, gs_get_namespace(ns_client), scid->cid, tmp,
				to_step, to_all, NULL);
		if(!result || 0 == g_strv_length(result)) {
			if(!err)
				err = GS_ERROR_NEW(500,
						"Service [%s] polling failure, no error", tmp);
			return FALSE;
		}
		DEBUG("Polling the meta2 with specified tag \"%s\" selection "
				"succeeded with %u results",
				meta2_addr, g_strv_length(result));

		for (ps=result; *ps ;ps++) {
			DEBUG("Got DST meta2 [%s]", *ps);
		}

		move->dst_url = meta1_unpack_url(result[0]);
		g_strfreev(result);
		return (!err);
	}

	if (NULL != meta2_addr) {
		if (forcing_ip) {
			gchar tmp[256];
			memset(tmp, '\0', 256);
			g_snprintf(tmp, 256, "%"G_GINT64_FORMAT"|meta2|%s|",
					move->src_url->seq + 1, meta2_addr);
			move->dst_url = meta1_unpack_url(tmp);
			DEBUG("Forcing [%s]", tmp);
			if(!meta1v2_remote_force_reference_service(&(move->m1.addr),
						&err, gs_get_namespace(ns_client), scid->cid, tmp,
						to_step, to_all, NULL)) {
				return err;
			}
			DEBUG("Service [%s] successfully forced", tmp);
		} else {
			if(!_poll()) return err;
		}
	} else {
		if(!_poll()) return err;
	}

	if(NULL != (err = xaddr_init_from_url(&(move->dst), move->dst_url->host)))
		GS_ERROR_STACK(&err);

	return err;
}

static GError*
meta2_mover_locate_source(gs_grid_storage_t * ns_client,
	GSList *meta2, struct xcid_s *scid, struct cid_move_s *move)
{
	GError *err;
	gs_error_t *gserr = NULL;
	g_assert(scid != NULL);
	g_assert(move != NULL);

	DEBUG("Trying to locate CID[%s]", scid->str);

	/* Locate the source */
	scid->location = gs_locate_container_by_hexid(ns_client, scid->str, &gserr);
	if (!scid->location) {
		err = GS_ERROR_NEW(gs_error_get_code(gserr),
				"Grid ERROR : %s", gs_error_get_message(gserr));
		GS_ERROR_STACK(&err);
		gs_error_free(gserr);
		return err;
	}

	if (!scid->location->m2_url || !scid->location->m2_url[0]) {
		return GS_ERROR_NEW(CODE_CONTAINER_NOTFOUND, "No meta2 for this container");
	} else if (g_strv_length(scid->location->m2_url) > 1) {
		return GS_ERROR_NEW(CODE_NOT_IMPLEMENTED,
				"Replicated container, cannot move (not implemetented)");
	}

	err = xaddr_init_from_url(&(move->m1), scid->location->m1_url[0]);
	if (NULL != err) {
		GS_ERROR_STACK(&err);
		return err;
	}

	/* Init all the source-related structures */
	err = xaddr_init_from_url(&(move->src), scid->location->m2_url[0]);
	if (NULL != err) {
		GS_ERROR_STACK(&err);
		return err;
	}

	/* Get the old URL with the sequence number */
	do {
		gchar **ps, **result;
		result = meta1v2_remote_list_reference_services(&(move->m1.addr), &err,
				gs_get_namespace(ns_client), scid->cid, "meta2",
				
				to_step, to_all);
		if (!result) {
			if (!err)
				err = GS_ERROR_NEW(500, "No SRC meta2 located");
		}
		else {
			if (!result[0]) {
				err = GS_ERROR_NEW(500, "No SRC meta2 located");
			}
			else {
				for (ps=result; *ps ;ps++)
					DEBUG("Got SRC meta2 [%s]", *ps);
				move->src_url = meta1_unpack_url(result[0]);
				move->v2 = _is_meta2v2(gs_get_namespace(ns_client), meta2, move->src_url->host);
				if (err != NULL)
					GS_ERROR_STACK(&err);
			}
			g_strfreev(result);
		}
	} while (0);

	if (err)
		return err;

	return NULL;
}

/* Migration steps --------------------------------------------------------- */

/* Each step is responsible for:
 * - a single action before going to the next step
 * - the retry attempts of this action
 * - the rollback of the action in case of a next step's failure
 */

static GError*
_do_PIPEFROM(struct cid_move_s *move, struct xcid_s *scid)
{
	struct sqlx_name_s n;
	struct client_s *client;
	GError *err = NULL;

	n.ns = "";
	n.base = scid->str;
	n.type = "meta2";

	GByteArray *req = sqlx_pack_PIPEFROM(&n, move->src_url->host);

	EXTRA_ASSERT(req != NULL);

	client = gridd_client_create_idle(move->dst_url->host);
	if (!client)
		err = NEWERROR(2, "errno=%d %s", errno, strerror(errno));
	else {
		if ((to_step >= 0) && (to_all >= 0))
			gridd_client_set_timeout(client, to_step, to_all);

		if (!gridd_client_start(client))
			err = gridd_client_error(client);
		if (!err)
			err = gridd_client_request(client, req, NULL, NULL);
		if (!err) {
			if (!(err = gridd_client_loop(client))) {
				err = gridd_client_error(client);
			}
		}
		gridd_client_free(client);
	}

	g_byte_array_free(req, TRUE);

	return err;
}

static GError*
_step2_MIGRATE(gs_grid_storage_t *ns_client,
		struct xcid_s *scid, struct cid_move_s *move)
{
	int attempts, code;
	GError *err = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	for (attempts = 5 ; ; --attempts) {
		if (attempts <= 0) {
			err = GS_ERROR_NEW(500, "Too many attempts, migration not done");
			GS_ERROR_STACK(&err);

			/*no rollback*/
			return err;
		}

		if(move->v2) {
			DEBUG("Moving v2 container");
			if(!(err = _do_PIPEFROM(move, scid)))
				break;
		} else {
			DEBUG("Sending the dump/restore command...");
			if (meta2_remote_restorev1_container(&(move->dst.cnx), scid->cid,
						&(move->src.addr), scid->cid, &err))
				break;
		}


		ERROR("Failed to copy the container : %s", gerror_get_message(err));
		code = gerror_get_code(err);
		if (code < 100) { /* network error */
			g_clear_error(&err);
		} else {
			GS_ERROR_STACK(&err);

			/* ROLLBACK: remove the created container on the dest meta2 */
			GError* local_error = NULL;
			DEBUG("Rollback, Destroy created destination container on [%s]", move->dst.str);
			addr_info_t* m2addr =  addr_info_from_service_str(move->dst.str);
			if (m2addr) {
				meta2_remote_container_destroy (m2addr, 3000, &local_error, scid->cid);
				if (local_error) {
					ERROR("Failed to destroy created container during rollback [%s] on [%s]", 
							scid->str, move->dst.str);
					g_error_free(local_error);
				}
				addr_info_clean(m2addr);
			}

			return err;
		}
	}
	DEBUG("Container copied");


	/* next step, no ROLLBACK to the migration operation */
	return _step3_CHANGE_REFS(ns_client, scid, move);
}

static GError*
_step1_POLL_TARGET(gs_grid_storage_t *ns_client,
	struct xcid_s *scid, struct cid_move_s *move,
	const gchar *meta2_addr, gboolean forcing_ip)
{
	GError *err = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	/* Init the target side of the movement */
	err = meta2_mover_locate_destination(ns_client,
			scid, move, meta2_addr, forcing_ip);
	if (NULL != err) {
		GS_ERROR_STACK(&err);
		return err;
	}

	if (! g_ascii_strcasecmp(move->src.str, move->dst.str)) {
		err = NEWERROR(500, "SRC and DST meta2 are the same, skipping");
	}
	else {
		DEBUG("Ready to move ID[%s] M0[%s] M1[%s] M2[%s] -> M2[%s]",
				scid->str, scid->location->m0_url,
				move->m1.str, move->src.str, move->dst.str);

		/* next step, move */
		if (!(err = _step2_MIGRATE(ns_client, scid, move))) {
			DEBUG("container \"%s\" successfuly migrated to service \"%s\"",
					scid->str, move->dst.str);
			return NULL;
		}
	}

	/* ROLLBACK: remove the service polled */
	GError *rollback_error = NULL;
	INFO("Unlink DST [%"G_GINT64_FORMAT"|%s]",
			move->dst_url->seq, move->dst_url->host);
	(void) meta1v2_remote_unlink_one_service(&(move->m1.addr),
			&rollback_error, gs_get_namespace(ns_client), scid->cid, "meta2",
			to_step, to_all, NULL, move->dst_url->seq);
	if (!rollback_error) {
		INFO("Rolled back : %s", __FUNCTION__);
	}
	else {
		WARN("ROLLBACK(%s) failed : (%d) %s", __FUNCTION__,
				rollback_error->code, rollback_error->message);
		g_clear_error(&rollback_error);
	}

	return err;
}

static GError*
_step0_FREEZE_SOURCE(gs_grid_storage_t *ns_client, struct xcid_s *scid,
		struct cid_move_s *move, const gchar* meta2_addr, gboolean forcing_ip)
{
	int attempts, code;
	GError *err = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	/* Prepare, with retries */
	for (attempts = 5 ;  ; --attempts) {
		if (attempts <= 0) {
			err = GS_ERROR_NEW(500, "Too many attempts, source not frozen");
			GS_ERROR_STACK(&err);
			return err;
		}

		DEBUG("Freezing the source container (%d attempts remaining) ...",
				attempts);
		if (meta2_remote_container_freeze(&(move->src.cnx), scid->cid, &err)) {
			INFO("Source container frozen");
			break;
		}

		code = gerror_get_code(err);
		if (code < 100) { /* network error */
			g_clear_error(&err);
		}
		else if (code == CODE_CONTAINER_FROZEN) {
			g_clear_error(&err);
			break;
		}
		else {
			GS_ERROR_STACK(&err);
			return err;
		}
		g_assert(err == NULL);
	}

	/* next step */
	if (!(err = _step1_POLL_TARGET(ns_client, scid, move,
					meta2_addr, forcing_ip)))
		return NULL;

	/* ROLLBACK : enables the source */
	_enable_container(scid, &(move->src));
	return err;
}


/* -------------------------------------------n------------------------------ */

/*!
 * Locate the source META2 and the META1, poll a destination META2,
 * then advance to the next step
 */
GError*
meta2_mover_migrate(gs_grid_storage_t * ns_client, const gchar * xcid,
		const gchar *meta2_addr)
{
	struct cid_move_s move;
	struct xcid_s *scid = NULL;
	GError *err = NULL;
	GSList *meta2 = NULL;
	GSList *cursor = NULL;
	gboolean full_url = (NULL != meta2_addr
			&& g_str_has_prefix(meta2_addr,"url="));

	gboolean _iterate_meta2(struct service_info_s **dst)
	{
		if (!cursor || !dst) {
			cursor = meta2;
			return FALSE;
		}
		*dst = service_info_dup(cursor->data);
		cursor = cursor->next;
		return TRUE;
	}

	g_assert(xcid != NULL);
	_cid_move_init(&move);

	if (!(scid = xcid_from_hexa(xcid))) {
		err = GS_ERROR_NEW(0, "Bad format for container id [%.*s]", 64, xcid);
		_cid_move_destroy(&move, TRUE);
		return err;
	}

	cursor = meta2 = list_namespace_services(gs_get_namespace(ns_client),
				"meta2", &err);
	if(NULL != err || 0 == g_slist_length(meta2)) {
		_cid_move_destroy(&move, TRUE);
		xcid_free(scid);
		ERROR("Meta2 list loading failure");
		return err;
	}

	DEBUG("Found %u meta2 services for ns [%s]", g_slist_length(meta2),
			gs_get_namespace(ns_client));

	/* Locate the container */
	if (!(err = meta2_mover_locate_source(ns_client, meta2, scid, &move))) {
		/* ensure target is v2 if source is v2 */
		if(NULL != meta2_addr && move.v2 && full_url
				&& !_is_meta2v2(gs_get_namespace(ns_client), meta2, meta2_addr + 4)) {
			err = GS_ERROR_NEW(0, "Source meta2 is identified as v2, but target"
					" seems in v1, not able to migrate cid [%.*s]", 64, xcid);
		} else if (NULL != (err = _step0_FREEZE_SOURCE(ns_client,
						scid, &move,
						full_url? meta2_addr + 4 : meta2_addr, full_url))) {
			GS_ERROR_STACK(&err);
		}
	} else {
		GS_ERROR_STACK(&err);
	}

	g_slist_free_full(meta2, (GDestroyNotify)service_info_clean);
	xcid_free(scid);
	_cid_move_destroy(&move, TRUE);

	return err;
}

