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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2-mover"
#endif

#include <meta1_remote.h>
#include <meta2_remote.h>
#include <meta2_services_remote.h>
#include <grid_client.h>
#include "./meta2_mover.h"
#include "./meta2_mover_internals.h"
#include "./meta2_mover.h"

#include <stdio.h>

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
};

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

        INFO("Enabling on %s", addr->str);

        for (attempts = 5 ; ; --attempts) {

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

static gchar*
g_substr(const gchar* string, guint32 start_pos, guint32 end_pos) {
	gsize len;
	gchar* output = NULL;

	if (start_pos >= strlen(string))
		return NULL;

	if (end_pos > strlen(string))
		len = strlen(string) - start_pos;
	else
		len = end_pos - start_pos;

	output = g_malloc0(len + 1);
	if (NULL == output)
		return NULL;

	return g_utf8_strncpy(output, &string[start_pos], len);
}

static GError*
meta2_mover_locate_destination(gs_grid_storage_t * ns_client,
		struct xcid_s *scid, struct cid_move_s *move, const gchar* meta2_addr, gboolean forcing_ip)
{
	gchar **ps, **result = NULL;
	GError *err = NULL;
	gboolean result2 = FALSE;
	gchar* meta2_addr2 = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	if (NULL != meta2_addr) {
		if (forcing_ip == TRUE) {
			if (!meta1v2_remote_unlink_one_service(&(move->m1.addr), &err, gs_get_namespace(ns_client), scid->cid, "meta2", to_step, to_all, NULL, move->src_url->seq)) {
				err = GS_ERROR_NEW(500, "Unref error");
                                return err;
			}
			
			meta2_addr2 = g_strconcat("2|meta2|", meta2_addr, "|", NULL);
			DEBUG("Forcing a META2 Using namespace [%s] on meta2 [%s]", gs_get_namespace(ns_client), meta2_addr2);
			result2 = meta1v2_remote_force_reference_service(&(move->m1.addr), &err,
					gs_get_namespace(ns_client), scid->cid, meta2_addr2,
					to_step, to_all, NULL);

			if (FALSE == result2) {
				DEBUG("Failed to move : No meta2 found for the specified URL \"%s\"", meta2_addr);
				printf("Failed to move : No meta2 found for the specified URL \"%s\"\n", meta2_addr);
				err = GS_ERROR_NEW(500, "No meta2 found for the specified URL");
                                return err;
			}
			else {
				DEBUG("Forcing the selection on the meta2 with URL \"%s\" succeeded", meta2_addr);
			}
		}
		else {
			meta2_addr2 = g_strconcat("meta2;", meta2_addr, NULL);
			DEBUG("POLL'ing a META2 Using namespace [%s] on meta2 [%s]", gs_get_namespace(ns_client), meta2_addr2);
			result = meta1v2_remote_poll_reference_service(&(move->m1.addr), &err,
					gs_get_namespace(ns_client), scid->cid, meta2_addr2,
					to_step, to_all, NULL);
			if (NULL == meta2_addr2) {
                                g_free(meta2_addr2);
                        }

			guint poll_srv_count = g_strv_length(result);
			if (0 == poll_srv_count) {
				DEBUG("Failed to move : No, or not enough, meta2 found for the specified tag \"%s\"", meta2_addr);
				printf("Failed to move : No, or not enough, meta2 found for the specified tag \"%s\"\n", meta2_addr);
				err = GS_ERROR_NEW(500, "No, or not enough,  meta2 found for the specified tag");
				return err;
			}
			else {
				DEBUG("Polling the meta2 with specified tag \"%s\" selection succeeded with %u results", meta2_addr, poll_srv_count);
			}
		}
	}
	else {
		DEBUG("POLL'ing a META2 Using namespace [%s]", gs_get_namespace(ns_client));
		result = meta1v2_remote_poll_reference_service(&(move->m1.addr), &err,
				gs_get_namespace(ns_client), scid->cid, "meta2",
				to_step, to_all, NULL);

		guint poll_srv_count = g_strv_length(result);
		if (0 == poll_srv_count) {
			DEBUG("Failed to move : No, or not enough, meta2 found");
			printf("Failed to move : No, or not enough, meta2 found\n");
			err = GS_ERROR_NEW(500, "No, or not enough, meta2 found");
                        return err;
		}
		else {
			DEBUG("Polling the meta2 selection succeeded with %u results", poll_srv_count);
		}
	}

	if (forcing_ip == TRUE) {
		if (result2 == FALSE) {
			if (!err) {
				err = GS_ERROR_NEW(500, "No DST meta2 available");
			}
		}
		else {
			DEBUG("Got forced DST meta2 [%s]", meta2_addr2);

			move->dst_url = meta1_unpack_url(meta2_addr2);
			err = xaddr_init_from_url(&(move->dst), move->dst_url->host);
			if (err != NULL) {
				GS_ERROR_STACK(&err);
			}

			if (NULL == meta2_addr2) {
				g_free(meta2_addr2);
			}
		}
	}
	else {
		if (!result) {
			if (!err) {
				err = GS_ERROR_NEW(500, "No DST meta2 available");
			}
		}
		else {
			if (!result[0]) {
				err = GS_ERROR_NEW(500, "No DST meta2 available");
			}
			else {
				for (ps=result; *ps ;ps++) {
					DEBUG("Got DST meta2 [%s]", *ps);
				}

				move->dst_url = meta1_unpack_url(result[0]);
				err = xaddr_init_from_url(&(move->dst), move->dst_url->host);
				if (err != NULL) {
					GS_ERROR_STACK(&err);
				}
			}

			g_strfreev(result);
		}	
	}

	return err;
}

static GError*
meta2_mover_locate_source(gs_grid_storage_t * ns_client,
	struct xcid_s *scid, struct cid_move_s *move)
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
			return err;
		}

		DEBUG("Sending the dump/restore command...");
		if (meta2_remote_restorev1_container(&(move->dst.cnx), scid->cid, &(move->src.addr), scid->cid, &err))
			break;

		ERROR("Failed to copy the container : %s", gerror_get_message(err));
		code = gerror_get_code(err);
		if (code < 100) { /* network error */
			g_clear_error(&err);
		}
		/*
		else if (code == 501) {
			g_clear_error(&err);
			break;
		}
		*/
		else {
			GS_ERROR_STACK(&err);
			return err;
		}
	}
	DEBUG("Container copied");

	/* next step, no ROLLBACK to the migration operation */
	return _step3_CHANGE_REFS(ns_client, scid, move);
}

static GError*
_step1_POLL_TARGET(gs_grid_storage_t *ns_client,
		struct xcid_s *scid, struct cid_move_s *move, const gchar *meta2_addr, gboolean forcing_ip)
{
	GError *err = NULL;

	g_assert(scid != NULL);
	g_assert(move != NULL);

	/* Init the target side of the movement */
	err = meta2_mover_locate_destination(ns_client, scid, move, meta2_addr, forcing_ip);
	if (NULL != err) {
		GS_ERROR_STACK(&err);
		return err;
	}

	if (! g_ascii_strcasecmp(move->src.str, move->dst.str)) {
		err = g_error_new(g_quark_from_static_string(LOG_DOMAIN), 500, "SRC and DST meta2 are the same, skipping");
	}
	else {
		DEBUG("Ready to move ID[%s] M0[%s] M1[%s] M2[%s] -> M2[%s]",
				scid->str, scid->location->m0_url,
				move->m1.str, move->src.str, move->dst.str);

		/* next step, move */
		if (!(err = _step2_MIGRATE(ns_client, scid, move))) {
			DEBUG("container \"%s\" successfuly migrated to service \"%s\"", scid->str, move->dst.str);
			printf("Move succeeded : Container \"%s\" successfuly migrated to service \"%s\"\n", scid->str, move->dst.str);
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

	/* Forcing the old association into Meta1 */
	/*
	gchar* meta2_addr2 = g_strconcat("1|meta2|", move->src.str, "|", NULL);
	gchar temp_seq[20];
	sprintf(temp_seq, "%ld", move->src_url->seq);
	gchar* meta2_addr2 = g_strconcat(temp_seq, "|meta2|", move->src.str, "|", NULL);
	*/
	/*
	gboolean result = FALSE;
	DEBUG("Rollback : Forcing a META2 Using namespace [%s] on meta2 [%s]", gs_get_namespace(ns_client), meta2_addr2);
	result = meta1v2_remote_force_reference_service(&(move->m1.addr), &err,
				gs_get_namespace(ns_client), scid->cid, meta2_addr2,
                                to_step, to_all, NULL);
	if (result == FALSE) {
		if (!err) {
                	err = GS_ERROR_NEW(500, "Failed to rollback to the previous DST");
			GS_ERROR_STACK(&err);
                }
	}
	if (NULL != meta2_addr2) {
		g_free(meta2_addr2);
	}
	*/

	return err;
}

static GError*
_step0_FREEZE_SOURCE(gs_grid_storage_t *ns_client,
		struct xcid_s *scid, struct cid_move_s *move, const gchar* meta2_addr, gboolean forcing_ip)
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

		DEBUG("Freezing the source container (%d attempts remaining) ...", attempts);
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
	if (!(err = _step1_POLL_TARGET(ns_client, scid, move, meta2_addr, forcing_ip)))
		return NULL;

	/* ROLLBACK : enables the source */
	_enable_container(scid, &(move->src));
	return err;
}


/* ------------------------------------------------------------------------- */

/*!
 * Locate the source META2 and the META1, poll a destination META2,
 * then advance to the next step
 */
GError*
meta2_mover_migrate(gs_grid_storage_t * ns_client, const gchar * xcid, const gchar *meta2_addr)
{
	struct cid_move_s move;
	struct xcid_s *scid = NULL;
	GError *err = NULL;

	gchar* meta2_addr_ip = NULL;

	if (NULL != meta2_addr && strlen(meta2_addr) >= 4) {
		gchar* url_tok = g_substr(meta2_addr, 0, 4);
		if (!g_strcmp0(url_tok, "url=")) {
			meta2_addr_ip = g_substr(meta2_addr, 4, strlen(meta2_addr));

			DEBUG("Forcing the META2 with IP %s", meta2_addr_ip);
		}
		if (url_tok) {
                	g_free(url_tok);
        	}
	}

	g_assert(xcid != NULL);
	_cid_move_init(&move);

	if (!(scid = xcid_from_hexa(xcid))) {
		err = GS_ERROR_NEW(0, "Bad format for container id [%.*s]", 64, xcid);
		_cid_move_destroy(&move, TRUE);
		return err;
	}

	/* Locate the container */
	if (NULL != (err = meta2_mover_locate_source(ns_client, scid, &move))) {
		GS_ERROR_STACK(&err);
		_cid_move_destroy(&move, TRUE);
		return err;
	}

	if (NULL == meta2_addr_ip) {
		if (NULL != (err = _step0_FREEZE_SOURCE(ns_client, scid, &move, meta2_addr, FALSE))) {
			GS_ERROR_STACK(&err);
		}		
	}
	else {
		if (NULL != (err = _step0_FREEZE_SOURCE(ns_client, scid, &move, meta2_addr_ip, TRUE))) {
                        GS_ERROR_STACK(&err);
                }
	}

	_cid_move_destroy(&move, TRUE);
	if (meta2_addr_ip) {
		g_free(meta2_addr_ip);
	}
	return err;
}

