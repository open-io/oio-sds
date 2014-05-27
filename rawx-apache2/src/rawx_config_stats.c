#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <time.h>

#include <apr.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <apr_time.h>
#include <apr_atomic.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>

#include <mod_dav.h>

#include "rawx_internals.h"
#include "rawx_config.h"
#include "rawx_stats_rrd.h"

apr_status_t
server_init_master_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog)
{
	char buff[256];
	apr_status_t rc;

	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	/* Try to attach to the already existing SHM segment */
	rc = apr_shm_attach(&(conf->shm.handle), conf->shm.path, pool);
	if (APR_SUCCESS != rc) {
		DAV_DEBUG_POOL(plog, 0, "%s: Failed to attach to SHM segment at [%s]: %s",
				__FUNCTION__, conf->shm.path, apr_strerror(rc, buff, sizeof(buff)));
		conf->shm.handle = NULL;
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s: Attached to existing SHM segment at [%s]",
			__FUNCTION__, conf->shm.path);

	/* Create a processus lock*/
	rc = apr_global_mutex_create(&(conf->lock.handle), conf->shm.path, APR_LOCK_DEFAULT, pool);
	if (rc != APR_SUCCESS) {
		DAV_ERROR_POOL(plog, 0, "%s : Cannot create a global_mutex at [%s] rc=%d : %s",
			__FUNCTION__, conf->shm.path, rc, apr_strerror(rc, buff, sizeof(buff)));
		(void) apr_shm_destroy(conf->shm.handle);
		conf->shm.handle = NULL;
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s : globalmutex created at [%s]", __FUNCTION__, conf->shm.path);

	return APR_SUCCESS;
}

void
server_master_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog)
{
	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	if (conf->lock.handle) {
		DAV_DEBUG_POOL(plog, 0, "%s: Destroying the globalmutex at [%s]", __FUNCTION__, conf->shm.path);
		if (APR_SUCCESS != apr_global_mutex_destroy(conf->lock.handle)) {
			DAV_ERROR_POOL(plog, 0, "Failed to destroy the global_mutex");
		}
		conf->lock.handle = NULL;
	}

	if (conf->shm.handle) {
		DAV_DEBUG_POOL(plog, 0, "%s: Detaching the SHM segment at [%s]", __FUNCTION__, conf->shm.path);
		if (APR_SUCCESS != apr_shm_detach(conf->shm.handle)) {
			DAV_ERROR_POOL(plog, 0, "Failed to detach the SHM segment");
		}
		conf->shm.handle = NULL;
	}
}

apr_status_t
server_init_child_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog)
{
	char buff[256];
	apr_status_t rc;

	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	/* Attaches the mutex */
	DAV_DEBUG_POOL(plog, 0, "%s : Attaching the SHM global_mutex at [%s]", __FUNCTION__, conf->shm.path);
	rc = apr_global_mutex_child_init(&(conf->lock.handle), conf->shm.path, pool);
	if (APR_SUCCESS != rc) {
		DAV_ERROR_POOL(plog, 0, "%s : Failed to attach the SHM global_mutex at [%s] rc=%d : %s",
			__FUNCTION__, conf->shm.path, rc, apr_strerror(rc, buff, sizeof(buff)));
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s : globalmutex attached at [%s]", __FUNCTION__, conf->shm.path);

	/* Atatches the SHM */
	if (!conf->shm.handle) {
		DAV_DEBUG_POOL(plog, 0, "%s : Attaching the SHM segment at [%s]", __FUNCTION__, conf->shm.path);
		rc = apr_shm_attach(&(conf->shm.handle), conf->shm.path, pool);
		if (APR_SUCCESS != rc) {
			DAV_ERROR_POOL(plog, 0, "%s : Failed to attach the SHM segment at [%s] rc=%d : %s",
				__FUNCTION__, conf->shm.path, rc, apr_strerror(rc, buff, sizeof(buff)));
			conf->shm.handle = NULL;
			return rc;
		}
	}
	DAV_DEBUG_POOL(plog, 0, "%s : SHM segment attached at [%s]", __FUNCTION__, conf->shm.path);

	return APR_SUCCESS;
}

apr_status_t
server_child_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog)
{
	char buff[256];
	apr_status_t rc;

	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	/* Detaches the segment */
	if (conf->shm.handle) {
		rc = apr_shm_detach(conf->shm.handle);
		if (APR_SUCCESS != rc) {
			DAV_ERROR_POOL(plog, 0, "Failed to detach SHM segment at [%s] rc=%d : %s",
					conf->shm.path, rc, apr_strerror(rc, buff, sizeof(buff)));
			return rc;
		}
		conf->shm.handle = NULL;
	}

	DAV_DEBUG_POOL(plog, 0, "%s: SHM segment at [%s] detached", __FUNCTION__, conf->shm.path);
	return APR_SUCCESS;
}


void
server_add_stat(dav_rawx_server_conf *conf, const char *n, apr_uint32_t value, apr_uint32_t duration)
{
	struct shm_stats_s *shm_stats;

	if (!n)
		return;

	if (!conf->shm.handle || !conf->lock.handle) { /* This should never happen! */
#ifdef HAVE_EXTRA_DEBUG
		abort();
#else
		return;
#endif
	}

	if (!n[0] || !n[1] || n[2]!='\0') { /* strlen(n)!=2 */
#ifdef HAVE_EXTRA_DEBUG
		abort();
#else
		return;
#endif
	}

	apr_global_mutex_lock(conf->lock.handle);
	shm_stats = apr_shm_baseaddr_get(conf->shm.handle);
	apr_global_mutex_unlock(conf->lock.handle);

	/* increase the appropriated counter */
	if (shm_stats) {
		switch (*n) {
			case 'q':
				switch (n[1]) {
					case '0':
						apr_atomic_add32(&(shm_stats->body.req_all), value);
						if(duration > 0) {
							apr_atomic_add32(&(shm_stats->body.time_all), duration);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_req_sec), shm_stats->body.req_all);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_duration), shm_stats->body.time_all);
						}
						break;
					case '1':
						apr_atomic_add32(&(shm_stats->body.req_chunk_get), value);
						if(duration > 0) {
							apr_atomic_add32(&(shm_stats->body.time_get), duration);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_req_get_sec), shm_stats->body.req_chunk_get);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_get_duration), shm_stats->body.time_get);
						}
						break;
					case '2':
						apr_atomic_add32(&(shm_stats->body.req_chunk_put), value);
						if(duration > 0) {
							apr_atomic_add32(&(shm_stats->body.time_put), duration);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_req_put_sec), shm_stats->body.req_chunk_put);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_put_duration), shm_stats->body.time_put);
						}
						break;
					case '3':
						apr_atomic_add32(&(shm_stats->body.req_chunk_del), value);
						if(duration > 0) {
							apr_atomic_add32(&(shm_stats->body.time_del), duration);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_req_del_sec), shm_stats->body.req_chunk_del);
							rawx_stats_rrd_push(&(shm_stats->body.rrd_del_duration), shm_stats->body.time_del);
						}
						break;
					case '4': apr_atomic_add32(&(shm_stats->body.req_stat), value); break;
					case '5': apr_atomic_add32(&(shm_stats->body.req_info), value); break;
					case '6': apr_atomic_add32(&(shm_stats->body.req_raw), value); break;
					case '7': apr_atomic_add32(&(shm_stats->body.req_other), value); break;
				}
				break;
			case 'r':
				switch (n[1]) {
					case '1': apr_atomic_add32(&(shm_stats->body.rep_2XX), value); break;
					case '2': apr_atomic_add32(&(shm_stats->body.rep_4XX), value); break;
					case '3': apr_atomic_add32(&(shm_stats->body.rep_5XX), value); break;
					case '4': apr_atomic_add32(&(shm_stats->body.rep_other), value); break;
					case '5': apr_atomic_add32(&(shm_stats->body.rep_403), value); break;
					case '6': apr_atomic_add32(&(shm_stats->body.rep_404), value); break;
					case '7': apr_atomic_add32(&(shm_stats->body.rep_bread), value); break;
					case '8': apr_atomic_add32(&(shm_stats->body.rep_bwritten), value); break;
				}
				break;
		}
	}
}

void
server_inc_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration)
{
	server_add_stat(conf, n, 1LLU, duration);
}

void
server_inc_request_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration)
{
	server_inc_stat(conf, n, duration);
	server_inc_stat(conf, RAWX_STATNAME_REQ_ALL, duration);
}

void
server_inc_daverror_stat(dav_rawx_server_conf *conf, dav_error *derr)
{
	if (!derr) {
		server_inc_stat(conf, RAWX_STATNAME_REP_2XX, 0);
		return;
	}

	switch (derr->status / 100) {
		case 2:
			server_inc_stat(conf, RAWX_STATNAME_REP_2XX, 0);
			return;
		case 4:
			server_inc_stat(conf, RAWX_STATNAME_REP_4XX, 0);
			if (derr->status == 403)
				server_inc_stat(conf, RAWX_STATNAME_REP_403, 0);
			else if (derr->status == 403)
				server_inc_stat(conf, RAWX_STATNAME_REP_404, 0);
			return;
		case 5:
			server_inc_stat(conf, RAWX_STATNAME_REP_5XX, 0);
			return;
		default:
			server_inc_stat(conf, RAWX_STATNAME_REP_OTHER, 0);
			return;
	}
}

dav_error*
server_create_and_stat_error(dav_rawx_server_conf *conf, apr_pool_t *p, int status, int error_id, const char *desc)
{
	dav_error *error;
	error = __dav_new_error(p, status, error_id, desc);
	server_inc_daverror_stat(conf, error);
	return error;
}

