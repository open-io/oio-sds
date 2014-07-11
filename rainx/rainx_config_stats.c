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

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>

#include <mod_dav.h>

#include "./rainx_internals.h"
#include "./rainx_config.h"
#include "./rainx_stats_rrd.h"

apr_status_t
server_init_master_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog)
{
	char buff[256];
	apr_status_t rc;

	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	/* Create and attach the segment */
	rc = apr_shm_create(&(conf->shm.handle), sizeof(struct shm_stats_s), conf->shm.path, pool);
	if (APR_SUCCESS != rc) {
		DAV_ERROR_POOL(plog, 0, "%s : Cannot create a SHM segment at [%s] rc=%d : %s",
			__FUNCTION__, conf->shm.path, rc, apr_strerror(rc, buff, sizeof(buff)));
		conf->shm.handle = NULL;
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s : SHM segment created at [%s]", __FUNCTION__, conf->shm.path);

	/* Create a processus lock*/
	rc = apr_global_mutex_create(&(conf->lock.handle), conf->lock.path, APR_LOCK_DEFAULT, pool);
	if (rc != APR_SUCCESS) {
		DAV_ERROR_POOL(plog, 0, "%s : Cannot create a global_mutex at [%s] rc=%d : %s",
			__FUNCTION__, conf->lock.path, rc, apr_strerror(rc, buff, sizeof(buff)));
		(void) apr_shm_destroy(conf->shm.handle);
		conf->shm.handle = NULL;
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s : globalmutex created at [%s]", __FUNCTION__, conf->lock.path);

	/* Init the SHM */
	void *ptr_counter = apr_shm_baseaddr_get(conf->shm.handle);
	if (ptr_counter) {
		bzero(ptr_counter, sizeof(struct shm_stats_s));
		/* init rrd's */
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_req_sec));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_duration));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_req_put_sec));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_put_duration));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_req_get_sec));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_get_duration));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_req_del_sec));
		rainx_stats_rrd_init(&(((struct shm_stats_s *) ptr_counter)->body.rrd_del_duration));
	}

	return APR_SUCCESS;
}

void
server_master_stat_fini(dav_rainx_server_conf *conf, apr_pool_t *plog)
{
	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	if (conf->lock.handle) {
		DAV_DEBUG_POOL(plog, 0, "%s : Destroying the globalmutex at [%s]", __FUNCTION__, conf->lock.path);
		if (APR_SUCCESS != apr_global_mutex_destroy(conf->lock.handle)) {
			DAV_ERROR_POOL(plog, 0, "Failed to destroy the global_mutex");
		}
		conf->lock.handle = NULL;
	}

	if (conf->shm.handle) {
		DAV_DEBUG_POOL(plog, 0, "%s : Detaching the SHM segment at [%s]", __FUNCTION__, conf->shm.path);
		if (APR_SUCCESS != apr_shm_destroy(conf->shm.handle)) {
			DAV_ERROR_POOL(plog, 0, "Failed to detach the SHM segment");
		}
		conf->shm.handle = NULL;
	}

}

apr_status_t
server_init_child_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog)
{
	char buff[256];
	apr_status_t rc;

	DAV_XDEBUG_POOL(plog, 0, "%s()", __FUNCTION__);

	/* Attaches the mutex */
	DAV_DEBUG_POOL(plog, 0, "%s : Attaching the SHM global_mutex at [%s]", __FUNCTION__, conf->lock.path);
	rc = apr_global_mutex_child_init(&(conf->lock.handle), conf->lock.path, pool);
	if (APR_SUCCESS != rc) {
		DAV_ERROR_POOL(plog, 0, "%s : Failed to attach the SHM global_mutex at [%s] rc=%d : %s",
			__FUNCTION__, conf->lock.path, rc, apr_strerror(rc, buff, sizeof(buff)));
		return rc;
	}
	DAV_DEBUG_POOL(plog, 0, "%s : globalmutex attached at [%s]", __FUNCTION__, conf->lock.path);

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
server_child_stat_fini(dav_rainx_server_conf *conf, apr_pool_t *plog)
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
	
	DAV_DEBUG_POOL(plog, 0, "%s : SHM segment at [%s] detached", __FUNCTION__, conf->shm.path);
	return APR_SUCCESS;
}


void
server_add_stat(dav_rainx_server_conf *conf, const char *n, apr_uint64_t value, apr_uint64_t duration)
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
	/* XXX */

	/* increase the appropriated counter */
	shm_stats = apr_shm_baseaddr_get(conf->shm.handle);
	if (shm_stats) {
		switch (*n) {
			case 'q':
				switch (n[1]) {
					case '0': 
						shm_stats->body.req_all += value;
						if(duration > 0) {
							shm_stats->body.time_all += duration;
							rainx_stats_rrd_push(&(shm_stats->body.rrd_req_sec), shm_stats->body.req_all);
							rainx_stats_rrd_push(&(shm_stats->body.rrd_duration), shm_stats->body.time_all);
						}
						break;
					case '1':
						shm_stats->body.req_chunk_get += value;
						if(duration > 0) {
							shm_stats->body.time_get += duration;
							rainx_stats_rrd_push(&(shm_stats->body.rrd_req_get_sec), shm_stats->body.req_chunk_get);
							rainx_stats_rrd_push(&(shm_stats->body.rrd_get_duration), shm_stats->body.time_get);
						}
						break;
					case '2':
						shm_stats->body.req_chunk_put += value;
						if(duration > 0) {
							shm_stats->body.time_put += duration;
							rainx_stats_rrd_push(&(shm_stats->body.rrd_req_put_sec), shm_stats->body.req_chunk_put);
							rainx_stats_rrd_push(&(shm_stats->body.rrd_put_duration), shm_stats->body.time_put);
						}
						break;
					case '3':
						shm_stats->body.req_chunk_del += value;
						if(duration > 0) {
							shm_stats->body.time_del += duration;
							rainx_stats_rrd_push(&(shm_stats->body.rrd_req_del_sec), shm_stats->body.req_chunk_del);
							rainx_stats_rrd_push(&(shm_stats->body.rrd_del_duration), shm_stats->body.time_del);
						}
						break;
					case '4': shm_stats->body.req_stat += value; break;
					case '5': shm_stats->body.req_info += value; break;
					case '6': shm_stats->body.req_raw += value; break;
					case '7': shm_stats->body.req_other += value; break;
				}
				break;
			case 'r':
				switch (n[1]) {
					case '1': shm_stats->body.rep_2XX += value; break;
					case '2': shm_stats->body.rep_4XX += value; break;
					case '3': shm_stats->body.rep_5XX += value; break;
					case '4': shm_stats->body.rep_other += value; break;
					case '5': shm_stats->body.rep_403 += value; break;
					case '6': shm_stats->body.rep_404 += value; break;
					case '7': shm_stats->body.rep_bread += value; break;
					case '8': shm_stats->body.rep_bwritten += value; break;
				}
				break;
		}
	}

	/* XXX */
	apr_global_mutex_unlock(conf->lock.handle);
}

void
server_inc_stat(dav_rainx_server_conf *conf, const char *n, apr_time_t duration)
{
	server_add_stat(conf, n, 1LLU, duration);
}

void
server_inc_request_stat(dav_rainx_server_conf *conf, const char *n, apr_time_t duration)
{
	server_inc_stat(conf, n, duration);
	server_inc_stat(conf, RAWX_STATNAME_REQ_ALL, duration);
}

void
server_inc_daverror_stat(dav_rainx_server_conf *conf, dav_error *derr)
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
server_create_and_stat_error(dav_rainx_server_conf *conf, apr_pool_t *p, int status, int error_id, const char *desc)
{
	dav_error *error;
	error = __dav_new_error(p, status, error_id, desc);
	server_inc_daverror_stat(conf, error);
	return error;
}

void
server_getall_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, struct rainx_stats_s *stats)
{
	char *ptr_counter;
	(void) pool;

	apr_global_mutex_lock(conf->lock.handle);
	/* XXX */

	/* increase the appropriated counter */
	ptr_counter = apr_shm_baseaddr_get(conf->shm.handle);
	if (ptr_counter) {
		struct shm_stats_s *stats_struct = (struct shm_stats_s*)ptr_counter;
		memcpy(stats, &(stats_struct->body), sizeof(struct rainx_stats_s));
	}

	/* XXX */
	apr_global_mutex_unlock(conf->lock.handle);
}
