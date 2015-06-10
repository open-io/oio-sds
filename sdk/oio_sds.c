#include <assert.h>

#include <glib.h>

#include "metautils/lib/hc_url.h"
#include "client/c/lib/grid_client.h"
#include "client/c/lib/hc.h"
#include "oio_sds.h"

struct oio_sds_s;
struct oio_error_s;
struct hc_url_s;

/* error management */
void
oio_error_free (struct oio_error_s *e)
{
	if (!e) return;
	gs_error_free ((gs_error_t*)e);
}

void
oio_error_pfree (struct oio_error_s **pe)
{
	if (!pe || !*pe) return;
	oio_error_free (*pe);
	*pe = NULL;
}

int
oio_error_code (const struct oio_error_s *e)
{
	if (!e) return 0;
	return ((gs_error_t*)e)->code;
}

const char *
oio_error_message (const struct oio_error_s *e)
{
	if (!e) return "?";
	return ((gs_error_t*)e)->msg;
}

/* client management */
struct oio_error_s *
oio_sds_init (struct oio_sds_s **out, const char *ns)
{
	assert (out != NULL);
	gs_error_t *e = NULL;
	*out = (struct oio_sds_s*) gs_grid_storage_init (ns, &e);
	return (struct oio_error_s*) e;
}

void
oio_sds_free (struct oio_sds_s *sds)
{
	if (!sds) return;
	gs_grid_storage_free ((gs_grid_storage_t*)sds);
}

void
oio_sds_pfree (struct oio_sds_s **psds)
{
	if (!psds || !*psds) return;
	oio_sds_free (*psds);
	*psds = NULL;
}

struct oio_error_s*
oio_sds_download_to_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL),
	assert (url != NULL);
	gs_error_t *e = NULL;
	(void) hc_dl_content_to_file ((gs_grid_storage_t*)sds,
			hc_url_get(url, HCURL_USER), hc_url_get(url, HCURL_PATH),
			local, &e);
	return (struct oio_error_s*)e;
}

struct oio_error_s*
oio_sds_upload_from_file (struct oio_sds_s *sds, struct hc_url_s *url,
		const char *local)
{
	assert (sds != NULL);
	assert (url != NULL);
	gs_error_t *e = NULL;
	(void) hc_dl_content_to_file ((gs_grid_storage_t*)sds,
			hc_url_get(url, HCURL_USER), hc_url_get(url, HCURL_PATH),
			local, &e);
	return (struct oio_error_s*)e;
}

struct oio_error_s*
oio_sds_delete (struct oio_sds_s *sds, struct hc_url_s *url)
{
	assert (sds != NULL);
	assert (url != NULL);
    return (struct oio_error_s*) hc_delete_content ((gs_grid_storage_t*)sds, url);
}

