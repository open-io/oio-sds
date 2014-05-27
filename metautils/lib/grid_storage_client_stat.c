#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.stats"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include <glib.h>

#include "metautils.h"
#include "grid_storage_client_stat.h"




/***************************************************************************/
/* THREADSAFE                                                              */
/***************************************************************************/

// call 1 time by the first call of the first thread
static void *_gscstat_thread_init(void *);

// init variable value
static GOnce g_gscstat_thread_init = G_ONCE_INIT;

// mutex
static GStaticMutex g_gscstat_lock = G_STATIC_MUTEX_INIT;

//add to each functions...
#define GSCSTAT_TH_INIT(/*int*/status, /*(GError **)*/err) do {\
	status = 0; (void) err; \
	(void) g_once(&g_gscstat_thread_init, _gscstat_thread_init, NULL); \
} while (0)

#define GSCSTAT_TH_LOCK_INIT()     0
#define GSCSTAT_TH_LOCK_DESTROY()  do {  } while (0)
#define GSCSTAT_TH_LOCK()          g_static_mutex_lock(&g_gscstat_lock); do {
#define GSCSTAT_TH_UNLOCK()        } while (0); g_static_mutex_unlock(&g_gscstat_lock)




/***************************************************************************/
/* constante / structure                                                   */
/***************************************************************************/

/*calcul od process time*/
#define GSCSTAT_GETCLOCK(/*struct timeval*/ startorend) gettimeofday(&startorend, NULL)
#define GSCSTAT_CALC(/*struct timeval*/ start, /*struct timeval*/ end) \
        ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec))



typedef struct gscstat_s
{
	GSList *services;	// element: gscstat_service_info_t
} gscstat_t;




/***************************************************************************/
/* function                                                                */
/***************************************************************************/

static gscstat_service_info_t *_gscstat_getService(char *pServiceType,
    gscstat_service_tags_lst tagsEnabled);
static char *_gscstat_dumpServiceByStruct(gscstat_service_info_t * pSvc,
    gboolean bWithTitle, gscstat_service_tags_lst tags);
static void _gscstat_tags_clearByStruct(gscstat_service_info_t * pSvc,
    gscstat_service_tags_lst tag);




/***************************************************************************/
/* variables                                                               */
/***************************************************************************/

static gscstat_t g_gscstat_info;




/***************************************************************************/
/* Functions                                                               */
/***************************************************************************/

int
gscstat_initAndConfigureALLServices(GError ** err)
{
#define LIST_NB 7
	static gchar *list[LIST_NB] = {
		GSCSTAT_SERVICE_ALL,
		GSCSTAT_SERVICE_METACD,
		GSCSTAT_SERVICE_META0,
		GSCSTAT_SERVICE_META1,
		GSCSTAT_SERVICE_META2,
		GSCSTAT_SERVICE_RAWX,
		GSCSTAT_SERVICE_SOLR
	};

	int status = 0;
	GSCSTAT_TH_INIT(status, err);
	if (status != 0)
		return -1;

	// enabled all tags traitement
	gscstat_service_tags_lst tagsname = GSCSTAT_TAGS_all;

	int result = 0;
	for (int s = 0; s < LIST_NB; s++) {
		if (gscstat_addServiceAndTags(list[s], tagsname, err) < 0) {
			GSETERROR(err, "Service not added");
			result = -1;
			continue;
		}
	}

	if (TRACE_ENABLED()) {
		char *tmp = gscstat_dumpAllServices();
		TRACE("Services added to spy by gscstat %s\n %s\n", ((result < 0)
					? "(not all services selected are added to spy)" : ""
					), tmp);
		g_free(tmp);
	}

	return result;
}


int
gscstat_init(GError ** err)
{
	//init mutex
	if (GSCSTAT_TH_LOCK_INIT() != 0) {
		GSETERROR(err, "mutex init failed");
		return -1;
	}

	//init global data
	memset(&g_gscstat_info, 0, sizeof(gscstat_t));

	return 0;
}


void
gscstat_free(void)
{
	int status = 0;
	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return;

	GSCSTAT_TH_LOCK();
	if (g_gscstat_info.services) {
		g_slist_free_full(g_gscstat_info.services, g_free);
		g_gscstat_info.services = NULL;
	}
	GSCSTAT_TH_UNLOCK();

	GSCSTAT_TH_LOCK_DESTROY();
}


int
gscstat_addServiceAndTags(char *pServiceType,
    gscstat_service_tags_lst tagsEnabled, GError ** err)
{
	int status = 0;
	GSCSTAT_TH_INIT(status, err);
	if (status != 0)
		return -1;

	gscstat_service_info_t *pSvc = _gscstat_getService(pServiceType,
			GSCSTAT_TAGS_all);
	if (pSvc != NULL) {
		GSETERROR(err, "Service already added");
		return -1;
	}

	pSvc = (gscstat_service_info_t *) g_malloc0(sizeof(gscstat_service_info_t));
	g_strlcpy(pSvc->serviceType, pServiceType, GSCSTAT_MAXBYTES_SVCTYP);

	pSvc->tagsEnabled = tagsEnabled;

	GSCSTAT_TH_LOCK();
	g_gscstat_info.services = g_slist_prepend(g_gscstat_info.services, pSvc);
	GSCSTAT_TH_UNLOCK();

	return 0;
}


int
gscstat_addTagsToService(char *pServiceType,
    gscstat_service_tags_lst tagsEnabled, GError ** err)
{
	int status = 0;
	GSCSTAT_TH_INIT(status, err);
	if (status != 0)
		return -1;

	gscstat_service_info_t *pSvc;
	pSvc = _gscstat_getService(pServiceType, GSCSTAT_TAGS_all);
	if (pSvc == NULL) {
		GSETERROR(err, "Service not initialize");
		return -1;
	}

	GSCSTAT_TH_LOCK();
	pSvc->tagsEnabled |= tagsEnabled;
	GSCSTAT_TH_UNLOCK();

	return 0;
}


/**
 * if tag == GSCSTAT_TAGS_REQPROCTIME: tagValue => (gscstat_service_tag_reqprctime_t*)
 */
int
gscstat_getTagFromService(char *pServiceType, gscstat_service_tags_e tag,
    void *tagValue, GError ** err)
{
	int status = 0;

	GSCSTAT_TH_INIT(status, err);
	if (status != 0)
		return -1;

	gscstat_service_info_t *pSvc = _gscstat_getService(pServiceType, tag);

	if (tagValue == NULL) {
		GSETERROR(err, "tagValue NULL");
		return -1;
	}

	if (pSvc == NULL) {
		GSETERROR(err, "Service [pServiceType] not spy");
		return -1;
	}

	if ((tag & GSCSTAT_TAGS_REQPROCTIME) != 0) {
		gscstat_service_tag_reqprctime_t *val =
		    (gscstat_service_tag_reqprctime_t *) tagValue;
		GSCSTAT_TH_LOCK();
		memcpy(val, &(pSvc->tag_recproctime),
		    sizeof(gscstat_service_tag_reqprctime_t));
		GSCSTAT_TH_UNLOCK();
	}

	return 0;
}


char *
gscstat_dumpService(char *pServiceType, GError ** err)
{
	GString *str = g_string_new("");

	int status = 0;

	GSCSTAT_TH_INIT(status, err);
	if (status != 0)
		return g_string_free(str, FALSE);

	gscstat_service_info_t *pSvc =
	    _gscstat_getService(pServiceType, GSCSTAT_TAGS_all);
	if (pSvc == NULL)
		return g_string_free(str, FALSE);

	return _gscstat_dumpServiceByStruct(pSvc, TRUE, GSCSTAT_TAGS_all);
}


char *
gscstat_dumpAllServices(void)
{
	GString *str = g_string_new("");
	char *tmp;
	int nbElt, i;

	gscstat_service_info_t *pSvc = NULL;
	GSList *list = NULL;

	int status = 0;

	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return g_string_free(str, FALSE);

	list = g_gscstat_info.services;
	nbElt = g_slist_length(list);
	for (i = 0; i < nbElt; i++) {
		pSvc = (gscstat_service_info_t *) g_slist_nth_data(list, i);

		tmp = _gscstat_dumpServiceByStruct(pSvc,
		    (list == g_gscstat_info.services),
		    GSCSTAT_TAGS_REQPROCTIME);
		g_string_append_printf(str, "%s", tmp);
		g_free(tmp);
	}

	return g_string_free(str, FALSE);;
}


void
gscstat_tags_clearAllServices(gscstat_service_tags_lst tag)
{
	gscstat_service_info_t *pSvc = NULL;
	GSList *list = NULL;
	int nbElt = 0;
	int i;

	int status = 0;

	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return;


	list = g_gscstat_info.services;
	nbElt = g_slist_length(list);
	for (i = 0; i < nbElt; i++) {
		pSvc = (gscstat_service_info_t *) g_slist_nth_data(list, i);
		_gscstat_tags_clearByStruct(pSvc, tag);
	}

}


void
gscstat_tags_clear(char *pServiceType, gscstat_service_tags_lst tag)
{
	int status = 0;

	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return;

	gscstat_service_info_t *pSvc = _gscstat_getService(pServiceType, tag);

	_gscstat_tags_clearByStruct(pSvc, tag);
}


void
gscstat_tags_start(char *pServiceType, gscstat_service_tags_lst tag)
{
	int status = 0;

	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return;

	gscstat_service_info_t *pSvc = _gscstat_getService(pServiceType, tag);

	if (pSvc == NULL)
		return;

	if ((tag & GSCSTAT_TAGS_REQPROCTIME) != 0) {
		GSCSTAT_TH_LOCK();
		GSCSTAT_GETCLOCK(pSvc->tag_recproctime.proctime_start);
		GSCSTAT_TH_UNLOCK();
	}

}


void
gscstat_tags_end(char *pServiceType, gscstat_service_tags_lst tag)
{
	int status = 0;

	GSCSTAT_TH_INIT(status, NULL);
	if (status != 0)
		return;

	gscstat_service_info_t *pSvc = _gscstat_getService(pServiceType, tag);

	if (pSvc == NULL)
		return;

	if ((tag & GSCSTAT_TAGS_REQPROCTIME) != 0) {
		GSCSTAT_TH_LOCK();
		gscstat_service_tag_reqprctime_t *val =
		    &(pSvc->tag_recproctime);
		GSCSTAT_GETCLOCK(val->proctime_end);
		val->last_req =
		    GSCSTAT_CALC(val->proctime_start, val->proctime_end);
		val->sum_req += val->last_req;
		(val->nb_req)++;
		val->average_req = val->sum_req / val->nb_req;
		GSCSTAT_TH_UNLOCK();
	}

}





/*========================================================================*/

void *
_gscstat_thread_init(void *ignored)
{
	GError *err = NULL;

	gscstat_init(&err);
	if (err)
		g_clear_error(&err);
	return ignored;
}


gscstat_service_info_t *
_gscstat_getService(char *pServiceType, gscstat_service_tags_lst tagsEnabled)
{
	gscstat_service_info_t *pSvc = NULL;
	gscstat_service_info_t *pSvcResult = NULL;
	GSList *list = NULL;
	int nbElt, i;

	list = g_gscstat_info.services;
	nbElt = g_slist_length(list);
	for (i = 0; i < nbElt; i++) {
		pSvc = (gscstat_service_info_t *) g_slist_nth_data(list, i);
		if ((pSvc != NULL)
		    && (strcmp(pSvc->serviceType, pServiceType) == 0)) {
			if ((tagsEnabled & pSvc->tagsEnabled) != 0) {
				pSvcResult = pSvc;
				break;
			}
		}
	}

	return pSvcResult;
}


char *
_gscstat_dumpServiceByStruct(gscstat_service_info_t * pSvc, gboolean bWithTitle,
    gscstat_service_tags_lst tags)
{
	GString *str = g_string_new("");

	if ((tags & GSCSTAT_TAGS_REQPROCTIME) != 0) {
		GSCSTAT_TH_LOCK();
		if ((pSvc->tagsEnabled & GSCSTAT_TAGS_REQPROCTIME) != 0) {

			if (bWithTitle == TRUE)
				g_string_append_printf(str,
				    "\n%15s: last(ms) sum(ms) average(ms) nb\n",
				    "recproctime");

			gscstat_service_tag_reqprctime_t *val =
			    &(pSvc->tag_recproctime);
			if (val->nb_req == 0)
				g_string_append_printf(str, "%15s: -\n",
				    pSvc->serviceType);
			else
				g_string_append_printf(str,
				    "%15s: %.3lf \t%.3lf \t%.3lf \t%d\n",
				    pSvc->serviceType, val->last_req / 1000,
				    val->sum_req / 1000,
				    val->average_req / 1000, val->nb_req);
		}
		GSCSTAT_TH_UNLOCK();
	}


	return g_string_free(str, FALSE);

}


void
_gscstat_tags_clearByStruct(gscstat_service_info_t * pSvc,
    gscstat_service_tags_lst tag)
{
	gscstat_service_tag_reqprctime_t *val = NULL;

	if (pSvc == NULL)
		return;

	if ((tag & GSCSTAT_TAGS_REQPROCTIME) != 0) {
		GSCSTAT_TH_LOCK();
		val = &(pSvc->tag_recproctime);
		val->last_req = 0;
		val->sum_req = 0;
		val->nb_req = 0;
		val->average_req = 0;
		GSCSTAT_TH_UNLOCK();
	}
}


