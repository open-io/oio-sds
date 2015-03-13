/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__grid_storage_client_stat_h
# define OIO_SDS__metautils__lib__grid_storage_client_stat_h 1

/******************************************************/
/* constant / macro / type                            */
/******************************************************/
/**
 * serviceType
 */
#define GSCSTAT_SERVICE_ALL    "total"
#define GSCSTAT_SERVICE_META0  "meta0"
#define GSCSTAT_SERVICE_META1  "meta1"
#define GSCSTAT_SERVICE_META2  "meta2"
#define GSCSTAT_SERVICE_METACD "metacd"
#define GSCSTAT_SERVICE_RAWX   "rawx"
#define GSCSTAT_SERVICE_SOLR   "solr"

/**
 * tag name
 */
typedef enum
{
	GSCSTAT_TAGS_none = 0x0000,
	GSCSTAT_TAGS_REQPROCTIME = 0x0001,	// "stat.reqproctime"
	GSCSTAT_TAGS_all = 0xFFFF
} gscstat_service_tags_e;

/**
 * tags name list, separated by '|'
 */
#define gscstat_service_tags_lst unsigned short

/******************************************************/
/* structure for service / tag config / value         */
/******************************************************/

/**
 * value of tag GSCSTAT_TAGS_REQPROCTIME
 */
typedef struct gscstat_service_tag_reqprctime_s
{
	//runing data
	struct timeval proctime_start;
	struct timeval proctime_end;

	/* measure GSCSTAT_TAGS_REQPROCTIME, about de request / response: client  <----> service */
	double last_req;// process time in micro-second of last ~
	double sum_req;	// sum of all process time in micro-second of all ~
	int nb_req;		// nb ~
	double average_req;	// = sum / nb
} gscstat_service_tag_reqprctime_t;

/**
 * configuration and data for each service
 */
#define GSCSTAT_MAXBYTES_SVCTYP      128

typedef struct gscstat_service_info_s
{
	char serviceType[GSCSTAT_MAXBYTES_SVCTYP];
	gscstat_service_tags_lst tagsEnabled;

	// value of tags enabled
	gscstat_service_tag_reqprctime_t tag_recproctime;

} gscstat_service_info_t;

/******************************************************/
/* functions                                          */
/******************************************************/

/* function: client */
int gscstat_initAndConfigureALLServices(GError ** err);

int gscstat_init(GError ** err);
void gscstat_free(void);

int gscstat_addServiceAndTags(char *pServiceType,
		gscstat_service_tags_lst tagsEnabled, GError ** err);
int gscstat_addTagsToService(char *pServiceType,
		gscstat_service_tags_lst tagsEnabled, GError ** err);
int gscstat_getTagFromService(char *pServiceType, gscstat_service_tags_e tag,
    void *tagValue, GError ** err);

/* Debug */
char *gscstat_dumpAllServices(void);
char *gscstat_dumpService(char *pServiceType, GError ** err);

/* function: for mesearment*/
void gscstat_tags_clearAllServices(gscstat_service_tags_lst tag);
void gscstat_tags_clear(char *pServiceType, gscstat_service_tags_lst tag);
void gscstat_tags_start(char *pServiceType, gscstat_service_tags_lst tag);
void gscstat_tags_end(char *pServiceType, gscstat_service_tags_lst tag);

#endif /*OIO_SDS__metautils__lib__grid_storage_client_stat_h*/