#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta0.prefixassign"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "./meta0_backend.h"
#include "./meta0_utils.h"
#include "./internals.h"
#include "./meta0_prefixassign.h"


struct meta0_assign_meta1_s
{
        gchar *addr;
        guint score;
        gboolean available;
	gboolean used;
        GArray *assignPrefixes;
};

struct meta0_assign_context_s
{
	GDateTime *lastAssignTime;
        GPtrArray *array_meta1_by_prefix ;
	GHashTable *map_meta1_ref;

        GHashTable *working_map_meta1_ref ;

	guint8 *treat_prefixes;
        guint replica, avgscore;

};


static GQuark gquark_log = 0;
static struct meta0_assign_context_s *context=NULL;

static guint period_between_two_assign = 10;  // in minute
static guint trigger_assignment = 5;  // percent


/* ----------------------------------------------------------------------------------------*/

static void _free_meta0_assign_meta1(struct meta0_assign_meta1_s *aM1) {
	if (!aM1)
		return;
	if (aM1->assignPrefixes)
		g_array_free(aM1->assignPrefixes, TRUE);
	if (aM1->addr)
		g_free(aM1->addr);
}

static void _gfree_map_meta0_assign_meta1(gpointer p1)
{
        if (p1) {
                _free_meta0_assign_meta1((struct meta0_assign_meta1_s *) p1);
	}
}


/* ----------------------------------------------------------------------------------------*/

static struct meta0_assign_meta1_s*
_unpack_meta1ref(gchar *s_meta1ref)
{
        EXTRA_ASSERT(s_meta1ref != NULL);

        struct meta0_assign_meta1_s *aM1;

        aM1 = g_malloc0(sizeof(struct meta0_assign_meta1_s));
        gchar** split_result = g_strsplit(s_meta1ref,"|",-1);

        if ( g_strv_length(split_result) != 3 )
                return NULL;

        aM1->addr=g_strdup(split_result[0]);
        aM1->used=(g_ascii_strtoll(split_result[1], NULL, 10) == 0) ? FALSE : TRUE;
        aM1->score=g_ascii_strtoll(split_result[2], NULL, 10);
	g_strfreev(split_result);

        return aM1;
}

static gchar *
_pack_meta1ref(struct meta0_assign_meta1_s *m1ref)
{
        gchar *nb = g_strdup_printf("%d",m1ref->score);
        gchar * result = meta0_utils_pack_meta1ref(m1ref->addr,( m1ref->used ? "1":"0") ,nb);
        g_free(nb);
        return result;
}

static GHashTable*  _meta1ref_array_to_map(GPtrArray *array)
{
        GHashTable *result;
        guint i, max;

        result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

        for (i=0, max=array->len; i<max ;i++) {
		struct meta0_assign_meta1_s *aM1 = _unpack_meta1ref(array->pdata[i]);
                if (aM1)
                        g_hash_table_insert(result,aM1->addr,aM1);
        }

        return result;
}

static GPtrArray* _meta1ref_map_to_array(GHashTable *map)
{
        GPtrArray *result;
        GHashTableIter iter;
        gpointer key, value;


        result = g_ptr_array_new();

        g_hash_table_iter_init(&iter, map);
        while ( g_hash_table_iter_next(&iter,&key,&value))
        {
                struct meta0_assign_meta1_s *mRef = value;

                g_ptr_array_add(result,_pack_meta1ref(mRef));
        }
        return result;
}


/* ----------------------------------------------------------------------------------------*/

static void
_treat_prefix(guint8 *cache, const guint8 *prefix)
{
        guint16 slot = meta0_utils_bytes_to_prefix(prefix);
        cache[ slot / 8 ] |= (0x01 << (slot % 8));
}

static gboolean
_is_treat_prefix(guint8 *cache, const guint8 *prefix)
{
        guint16 slot = meta0_utils_bytes_to_prefix(prefix);
        return cache[ slot / 8 ] & (0x01 << (slot % 8));
}


static gint
meta0_assign_sort_by_score(gconstpointer a, gconstpointer b)
{
        const struct meta0_assign_meta1_s *si_a, *si_b;

        if (!a && b)
                return 1;
        if (a && !b)
                return -1;
        if (a == b)
                return 0;
        si_a = a;
        si_b = b;
        return si_b->score - si_a->score;
}


/* ----------------------------------------------------------------------------------------*/


static gboolean
_select_prefix(GArray *prefixes, guint8 *treat_prefixes)
{
	if (!prefixes) {
		return FALSE;
	}

	if ( prefixes->len != 0 ) {
		guint8 *prefix = (guint8 *)prefixes->data;
		if(!_is_treat_prefix(treat_prefixes,prefix)) {
			GRID_TRACE("select prefix %02X%02X ",prefix[0],prefix[1]);
			return TRUE;
		}

		prefixes=g_array_remove_index(prefixes,0);	
		
		if ( prefixes->len != 0 ) {
			return _select_prefix(prefixes,treat_prefixes);
		} 
	}

	g_array_free(prefixes,TRUE);
	prefixes=NULL;

	return FALSE;
}


static struct meta0_assign_meta1_s*  
_select_source_assign_m1(GList *lst, guint8 *treat_prefixes, const guint avgscore)
{
	if (lst == NULL )
		return NULL;
	struct meta0_assign_meta1_s *aM1 =(g_list_first(lst))->data;

	if (aM1->score <= avgscore)
		return NULL;


	// check current prefix 
	GArray *prefixes = aM1->assignPrefixes;
	if (prefixes) { 
		if (!_select_prefix(prefixes,treat_prefixes)) {
			aM1->available=FALSE;
			aM1->assignPrefixes=NULL;
		}
	} else {
		aM1->available=FALSE;
	}


	if (!aM1->available) {
		lst=g_list_delete_link(lst,lst);

		return _select_source_assign_m1(lst, treat_prefixes,avgscore);
	}

	GRID_TRACE("select source meta1 %s, score %d",aM1->addr,aM1->score);
	return aM1;
}


static struct meta0_assign_meta1_s*
_select_dest_assign_m1(GList *lst, const struct meta0_assign_meta1_s *s_aM1, guint8 *prefixe, gboolean unref,gboolean force)
{
	guint8 *prefix;
	if ( s_aM1 )
		prefix = (guint8 *)(s_aM1->assignPrefixes)->data;
	else {
		if (prefixe)
			prefix=prefixe;
		else 
			return NULL;
	}
	GRID_TRACE("select prefix %02X%02X ",prefix[0],prefix[1]);

	lst = g_list_last(lst);
	struct meta0_assign_meta1_s *d_aM1 = lst->data;

	gboolean loop = TRUE;
	gchar *shost=NULL, *dhost=NULL, *sport=NULL, *dport=NULL, *host=NULL, *port=NULL;
	guint i, len;

	guint avgscore = context->avgscore;

	if (s_aM1)
		l4_address_split(s_aM1->addr,&shost,&sport);
	do {
		if (d_aM1 == NULL || (d_aM1->score >= avgscore && !unref)) {
			loop=FALSE;
			d_aM1=NULL;
		} else {
			l4_address_split(d_aM1->addr,&dhost,&dport);
	
			gchar **urls = meta0_utils_array_get_urlv(context->array_meta1_by_prefix , prefix);	
			if ( urls ) {
				len = g_strv_length(urls);
				for ( i=0;i < len ; i++) {
					if ( s_aM1 && g_ascii_strncasecmp(urls[i],s_aM1->addr,strlen(s_aM1->addr))==0) {
						continue; //meta1 to replace
					}
					if ( g_ascii_strncasecmp(urls[i],d_aM1->addr,strlen(d_aM1->addr))==0 ) {
						loop=TRUE;
						break;  // meta1 manage this prefix, not OK
					}
					if (l4_address_split(urls[i],&host,&port)) {
						if (g_ascii_strncasecmp(host,dhost,strlen(dhost)) == 0 && ( shost==NULL || g_ascii_strncasecmp(host,shost,strlen(shost)) != 0)){
							if (!force) {
							//nouveau meta1 host identique a un host deja present
							//meta1 remplace a un host different , on fait pire au niveau localisation
								loop=TRUE;
								break;
							}
						}
						loop=FALSE;
						if( host) {
							g_free(host);
							host=NULL;
						}
						if( port) {
							g_free(port);
							port=NULL;
						}
					}
				}
				g_strfreev(urls);
			} else {
				// New Init select this meta1
				loop=FALSE;
			}

			if (loop==TRUE) {
				lst = g_list_previous(lst);
				if ( lst != NULL ) {
					d_aM1 = lst->data;
				} else {
					d_aM1=NULL;
				}
			}
		}
		if( dhost) {
			g_free(dhost);
			dhost=NULL;
		}
		if( host) {
			g_free(host);
			host=NULL;
		}
		if( dport) {
			g_free(dport);
			dport=NULL;
		}
		if( port) {
			g_free(port);
			port=NULL;
		}

	} while (loop==TRUE);
	if( shost) {
		g_free(shost);
		shost=NULL;
	}
	if( sport) {
		g_free(sport);
		sport=NULL;
	}

	if (d_aM1) {
		GRID_TRACE("select meta1 dest %s, score %d",d_aM1->addr,d_aM1->score);
	} else {
		GRID_TRACE("NO meta1 dest found");
	}
	return d_aM1;

}

static void
_remove_first_prefix_to_assign_meta1(struct meta0_assign_meta1_s *aM1)
{

	GArray *prefixes = aM1->assignPrefixes;
	if (prefixes->len > 0 ) 
		prefixes=g_array_remove_index(prefixes,0);


	if (prefixes->len == 0 ) {
		aM1->available=FALSE;
		aM1->assignPrefixes=NULL;
	}
}

static guint8*
_get_first_prefix_to_assign_meta1(struct meta0_assign_meta1_s *aM1)
{
	GArray *prefixes = aM1->assignPrefixes;
	if (prefixes) {
		if (prefixes->len > 0 )
			return (guint8 *)&g_array_index (prefixes, guint8, 0);			
	}
	return NULL;
}


static void
_increase_score(struct meta0_assign_meta1_s *aM1)
{
	aM1->score++;

}

static void
_decrease_score(struct meta0_assign_meta1_s *aM1)
{
	aM1->score--;
	if ( aM1->score <= context->avgscore )
		aM1->available=FALSE;
}

static void
_replace(struct meta0_assign_meta1_s *s_aM1, struct meta0_assign_meta1_s *d_aM1)
{
	guint8 *prefix = (guint8 *)(s_aM1->assignPrefixes)->data;
	if(meta0_utils_array_replace(context->array_meta1_by_prefix,prefix,s_aM1->addr,d_aM1->addr))
	{
		_treat_prefix(context->treat_prefixes,prefix);

		_remove_first_prefix_to_assign_meta1(s_aM1);
		_decrease_score(s_aM1);

		_increase_score(d_aM1);

	}

}

static GPtrArray*
_updated_meta1ref() {
	
	GPtrArray *array = _meta1ref_map_to_array(context->working_map_meta1_ref);

	return array;
}

static GError*
_assign(GList *working_m1list,GSList *unref_m1list)
{
	GError *error = NULL;
	guint nb_treat_prefixes=0;
	struct meta0_assign_meta1_s *s_aM1, *d_aM1;
	//unref meta1
	if ( unref_m1list ) {
		for (;unref_m1list;unref_m1list=unref_m1list->next) {
			s_aM1=unref_m1list->data;
			guint8 *prefix=_get_first_prefix_to_assign_meta1(s_aM1);
			if (!s_aM1->assignPrefixes)
				continue;
			do {
				if(_is_treat_prefix(context->treat_prefixes,prefix)) {
					GRID_ERROR("prefix [%02X%02X] already treat",prefix[0],prefix[1]);
					error=g_error_new(gquark_log,0, "Failed to remove Meta1 service"); 
				}
				d_aM1 =_select_dest_assign_m1(working_m1list,s_aM1,NULL,TRUE,FALSE);
				if ( ! d_aM1 ) {
					d_aM1 =_select_dest_assign_m1(working_m1list,s_aM1,NULL,TRUE,TRUE);
					if ( ! d_aM1 ) {
						error=g_error_new(gquark_log,0, "Failed to assign prefix from meta1 %s",s_aM1->addr);
						return error;
					}
				}
				_replace(s_aM1,d_aM1);
				nb_treat_prefixes++;

			} while ( s_aM1->assignPrefixes);
		}
	}


	gboolean loop = TRUE;

	do {
		s_aM1=NULL;
		d_aM1=NULL;
		// sort meta1 list
		working_m1list=g_list_sort(working_m1list,meta0_assign_sort_by_score);

		// election high meta1 and prefix
		s_aM1 = _select_source_assign_m1(working_m1list,context->treat_prefixes,context->avgscore);

		if (s_aM1) {
			d_aM1 =_select_dest_assign_m1(working_m1list,s_aM1,NULL,FALSE,FALSE);

			if ( d_aM1 ) {
				_replace(s_aM1,d_aM1);
				nb_treat_prefixes++;
			} else {
				_remove_first_prefix_to_assign_meta1(s_aM1);
			}
		} else {
			loop = FALSE;
		}

		if ( nb_treat_prefixes == 65536 )
			loop = FALSE;

	} while (loop==TRUE);

	GRID_TRACE("END Assign prefix,nb treat=%d",nb_treat_prefixes);
	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

static GError *
_init_assign(gchar *ns_name, GList **working_m1list,GSList **unref_m1list)
{ 
	GError *error = NULL;
	GSList *m1_list = NULL;

	m1_list = list_namespace_services(ns_name, "meta1", &error);
	if (!m1_list) {
		if ( error) {
			GRID_ERROR("failed to init meta1 service list :(%d) %s", error->code, error->message);
			goto errorLabel;
		}
	}
	GRID_INFO("nb m1 cs %d",g_slist_length(m1_list));
	if ( context->replica > g_slist_length(m1_list)) {
		GRID_ERROR("Number of meta1 services [%d] less than number of replication [%d]",g_slist_length(m1_list),context->replica);
		error = g_error_new(gquark_log,EINVAL, "Number of meta1 services [%d] less than number of replication [%d]",g_slist_length(m1_list),context->replica);
		goto errorLabel;
	}
	if ( context->replica <= 0 ) {
		GRID_ERROR("Invalid replica number [%d]",context->replica);
		error = g_error_new(gquark_log,EINVAL, "Invalid replica number [%d]",context->replica);
		goto errorLabel;
	}
	
	// Duplicate the current prefix distribution and build a List
	GSList *prefixByMeta1 = meta0_utils_array_to_list(context->array_meta1_by_prefix);

	GSList *l=NULL;
	for (;m1_list;m1_list=m1_list->next) {

		struct meta0_assign_meta1_s *aM1;
		struct service_info_s *sInfo;
		gchar url[128];
                url[0] = '\0';

		aM1 = g_malloc0(sizeof(struct meta0_assign_meta1_s));

		sInfo=m1_list->data;

                grid_addrinfo_to_string(&(sInfo->addr), url, sizeof(url));
		aM1->addr=g_strdup(url);
		aM1->score=0;
		aM1->available=FALSE;
		aM1->used=TRUE;

		l = prefixByMeta1;
		for (;l;l=l->next) {
			struct meta0_info_s *m0info;
			if (!(m0info = l->data))
				continue;
			if (addr_info_equal(&(m0info->addr),&(sInfo->addr))) {
				guint16 *p, *max;
				guint i=0;
				GArray *pfx = g_array_new(FALSE, FALSE, 2);
				p = (guint16*) m0info->prefixes;
				max = (guint16*) (m0info->prefixes + m0info->prefixes_size);
				for (; p<max; p++) {
					i++;
					pfx=g_array_append_vals(pfx,(guint8*)p,1);
				}
				aM1->assignPrefixes=pfx;
				aM1->score=i;
				GRID_DEBUG("aM1 %s , score %d",aM1->addr,aM1->score);
				prefixByMeta1=g_slist_remove(prefixByMeta1,m0info);
				meta0_info_clean(m0info);

				break;
			}
		}
		struct meta0_assign_meta1_s *m1ref = g_hash_table_lookup(context->map_meta1_ref,aM1->addr);

		if ( m1ref && !m1ref->used) {
			// unref meta1
			aM1->used=FALSE;
			if (aM1->score != 0 ) {
				// meta1 refer always prefixe
				*unref_m1list=g_slist_prepend(*unref_m1list,aM1);
			}
		} else {
			*working_m1list = g_list_prepend(*working_m1list,aM1);
		}
		g_hash_table_insert(context->working_map_meta1_ref,strdup(aM1->addr),aM1);
	}
	
	GRID_TRACE("len working %d, len reste pref %d",g_list_length(*working_m1list),g_slist_length(prefixByMeta1));
	guint nb_M1 = g_list_length(*working_m1list) + g_slist_length(prefixByMeta1);

	//defined the average assign score
	if (nb_M1 == 0 ) {
		GRID_ERROR("No Meta1 available");
		error = g_error_new(gquark_log,0, "No Meta1 service available");
		goto errorLabel;
	}


	context->avgscore = (65536* context->replica)/nb_M1; 
	GRID_DEBUG("average meta1 score %d",context->avgscore);

	GList *work = g_list_first(*working_m1list);
	for (;work;work=work->next) {
		struct meta0_assign_meta1_s *aM1 = work->data;
		if ( aM1->score > context->avgscore) {
		 	aM1->available=TRUE;
		}
	}

	GRID_DEBUG("init meta1 list, find %d meta1",g_list_length(*working_m1list));
	GRID_DEBUG("init unref meta1 list, find %d meta1",g_slist_length(*unref_m1list));

	meta0_utils_list_clean(prefixByMeta1);

errorLabel :
	if (m1_list) {
                g_slist_foreach(m1_list, service_info_gclean, NULL);
                g_slist_free(m1_list);
        }

	return error;
}

static GError*
_unref_meta1(gchar **urls)
{

	GError *error = NULL;
	GSList *prefixByMeta1 = meta0_utils_array_to_list(context->array_meta1_by_prefix);
	guint8 *prefix_mask = g_malloc0(8192);

	for(;*urls;urls++) {
		addr_info_t addr;
		GRID_DEBUG("unref url %s",*urls);

		grid_string_to_addrinfo(*urls,NULL,&addr);

		GSList *l=prefixByMeta1;
		for (;l;l=l->next) {
                        struct meta0_info_s *m0info;
                        if (!(m0info = l->data))
                                continue;	

			if (addr_info_equal(&(m0info->addr),&addr)) {

				guint16 *p, *max;
                                p = (guint16*) m0info->prefixes;
                                max = (guint16*) (m0info->prefixes + m0info->prefixes_size);
                                for (; p<max; p++) {
					if (_is_treat_prefix(prefix_mask,(guint8*)p) ) {
						GRID_WARN("prefix %02X%02X manage by two meta1 present in the request",((guint8*)p)[0],((guint8*)p)[1]);
						error = g_error_new(gquark_log,0, "prefix %02X%02X manage by two meta1 present in the request",((guint8*)p)[0],((guint8*)p)[1]);
						goto errorLabel;
					}
					_treat_prefix(prefix_mask,(guint8*)p);
                                }
			}
		}
		struct meta0_assign_meta1_s *aM1=NULL;

		aM1=g_hash_table_lookup(context->map_meta1_ref,*urls);
		if( !aM1) {
			aM1 = g_malloc0(sizeof(struct meta0_assign_meta1_s));

			aM1->addr=g_strdup(*urls);
			aM1->score=0;
			aM1->used=FALSE;

			g_hash_table_insert(context->map_meta1_ref,strdup(*urls),aM1);
		} else {
			aM1->used=FALSE;
		}
	}

errorLabel :
	meta0_utils_list_clean(prefixByMeta1);
	g_free(prefix_mask);

	return error;
}


static GError*
_check(GList *working_m1list) {
	GError *error = NULL;

	if ( working_m1list ) {

		working_m1list=g_list_sort(working_m1list,meta0_assign_sort_by_score);
		struct meta0_assign_meta1_s *hM1 = working_m1list->data;
		struct meta0_assign_meta1_s *lM1 = (g_list_last(working_m1list))->data;
		guint highscore = hM1->score;
		guint lowscore = lM1->score;
		GRID_TRACE("check delta highscore %d ,lowscore %d",highscore,lowscore);
		if ( (highscore - lowscore) < (context->avgscore * trigger_assignment )/ 100  ) {
			GRID_WARN("New assign not necessary, high score %d , low score %d, average %d", highscore, lowscore, context->avgscore);
			error = g_error_new(gquark_log,0, "New assign not necessary");
			return error;
		}
	}

	if ( context->lastAssignTime ) {
		GRID_TRACE("last time %s",g_date_time_format (context->lastAssignTime,"%Y-%m-%d %H:%M"));
		GDateTime *currentTime, *ltime;
		currentTime=g_date_time_new_now_local();
		ltime = g_date_time_add_minutes(context->lastAssignTime,period_between_two_assign);
		GRID_TRACE("currentTime :%s , last time + %d min :%s, comp :%d",g_date_time_format (currentTime,"%Y-%m-%d %H:%M"),period_between_two_assign,g_date_time_format (ltime,"%Y-%m-%d %H:%M"), g_date_time_compare(ltime,currentTime));
		if (g_date_time_compare(ltime,currentTime) > 0 ) {
			GRID_WARN("delay between two meta1 assign  not respected. Try later. last date [%s]",g_date_time_format (context->lastAssignTime,"%Y-%m-%d %H:%M"));
			error = g_error_new(gquark_log,0,"delay between two meta1 assign  not respected. Try later.");
			return error;
		}
	}

	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

static void 
_resetContext() {

	if (context->working_map_meta1_ref) {
		g_hash_table_destroy(context->working_map_meta1_ref);
		context->working_map_meta1_ref=NULL;
	}
	if (context->array_meta1_by_prefix) {
		meta0_utils_array_clean(context->array_meta1_by_prefix);
		context->array_meta1_by_prefix=NULL;
	}

	if (context->map_meta1_ref) {
		g_hash_table_destroy(context->map_meta1_ref);
		context->map_meta1_ref=NULL;
	}


	if (context->treat_prefixes) {
		g_free(context->treat_prefixes);
		context->treat_prefixes=NULL;
	}
	
	context->replica=0;  context->avgscore=0;
}

static GError* 
_initContext(struct meta0_backend_s *m0) {
	GError * error;

	if ( !context ) {
		context = g_malloc0(sizeof(struct meta0_assign_context_s));
	} else {
		_resetContext();
	}

	error = meta0_backend_get_all(m0,&(context->array_meta1_by_prefix));
	if ( error ) {
		GRID_ERROR("failed to duplicate current prefix distribution :(%d) %s", error->code, error->message);
		return error;
        }

	GPtrArray *meta1_ref;
	error = meta0_backend_get_all_meta1_ref(m0,&meta1_ref);
	if ( error ) {
		meta0_utils_array_meta1ref_clean(meta1_ref);
                GRID_ERROR("failed to duplicate current Meta1 reference :(%d) %s", error->code, error->message);
		return error;
        }
	context->map_meta1_ref = _meta1ref_array_to_map(meta1_ref);
	meta0_utils_array_meta1ref_clean(meta1_ref);
	
	context->working_map_meta1_ref=g_hash_table_new_full(g_str_hash, g_str_equal,g_free,_gfree_map_meta0_assign_meta1 );
	
        context->treat_prefixes = g_malloc0(8192);

	context->replica=0;  
	context->avgscore=0;

	if ( context->array_meta1_by_prefix->len > 0) {
		gchar **v =context->array_meta1_by_prefix->pdata[0];
		if ( v != NULL ) {
			for (; *v ;v++)
				context->replica++;
			if ( context->replica > 65536) {
				return g_error_new(gquark_log,EINVAL, "Invalid nb replica [%d]",context->replica);
        		}
		}
		GRID_DEBUG("replica %d",context->replica);
	}
	return NULL;
}

/* ----------------------------------------------------------------------------------------*/

GError*
meta0_assign_fill(struct meta0_backend_s *m0, gchar *ns_name, guint replicas,
		gboolean nodist)
{
	GError *error;
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GPtrArray *new_meta1ref = NULL;
	guint idx;
	struct meta0_assign_meta1_s *d_aM1;

	if (!gquark_log)
                gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_INFO("START fill meta0 db , replica %d",replicas);

	error = _initContext(m0);
	if (error) {
		goto errorLabel;
	}
	context->replica=replicas;

	error = _init_assign(ns_name,&working_m1list,&unref_m1list);
	if ( error ) {
		goto errorLabel;
	}

	error =_check(NULL);
	if ( error ) {
		goto errorLabel;
        }

	while (replicas--) {
		for (idx=0; idx<65536 ;idx++) {
			working_m1list=g_list_sort(working_m1list,meta0_assign_sort_by_score);
			d_aM1 =_select_dest_assign_m1(working_m1list,NULL,(guint8*)(&idx),TRUE, nodist);
                        if ( ! d_aM1 ) {
				error=g_error_new(gquark_log,0, "Failed to assign prefix %d to meta1",idx);
			        goto errorLabel;
                        }

			meta0_utils_array_add(context->array_meta1_by_prefix,(guint8*)(&idx),d_aM1->addr);

        	        _increase_score(d_aM1);
		}
	}

	new_meta1ref = _updated_meta1ref();
	error = meta0_backend_assign(m0, context->array_meta1_by_prefix, new_meta1ref,TRUE);
	if ( error ) {
                GRID_ERROR("failed to update BDD :(%d) %s", error->code, error->message);
		goto errorLabel;
        }

	context->lastAssignTime=g_date_time_new_now_local();

errorLabel :
	_resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
	if (working_m1list) {
                g_list_free(working_m1list);
		working_m1list=NULL;
	}
	if (unref_m1list) {
		g_slist_free(unref_m1list);
		unref_m1list=NULL;
	}
	GRID_INFO("END FILL");
	
	return error;
}


GError*
meta0_assign_prefix_to_meta1(struct meta0_backend_s *m0, gchar *ns_name, gboolean nocheck)
{
	// GET meta1 list from conscience
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GError *error;
	GPtrArray *new_meta1ref = NULL;
	
	if (!gquark_log)
                gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_INFO("START Assign prefix");

	error = _initContext(m0);
	if (error) {
		goto errorLabel;
	}


	// build working list , list sorted by score
	error = _init_assign(ns_name,&working_m1list,&unref_m1list);
	if ( error ) {
		goto errorLabel;
	}
	if ( nocheck ) {
		error =_check(working_m1list);
		if ( error ) {
			goto errorLabel;
        	}
	}
	
	error = _assign(working_m1list,unref_m1list);	
	if ( error ) {
		goto errorLabel;
        }

	new_meta1ref = _updated_meta1ref();
	error = meta0_backend_assign(m0, context->array_meta1_by_prefix, new_meta1ref,FALSE);
	if ( error ) {
                GRID_ERROR("failed to update BDD :(%d) %s", error->code, error->message);
		goto errorLabel;
        }
	context->lastAssignTime=g_date_time_new_now_local();

errorLabel :
	_resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
	if (working_m1list) {
                g_list_free(working_m1list);
		working_m1list=NULL;
	}
	if (unref_m1list) {
		g_slist_free(unref_m1list);
		unref_m1list=NULL;
	}
	GRID_INFO("END ASSIGN");

	return error;

}

GError*
meta0_assign_disable_meta1(struct meta0_backend_s *m0, gchar *ns_name, char **m1urls, gboolean nocheck)
{
	GList *working_m1list = NULL;
	GSList *unref_m1list = NULL;
	GPtrArray *new_meta1ref = NULL;
	GError *error;
	
	if (!gquark_log)
                gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	gchar * urls = g_strjoinv(" ",m1urls);
	GRID_INFO("START disable meta1 %s",urls);
	g_free(urls);

	error = _initContext(m0);
	if (error) {
		goto errorLabel;
	}

	if ( nocheck ) {
		error =_check(NULL);
		if ( error ) {
			goto errorLabel;
        	}
	}

	error =_unref_meta1(m1urls);
	if ( error ) {
                goto errorLabel;
        }

	error = _init_assign(ns_name,&working_m1list,&unref_m1list);
	if ( error ) {
		goto errorLabel;
	}
	
	error = _assign(working_m1list,unref_m1list);
	if ( error ) {
		goto errorLabel;
	}

	new_meta1ref = _updated_meta1ref();
        error = meta0_backend_assign(m0, context->array_meta1_by_prefix, new_meta1ref ,FALSE);
        if ( error ) {
                GRID_ERROR("failed to update BDD :(%d) %s", error->code, error->message);
                goto errorLabel;
        }

	context->lastAssignTime=g_date_time_new_now_local();

errorLabel :
        _resetContext();
	if (new_meta1ref) {
		meta0_utils_array_meta1ref_clean(new_meta1ref);
	}
        if (working_m1list) {
		g_list_free(working_m1list);
                working_m1list=NULL;
        }
        if (unref_m1list) {
		g_slist_free(unref_m1list);
                unref_m1list=NULL;
        }
	GRID_INFO("END DISABLE META1");

        return error;

}


