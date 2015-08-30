/*
OpenIO SDS metautils
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <search.h>

#include <metautils/metautils.h>

#include "srvset.h"

typedef struct service_info_s *SRV;
typedef SRV *PSRV;

struct srvset_s
{
    GPtrArray *services;
    gboolean must_sort:1;
    gboolean sorted:1;
};

static gint
_cmp (SRV s0, SRV s1)
{
    return strcmp (s0->type, s1->type) ? : addr_info_compare (&s0->addr,
        &s1->addr);
}

static gint
_pcmp (PSRV p0, PSRV p1)
{
    return _cmp (*p0, *p1);
}

typedef int (*cmp_f) (const void *p0, const void *p1);

static SRV
_get (srvset_t * ss, guint i)
{
    return ss->services->pdata[i];
}

static void
_sort (srvset_t * ss)
{
    g_ptr_array_sort (ss->services, (GCompareFunc) _pcmp);
    ss->sorted = 1;
}

static gboolean
_init (SRV si, const char *k)
{
    gchar *srvtype = g_strdup (k);
    STRING_STACKIFY (srvtype);
    gchar *straddr = strchr (srvtype, '|');
    if (!straddr)
        return FALSE;
    *(straddr++) = '\0';
    g_strlcpy (si->type, srvtype, sizeof (si->type));
    return grid_string_to_addrinfo (straddr, &si->addr);
}

srvset_t *
srvset_new (void)
{
    srvset_t *self = g_malloc0 (sizeof (*self));
    self->services = g_ptr_array_new ();
    return self;
}

void
srvset_clean (srvset_t * ss)
{
    if (!ss)
        return;
    for (guint i = 0; i < ss->services->len; ++i)
        service_info_clean (_get (ss, i));
    g_ptr_array_free (ss->services, TRUE);
    g_free (ss);
}

void
srvset_purge (srvset_t * ss, time_t pivot)
{
    guint pre = ss->services->len;
    for (guint i = 0; i < ss->services->len; ++i) {
        SRV si = _get (ss, i);

        if (si->score.timestamp && si->score.timestamp <= pivot) {
            ss->services->pdata[i] = NULL;
            g_ptr_array_remove_index_fast (ss->services, i);
            i--;
        }
    }
    if (pre != ss->services->len)
        ss->sorted = 0;
}

void
srvset_purge_type (srvset_t * ss, const char *type)
{
    guint pre = ss->services->len;
    for (guint i = 0; i < ss->services->len; ++i) {
        SRV si = _get (ss, i);
		if (!strcmp(si->type, type)) {
            ss->services->pdata[i] = NULL;
            g_ptr_array_remove_index_fast (ss->services, i);
            i--;
        }
    }
    if (pre != ss->services->len)
        ss->sorted = 0;
}

static PSRV
_plocate (srvset_t * ss, SRV si0)
{
    if (ss->must_sort && !ss->sorted)
        _sort (ss);
    PSRV pret;
    size_t len = ss->services->len;

    if (ss->sorted)             // binary search
        pret =
            bsearch (&si0, ss->services->pdata, len, sizeof (void *),
            (cmp_f) & _pcmp);
    else                        // linear search
        pret =
            lfind (&si0, ss->services->pdata, &len, sizeof (void *),
            (cmp_f) & _pcmp);
    if (pret) {
        g_assert (NULL != *pret);
        g_assert (!strcmp ((*pret)->type, si0->type));
        g_assert (!memcmp (&(*pret)->addr, &si0->addr, sizeof (addr_info_t)));
    }
    return pret;
}

static SRV
_locate (srvset_t * ss, SRV si0)
{
    PSRV pret = _plocate (ss, si0);
    return pret ? *pret : NULL;
}

SRV
srvset_get (srvset_t * ss, const char *k)
{
    struct service_info_s tmp;
    memset (&tmp, 0, sizeof (tmp));
    return _init (&tmp, k) ? _locate (ss, &tmp) : NULL;
}

SRV
srvset_get_iso (srvset_t * ss, SRV si)
{
    return _locate (ss, si);
}

static void
_del (srvset_t * ss, SRV si0)
{
    PSRV pret = _plocate (ss, si0);
    if (!pret)
        return;
    int i = (void **) pret - (void **) ss->services->pdata;
    g_assert (i >= 0 && (guint) i < ss->services->len);
    service_info_clean (*pret);
    *pret = NULL;
    pret = NULL;

    ss->services->pdata[i] = NULL;
    g_ptr_array_remove_index_fast (ss->services, i);
    if ((guint) i != ss->services->len)
        ss->sorted = 0;
}

void
srvset_delete (srvset_t * ss, const char *k)
{
    struct service_info_s tmp;
    memset (&tmp, 0, sizeof (tmp));
    if (_init (&tmp, k))
        return _del (ss, &tmp);
}

void
srvset_delete_iso (srvset_t * ss, struct service_info_s *si)
{
    return _del (ss, si);
}

static guint
srvset_runv (srvset_t * ss, gchar ** tv, void (*cb) (SRV))
{
    gboolean _has (const char *t) {
        for (gchar ** p = tv; *p; ++p)
            if (!strcmp (*p, t))
                return TRUE;
        return FALSE;
    }
    guint count = 0;
    for (guint i = 0; i < ss->services->len; ++i) {
        SRV si = _get (ss, i);

        if ((!tv || _has (si->type))) {
            if (cb)
                cb (si);
            ++count;
        }
    }
    return count;
}

gboolean
srvset_has (srvset_t * ss, const char *k)
{
    return NULL != srvset_get (ss, k);
}

guint
srvset_run (srvset_t * ss, const char *ts, void (*cb) (SRV))
{
    if (!ts || !*ts)
        return srvset_runv (ss, NULL, cb);
    gchar **tv = g_strsplit (ts, ",", 0);
    STRINGV_STACKIFY (tv);
    return srvset_runv (ss, tv, cb);
}

struct service_info_s *
srvset_push_and_clean (srvset_t * ss, struct service_info_s *si)
{
    PSRV pret = _plocate (ss, si);
    if (!pret) {
        g_ptr_array_add (ss->services, si);
        ss->sorted = 0;
        return ss->services->pdata[ss->services->len - 1];
    } else {
        memcpy (&(*pret)->addr, &si->addr, sizeof (addr_info_t));
        service_info_merge_tags (*pret, si);
        return *pret;
    }
}

guint
srvset_count (srvset_t * ss)
{
    return ss->services->len;
}

void
srvset_steal (srvset_t * ss)
{
    g_ptr_array_set_size (ss->services, 0);
}

