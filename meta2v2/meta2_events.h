/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__meta2v2__meta2_events_h
# define OIO_SDS__meta2v2__meta2_events_h 1

# ifndef  META2_EVTFIELD_NAMESPACE
#  define META2_EVTFIELD_NAMESPACE "NS"
# endif
# ifndef  META2_EVTFIELD_CNAME
#  define META2_EVTFIELD_CNAME "CNAME"
# endif
# ifndef  META2_EVTFIELD_CPATH
#  define META2_EVTFIELD_CPATH "CPATH"
# endif
# ifndef  META2_EVTFIELD_CID
#  define META2_EVTFIELD_CID GRIDCLUSTER_EVTFIELD_CID
# endif
# ifndef  META2_EVTFIELD_UEID
#  define META2_EVTFIELD_UEID GRIDCLUSTER_EVTFIELD_UEID
# endif
# ifndef  META2_EVTFIELD_AGGRNAME
#  define META2_EVTFIELD_AGGRNAME GRIDCLUSTER_EVTFIELD_AGGRNAME
# endif
# ifndef  META2_EVTFIELD_RAWCONTENT
#  define META2_EVTFIELD_RAWCONTENT "RAW"
# endif
# ifndef  META2_EVTFIELD_RAWCONTENT_V2
#  define META2_EVTFIELD_RAWCONTENT_V2 "RAW.V2"
# endif
# ifndef META2_EVTFIELD_CEVT
#  define META2_EVTFIELD_CEVT "CEVT"
# endif
# ifndef META2_EVTFIELD_CEVTID
#  define META2_EVTFIELD_CEVTID "CEVTID"
# endif
# ifndef META2_EVTFIELD_URL
#  define META2_EVTFIELD_URL "URL"
# endif

# ifndef  META2_EVTTYPE_CREATE
#  define META2_EVTTYPE_CREATE "meta2.CONTAINER.create"
# endif
# ifndef  META2_EVTTYPE_DESTROY
#  define META2_EVTTYPE_DESTROY "meta2.CONTAINER.destroy"
# endif
# ifndef  META2_EVTTYPE_PUT
#  define META2_EVTTYPE_PUT "meta2.CONTENT.put"
# endif
# ifndef  META2_EVTTYPE_DELETE
#  define META2_EVTTYPE_DELETE "meta2.CONTENT.delete"
# endif

# ifndef  META2_EVTTYPE_CONTENT_PROPSET
#  define META2_EVTTYPE_CONTENT_PROPSET "meta2.CONTENT.prop.set"
# endif
# ifndef  META2_EVTTYPE_CONTENT_PROPDEL
#  define META2_EVTTYPE_CONTENT_PROPDEL "meta2.CONTENT.prop.del"
# endif
# ifndef  META2_EVTTYPE_CONTAINER_PROPSET
#  define META2_EVTTYPE_CONTAINER_PROPSET "meta2.CONTAINER.prop.set"
# endif
# ifndef  META2_EVTTYPE_CONTAINER_PROPDEL
#  define META2_EVTTYPE_CONTAINER_PROPDEL "meta2.CONTAINER.prop.del"
# endif
# ifndef  META2_EVTTYPE_CONTAINER_EVTADD
#  define META2_EVTTYPE_CONTAINER_EVTADD "meta2.CONTAINER.evt.add"
# endif
# ifndef  META2_EVTTYPE_CONTAINER_EVTDIFF
#  define META2_EVTTYPE_CONTAINER_EVTDIFF "meta2.CONTAINER.evt.diff"
# endif
# ifndef  META2_EVTTYPE_CONTAINER_EVTRM
#  define META2_EVTTYPE_CONTAINER_EVTRM "meta2.CONTAINER.evt.rm"
# endif

# ifndef META2_EVT_TOPIC
#  define META2_EVT_TOPIC "sds.meta2"
# endif

#endif /*OIO_SDS__meta2v2__meta2_events_h*/
