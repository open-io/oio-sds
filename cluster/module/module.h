/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__cluster__module__module_h
# define OIO_SDS__cluster__module__module_h 1

#if 0
// FIXME dead code
# define NAME_MSGNAME_CS_GETNS  "REQ_CS_GETNS"
#endif

# define NAME_MSGNAME_CS_GET_NSINFO   "CS_CFG"
# define NAME_MSGNAME_CS_GET_SRVNAMES "CS_TYP"
# define NAME_MSGNAME_CS_GET_SRV      "CS_SRV"
# define NAME_MSGNAME_CS_PUSH_SRV     "CS_PSH"
# define NAME_MSGNAME_CS_RM_SRV       "CS_DEL"

# define NAME_GROUPNAME_STORAGE_POLICY		"STORAGE_POLICY"
# define NAME_GROUPNAME_DATA_SECURITY		"DATA_SECURITY"
# define NAME_GROUPNAME_DATA_TREATMENTS		"DATA_TREATMENTS"
# define NAME_GROUPNAME_STORAGE_CLASS		"STORAGE_CLASS"
# define STG_CONF_STR_MAX_LENGTH			50

# define KEY_NAMESPACE "namespace"
# define KEY_CHUNK_SIZE "chunk_size"
# define KEY_ALERT_LIMIT "alert_frequency_limit"
# define KEY_META0 "meta0"
# define KEY_SCORE_TIMEOUT "score_timeout"
# define KEY_SCORE_EXPR "score_expr"
# define KEY_STG_CONF "storage_conf"
# define KEY_SCORE_VARBOUND "score_variation_bound"

# define KEY_SERIALIZE_SRVINFO_CACHED "serialize_srvinfo_cache"
# define DEF_SERIALIZE_SRVINFO_CACHED FALSE

# define KEY_SERIALIZE_SRVINFO_TAGS   "serialize_srvinfo_tags"
# define DEF_SERIALIZE_SRVINFO_TAGS   TRUE

# define KEY_SERIALIZE_SRVINFO_STATS  "serialize_srvinfo_stats"
# define DEF_SERIALIZE_SRVINFO_STATS  FALSE

# define DOMAIN_PERIODIC "conscience.dump"

# define TIME_DEFAULT_ALERT_LIMIT 300L

# define EXPR_DEFAULT_META0 "100"
# define EXPR_DEFAULT_META1 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_META2 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_RAWX  "root(3,((num stat.cpu)*(num stat.io)*(num stat.space)))"

# define NB_BROKEN_LINES 64U
# define NB_SRV_ELEMENTS 128U

#endif /*OIO_SDS__cluster__module__module_h*/
