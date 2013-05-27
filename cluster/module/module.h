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

#ifndef __GCLUSTER_CONSCIENCE_MODULE_H__
# define __GCLUSTER_CONSCIENCE_MODULE_H__

# define NAME_MSGNAME_CS_GETNS  "REQ_CS_GETNS"
# define NAME_MSGNAME_CS_GET_NSINFO "REQ_CS_GET_NSINFO"
# define NAME_MSGNAME_CS_GETVOL "REQ_CS_GETVOL"
# define NAME_MSGNAME_CS_GETM0  "REQ_CS_GETM0"
# define NAME_MSGNAME_CS_GETM1  "REQ_CS_GETM1"
# define NAME_MSGNAME_CS_GETM2  "REQ_CS_GETM2"
# define NAME_MSGNAME_CS_PUSH_VOLSTAT "REQ_CS_PUSH_VOLSTAT"
# define NAME_MSGNAME_CS_PUSH_M1STAT  "REQ_CS_PUSH_M1STAT"
# define NAME_MSGNAME_CS_PUSH_M2STAT  "REQ_CS_PUSH_M2STAT"
# define NAME_MSGNAME_CS_RMVOL  "REQ_CS_RMVOL"
# define NAME_MSGNAME_CS_RMM1   "REQ_CS_RMM1"
# define NAME_MSGNAME_CS_RMM2   "REQ_CS_RMM2"
# define NAME_MSGNAME_CS_PUSH_VOLSCORE "REQ_CS_PUSH_VOLSCORE"
# define NAME_MSGNAME_CS_PUSH_M2SCORE  "REQ_CS_PUSH_M2SCORE"

# define NAME_MSGNAME_CS_PUSH_BROKEN_CONT "REQ_PUSH_BROKEN_CONT"
# define NAME_MSGNAME_CS_GET_BROKEN_CONT  "REQ_GET_BROKEN_CONT"
# define NAME_MSGNAME_CS_RM_BROKEN_CONT   "REQ_RM_BROKEN_CONT"
# define NAME_MSGNAME_CS_FIX_BROKEN_CONT  "REQ_FIX_BROKEN_CONT"

# define NAME_MSGNAME_CS_PUSH_VNS_SPACE_USED "REQ_PUSH_VNS_SPACE_USED"

# define NAME_MSGNAME_CS_GET_SRVNAMES "REQ_GET_SRVNAMES"
# define NAME_MSGNAME_CS_GET_SRV      "REQ_GET_SRV"
# define NAME_MSGNAME_CS_PUSH_SRV     "REQ_PUSH_SRV"
# define NAME_MSGNAME_CS_RM_SRV       "REQ_RM_SRV"

# define NAME_MSGNAME_CS_GET_EVENT_CONFIG "REQ_EVENT_CONFIG"

# define NAME_GROUPNAME_STORAGE_POLICY		"STORAGE_POLICY"
# define NAME_GROUPNAME_DATA_SECURITY		"DATA_SECURITY"
# define NAME_GROUPNAME_DATA_TREATMENTS		"DATA_TREATMENTS"
# define STG_CONF_STR_MAX_LENGTH			50

# define KEY_NAMESPACE "namespace"
# define KEY_CHUNK_SIZE "chunk_size"
# define KEY_ALERT_LIMIT "alert_frequency_limit"
# define KEY_META0 "meta0"
# define KEY_SCORE_TIMEOUT "score_timeout"
# define KEY_SCORE_EXPR "score_expr"
# define KEY_EVENT_HANDLERS "events"
# define KEY_STG_CONF "storage_conf"
# define KEY_SCORE_VARBOUND "score_variation_bound"

# define KEY_SERIALIZE_SRVINFO_CACHED "serialize_srvinfo_cache"
# define DEF_SERIALIZE_SRVINFO_CACHED FALSE

# define KEY_SERIALIZE_SRVINFO_TAGS   "serialize_srvinfo_tags"
# define DEF_SERIALIZE_SRVINFO_TAGS   TRUE

# define KEY_SERIALIZE_SRVINFO_STATS  "serialize_srvinfo_stats"
# define DEF_SERIALIZE_SRVINFO_STATS  FALSE

#define KEY_VNS_LIST "vns_list"
#define KEY_WRITABLE_VNS "writable_vns"

# define DOMAIN_PERIODIC "conscience.dump"

# define TIME_DEFAULT_ALERT_LIMIT 300L

# define EXPR_DEFAULT_META0 "100"
# define EXPR_DEFAULT_META1 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_META2 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_RAWX  "root(3,((num stat.cpu)*(num stat.io)*(num stat.space)))"
# define EXPR_DEFAULT_INDX  "num stat.cpu"

# define NB_BROKEN_LINES 64U
# define NB_SRV_ELEMENTS 128U

#endif /*__GCLUSTER_CONSCIENCE_MODULE_H__*/
