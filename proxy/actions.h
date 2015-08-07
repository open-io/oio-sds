/*
OpenIO SDS proxy
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

#ifndef OIO_SDS__proxy__actions_h
# define OIO_SDS__proxy__actions_h 1

// Cache

enum http_rc_e action_cache_status (struct req_args_s *args);
enum http_rc_e action_cache_flush_all (struct req_args_s *args);
enum http_rc_e action_cache_flush_high (struct req_args_s *args);
enum http_rc_e action_cache_flush_low (struct req_args_s *args);
enum http_rc_e action_cache_set_ttl_low (struct req_args_s *args);
enum http_rc_e action_cache_set_ttl_high (struct req_args_s *args);
enum http_rc_e action_cache_set_max_low (struct req_args_s *args);
enum http_rc_e action_cache_set_max_high (struct req_args_s *args);

// Load Balancing

enum http_rc_e action_lb_hash (struct req_args_s *args);
enum http_rc_e action_lb_def (struct req_args_s *args);

// Conscience

enum http_rc_e action_cs_srvtypes (struct req_args_s *args);
enum http_rc_e action_cs_nscheck (struct req_args_s *args);
enum http_rc_e action_cs_info (struct req_args_s *args);
enum http_rc_e action_cs_srvcheck (struct req_args_s *args);
enum http_rc_e action_cs_get (struct req_args_s *args);
enum http_rc_e action_cs_put (struct req_args_s *args);
enum http_rc_e action_cs_del (struct req_args_s *args);
enum http_rc_e action_cs_srv_lock (struct req_args_s *args, struct json_object *jargs);
enum http_rc_e action_cs_srv_unlock (struct req_args_s *args, struct json_object *jargs);
enum http_rc_e action_cs_action (struct req_args_s *args);

// Reference

enum http_rc_e action_ref_create (struct req_args_s *args);
enum http_rc_e action_ref_destroy (struct req_args_s *args);
enum http_rc_e action_ref_show (struct req_args_s *args);
enum http_rc_e action_ref_prop_get (struct req_args_s *args);
enum http_rc_e action_ref_prop_set (struct req_args_s *args);
enum http_rc_e action_ref_prop_del (struct req_args_s *args);
enum http_rc_e action_ref_link (struct req_args_s *args);
enum http_rc_e action_ref_unlink (struct req_args_s *args);
enum http_rc_e action_ref_force (struct req_args_s *args);
enum http_rc_e action_ref_renew (struct req_args_s *args);

// Container

enum http_rc_e action_container_create (struct req_args_s *args);
enum http_rc_e action_container_destroy (struct req_args_s *args);
enum http_rc_e action_container_show (struct req_args_s *args);
enum http_rc_e action_container_list (struct req_args_s *args);
enum http_rc_e action_container_prop_get (struct req_args_s *args);
enum http_rc_e action_container_prop_set (struct req_args_s *args);
enum http_rc_e action_container_prop_del (struct req_args_s *args);
enum http_rc_e action_container_touch (struct req_args_s *args);
enum http_rc_e action_container_dedup (struct req_args_s *args);
enum http_rc_e action_container_purge (struct req_args_s *args);
enum http_rc_e action_container_raw_insert (struct req_args_s *args);
enum http_rc_e action_container_raw_update (struct req_args_s *args);
enum http_rc_e action_container_raw_delete (struct req_args_s *args);

// Content

enum http_rc_e action_content_put (struct req_args_s *args);
enum http_rc_e action_content_delete (struct req_args_s *args);
enum http_rc_e action_content_show (struct req_args_s *args);
enum http_rc_e action_content_prepare (struct req_args_s *args);
enum http_rc_e action_content_prop_get (struct req_args_s *args);
enum http_rc_e action_content_prop_set (struct req_args_s *args);
enum http_rc_e action_content_prop_del (struct req_args_s *args);
enum http_rc_e action_content_touch (struct req_args_s *args);
enum http_rc_e action_content_spare (struct req_args_s *args);
enum http_rc_e action_content_copy (struct req_args_s *args);

// Admin

enum http_rc_e action_admin_ping (struct req_args_s *args);
enum http_rc_e action_admin_status (struct req_args_s *args);
enum http_rc_e action_admin_info (struct req_args_s *args);
enum http_rc_e action_admin_drop_cache (struct req_args_s *args);
enum http_rc_e action_admin_sync (struct req_args_s *args);
enum http_rc_e action_admin_leave (struct req_args_s *args);
enum http_rc_e action_admin_debug (struct req_args_s *args);
enum http_rc_e action_admin_copy (struct req_args_s *args);
enum http_rc_e action_admin_prop_get (struct req_args_s *args);
enum http_rc_e action_admin_prop_set (struct req_args_s *args);
enum http_rc_e action_admin_prop_del (struct req_args_s *args);
enum http_rc_e action_admin_freeze (struct req_args_s *args);
enum http_rc_e action_admin_enable (struct req_args_s *args);
enum http_rc_e action_admin_disable (struct req_args_s *args);


// Deprecated action handlers
// dir

enum http_rc_e action_dir_ref_has (struct req_args_s *args);
enum http_rc_e action_dir_ref_list (struct req_args_s *args);
enum http_rc_e action_dir_ref_create (struct req_args_s *args);
enum http_rc_e action_dir_ref_destroy (struct req_args_s *args);
enum http_rc_e action_dir_ref_action (struct req_args_s *args);
enum http_rc_e action_dir_prop_get (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_prop_set (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_prop_del (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_srv_list (struct req_args_s *args);
enum http_rc_e action_dir_srv_link (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_srv_unlink (struct req_args_s *args);
enum http_rc_e action_dir_srv_force (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_srv_renew (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_dir_srv_action (struct req_args_s *args);
enum http_rc_e action_dir_resolve (struct req_args_s *args);

// m2

enum http_rc_e action_m2_container_create (struct req_args_s *args);
enum http_rc_e action_m2_container_check (struct req_args_s *args);
enum http_rc_e action_m2_container_list (struct req_args_s *args);
enum http_rc_e action_m2_container_destroy (struct req_args_s *args);
enum http_rc_e action_m2_container_purge (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_dedup (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_touch (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_raw_insert (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_raw_update (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_raw_delete (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_propget (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_propset (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_propdel (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_stgpol (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_setvers (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_container_action (struct req_args_s *args);
enum http_rc_e action_m2_content_check (struct req_args_s *args);
enum http_rc_e action_m2_content_get (struct req_args_s *args);
enum http_rc_e action_m2_content_put (struct req_args_s *args);
enum http_rc_e action_m2_content_copy (struct req_args_s *args);
enum http_rc_e action_m2_content_delete (struct req_args_s *args);
enum http_rc_e action_m2_content_beans (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_touch (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_propget (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_propset (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_propdel (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_stgpol (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_spare (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_m2_content_action (struct req_args_s *args);

// sqlx

enum http_rc_e action_sqlx_propget (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_propset (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_propdel (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_leave (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_ping (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_status (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_info (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_leanify (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_resync (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_debug (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_copyto (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_freeze (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_enable (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_disable (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_disable_disabled (struct req_args_s *args, json_object *jargs);
enum http_rc_e action_sqlx_action (struct req_args_s *args);

#endif /*OIO_SDS__proxy__actions_h*/
