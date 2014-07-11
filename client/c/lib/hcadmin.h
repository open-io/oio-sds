#ifndef __HC_ADMIN__H__
#define __HC_ADMIN__H__

gs_error_t * hcadmin_meta1_policy_update(char *ns, gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args);
gs_error_t * hcadmin_touch(              char *url,gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args);






#endif /* __HC_ADMIN__H__ */

