#ifndef __{{module_name}}_REMOTE_H__
# define __{{module_name}}_REMOTE_H__

{{FOREACH f IN module_functions}}
/**
 * AUTO-GENERATED!
 * DO NOT EDIT THIS DIRECTLY, IT WILL BE OVERWRITTEN
 */
{{f.return.type}} {{f.prefix}}_remote_{{f.name}}(struct metacnx_ctx_s *ctx, {{FOREACH arg IN f.args}}{{arg.type}} {{IF arg.is_out}}*{{END}}{{arg.local_name}}, {{END}}GError **err);

{{END}}

#endif /*__{{module_name}}_REMOTE_H__*/

