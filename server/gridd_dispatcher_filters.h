#ifndef GRID__GRIDD_DISPATCHER_FILTERS__H
# define GRID__GRIDD_DISPATCHER_FILTERS__H 1

enum gridd_dispatcher_filter_result_e
{
	FILTER_KO=1,
	FILTER_OK,
	FILTER_DONE,
};

/* Forward declarations */
struct gridd_filter_ctx_s;
struct gridd_reply_ctx_s;

/* Meta2 dispatcher filter definition */
typedef int (*gridd_filter)(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply);

#endif
