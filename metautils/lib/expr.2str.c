#include "expr.h"

static char *__tab[NB_ET] = {
	"VAL_STR_ET",
	"VAL_NUM_ET",
	"UN_NUMSUP_ET",
	"UN_NUMINF_ET",
	"UN_NUMNOT_ET",
	"UN_STRNUM_ET",
	"UN_STRLEN_ET",
	"BIN_STRCMP_ET",
	"BIN_NUMCMP_ET",
	"BIN_NUMEQ_ET",
	"BIN_NUMNEQ_ET",
	"BIN_NUMLT_ET",
	"BIN_NUMLE_ET",
	"BIN_NUMGT_ET",
	"BIN_NUMGE_ET",
	"BIN_NUMADD_ET",
	"BIN_NUMSUB_ET",
	"BIN_NUMMUL_ET",
	"BIN_NUMDIV_ET",
	"BIN_NUMMOD_ET",
	"BIN_NUMAND_ET",
	"BIN_NUMXOR_ET",
	"BIN_NUMOR_ET",
	"ACC_ET"
};

const char *
expr_type2str(enum expr_type_e t)
{
	if (t >= NB_ET)
		return "INVALID_TYPE";

	return __tab[t];
}
