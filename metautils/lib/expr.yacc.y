%{
#include <metautils/lib/metautils.h>

#include "expr.h"

static struct expr_s* makeNum (double v);
static struct expr_s* makeStr (char *s);
static struct expr_s* makeUnary (enum expr_type_e e, struct expr_s *pE);
static struct expr_s* makeAccessor (char *pBase, char *pF);
static struct expr_s* makeBinary (enum expr_type_e e, struct expr_s *p1, struct expr_s *p2);

static int yyerror(char *m);
extern void* yy_scan_string(const char *yy_str );
extern void yy_switch_to_buffer(void*);
extern void yy_delete_buffer(void*);
extern int yylex(void);

static struct expr_s *pParsed = NULL;

%}
%union 
{
	double n;
	char* s;
	struct expr_s* e;
}
%token BIN_NUMCMP_TK BIN_NUMEQ_TK BIN_NUMNEQ_TK
%token BIN_NUMLT_TK BIN_NUMLE_TK BIN_NUMGT_TK BIN_NUMGE_TK
%token BIN_NUMADD_TK BIN_NUMSUB_TK BIN_NUMMUL_TK BIN_NUMDIV_TK BIN_NUMMOD_TK
%token BIN_ROOT_TK
%token UN_STRNUM_TK
%token PAROP_TK PARCL_TK DOT_TK COMA_TK
%token <s> ID_TK
%token <s> VAL_STR_TK
%token <n> VAL_NUM_TK
%type  <e> expr

%start input
%%

input: expr { pParsed = $1 ; }

expr:
	  VAL_NUM_TK { $$ = makeNum($1); }
	| VAL_STR_TK { $$ = makeStr($1); }
	| ID_TK DOT_TK ID_TK { $$ = makeAccessor ($1, $3); }
	| PAROP_TK expr PARCL_TK { $$ = $2; }

	| UN_STRNUM_TK expr { $$ = makeUnary (UN_STRNUM_ET,$2); }

	| BIN_ROOT_TK PAROP_TK expr COMA_TK  expr PARCL_TK { $$ = makeBinary (BIN_ROOT_ET,$3,$5); }

	| expr BIN_NUMCMP_TK expr { $$ = makeBinary (BIN_NUMCMP_ET,$1,$3); }
	| expr BIN_NUMEQ_TK expr  { $$ = makeBinary (BIN_NUMEQ_ET,$1,$3); }
	| expr BIN_NUMNEQ_TK expr { $$ = makeBinary (BIN_NUMNEQ_ET,$1,$3); }
	| expr BIN_NUMLT_TK expr  { $$ = makeBinary (BIN_NUMLT_ET,$1,$3); }
	| expr BIN_NUMLE_TK expr  { $$ = makeBinary (BIN_NUMLE_ET,$1,$3); }
	| expr BIN_NUMGT_TK expr  { $$ = makeBinary (BIN_NUMGT_ET,$1,$3); }
	| expr BIN_NUMGE_TK expr  { $$ = makeBinary (BIN_NUMGE_ET,$1,$3); }
	| expr BIN_NUMADD_TK expr { $$ = makeBinary (BIN_NUMADD_ET,$1,$3); }
	| expr BIN_NUMSUB_TK expr { $$ = makeBinary (BIN_NUMSUB_ET,$1,$3); }
	| expr BIN_NUMMUL_TK expr { $$ = makeBinary (BIN_NUMMUL_ET,$1,$3); }
	| expr BIN_NUMDIV_TK expr { $$ = makeBinary (BIN_NUMDIV_ET,$1,$3); }
	| expr BIN_NUMMOD_TK expr { $$ = makeBinary (BIN_NUMMOD_ET,$1,$3); }

	;
%%

static struct expr_s* makeNum (double v) {
	struct expr_s *pRet = g_malloc0(sizeof(struct expr_s));
	pRet->expr.num = v;
	pRet->type = VAL_NUM_ET;
	return pRet;
}

static struct expr_s* makeStr (char *s) {
	if (!s) return NULL;
	struct expr_s *pRet = g_malloc0(sizeof(struct expr_s));
	if (!pRet) return NULL;
	pRet->expr.str = s;
	pRet->type = VAL_STR_ET;
	return pRet;
}

static struct expr_s* makeUnary (enum expr_type_e e, struct expr_s *pE) {
	if (!pE) return NULL;
	struct expr_s *pRet = g_malloc0(sizeof(struct expr_s));
	pRet->expr.unary = pE;
	pRet->type = e;
	return pRet;
}

static struct expr_s* makeAccessor (char *pBase, char *pF) {
	if (!pF || !pBase) return NULL;
	struct expr_s *pRet = g_malloc0(sizeof(struct expr_s));
	pRet->expr.acc.field = pF;
	pRet->expr.acc.base = pBase;
	pRet->type = ACC_ET;
	return pRet;
}

static struct expr_s* makeBinary (enum expr_type_e e, struct expr_s *p1, struct expr_s *p2) {
	if (!p1 || !p2)
		return NULL;
	struct expr_s *pRet = g_malloc0(sizeof(struct expr_s));
	pRet->expr.bin.p1 = p1;
	pRet->expr.bin.p2 = p2;
	pRet->type = e;
	return pRet;
}

typedef void* YY_BUFFER_STATE;

int expr_parse (const char *pBuf, struct expr_s **pE)
{
	int ret;
	YY_BUFFER_STATE ys;

	if (!pBuf || !pE) {
		return -1;
	}

	pParsed = NULL;

	ys = yy_scan_string(pBuf);
	yy_switch_to_buffer(ys);
	ret = yyparse();
	yy_delete_buffer(ys);

	if (ret != 0) {
		return ret;
	}

	if (pParsed==NULL) {
		return -3;
	}

	*pE = pParsed;
	pParsed = NULL;

	return 0;
}


int yyerror(char *m) {
	fprintf(stderr,"%s\n", m);
	return 0;
}

