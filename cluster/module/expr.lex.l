%{
#define YY_NO_UNPUT
#include <metautils/lib/metautils.h>
#include "expr.yacc.h"

#include "./expr.h"

%}
%option noinput
%%
[ \t\r\n]*      {}

"num"    { return UN_STRNUM_TK; }
"root"	 { return BIN_ROOT_TK; }

[-]?[1-9][0-9]* { yylval.n=atof(yytext) ; return VAL_NUM_TK; }
[0]             { yylval.n=0 ; return VAL_NUM_TK; }

[<][Nn][>] { return BIN_NUMCMP_TK; }
[!][=]     { return BIN_NUMEQ_TK; }
[=][=]     { return BIN_NUMNEQ_TK; }
[<][=]     { return BIN_NUMLT_TK; }
[>][=]     { return BIN_NUMGT_TK; }
[<]        { return BIN_NUMLE_TK; }
[>]        { return BIN_NUMGE_TK; }
[-]        { return BIN_NUMSUB_TK; }
[+]        { return BIN_NUMADD_TK; }
[/]        { return BIN_NUMDIV_TK; }
[*]        { return BIN_NUMMUL_TK; }
[(]        { return PAROP_TK ; }
[)]        { return PARCL_TK ; }
[.]        { return DOT_TK ; }
[,]        { return COMA_TK ; }

["][^"]*["]               { yylval.s=g_strdup(yytext+1) ; yylval.s[strlen(yylval.s)-1]='\0' ; return VAL_STR_TK; }

[A-Za-z][-_0-9A-Za-z]* { yylval.s=g_strdup(yytext) ; return ID_TK; }

.                         { }
%%

int yywrap(void) {
	return 1;
}

